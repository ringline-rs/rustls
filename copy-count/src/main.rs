//! Measures the bytes ringline-tls copies per plaintext byte on the
//! unbuffered API's send (`WriteTraffic::encrypt`) and receive
//! (`ReadTraffic::next_record`) paths, TLS 1.3 with the ring provider.
//!
//! Run it with the shim from `shim.c` in `LD_PRELOAD`; the
//! `copy_count` test does. Copies of fewer than 256 bytes are not counted.
//! Output, one line each:
//!
//! ```text
//! control <memcpy calls> <memcpy bytes>
//! send <record size> <memcpy+memmove bytes per plaintext byte>
//! recv <record size> <memcpy+memmove bytes per plaintext byte>
//! ```

use std::sync::Arc;

use rustls::client::UnbufferedClientConnection;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::UnbufferedServerConnection;
use rustls::unbuffered::{ConnectionState, EncodeError};

type ResetFn = unsafe extern "C" fn();
type GetFn = unsafe extern "C" fn(*mut u64);

/// The shim's counters, found by symbol in the preloaded object.
struct Meter {
    reset: ResetFn,
    get: GetFn,
}

impl Meter {
    fn load() -> Option<Self> {
        // SAFETY: dlsym with valid NUL-terminated names; the symbols, if
        // present, are the shim's functions with these signatures.
        unsafe {
            let r = libc::dlsym(libc::RTLD_DEFAULT, c"cc_reset".as_ptr());
            let g = libc::dlsym(libc::RTLD_DEFAULT, c"cc_get".as_ptr());
            if r.is_null() || g.is_null() {
                return None;
            }
            Some(Self {
                reset: std::mem::transmute::<*mut libc::c_void, ResetFn>(r),
                get: std::mem::transmute::<*mut libc::c_void, GetFn>(g),
            })
        }
    }

    fn start(&self) {
        // SAFETY: the shim's reset takes no arguments.
        unsafe { (self.reset)() }
    }

    /// `[memcpy calls, memcpy bytes, memmove calls, memmove bytes]`.
    fn stop(&self) -> [u64; 4] {
        let mut o = [0u64; 4];
        // SAFETY: the shim writes four u64s.
        unsafe { (self.get)(o.as_mut_ptr()) }
        o
    }
}

/// Drive one side of the handshake until it waits for input or can send
/// application data. Evaluates to true once it can send application data.
/// A macro because `process_tls_records` is defined separately for the
/// client and server connection types.
macro_rules! step {
    ($conn:expr, $incoming:expr, $outgoing:expr) => {{
        let incoming: &mut Vec<u8> = $incoming;
        let outgoing: &mut Vec<u8> = $outgoing;
        loop {
            let st = $conn.process_tls_records(&mut incoming[..]);
            let mut discard = st.discard;
            let mut stop = false;
            let mut ready = false;
            match st.state.expect("TLS error") {
                ConnectionState::EncodeTlsData(mut e) => {
                    let mut tmp = vec![0u8; 32768];
                    match e.encode(&mut tmp) {
                        Ok(n) => outgoing.extend_from_slice(&tmp[..n]),
                        Err(EncodeError::InsufficientSize(_)) => panic!("encode buffer too small"),
                        Err(e) => panic!("{e:?}"),
                    }
                }
                ConnectionState::TransmitTlsData(t) => t.done(),
                ConnectionState::BlockedHandshake => stop = true,
                ConnectionState::WriteTraffic(_) => {
                    ready = true;
                    stop = true;
                }
                ConnectionState::ReadTraffic(mut rt) => {
                    while let Some(r) = rt.next_record() {
                        discard += r.expect("record").discard;
                    }
                }
                other => panic!("unexpected state {other:?}"),
            }
            incoming.drain(..discard);
            if stop {
                break ready;
            }
        }
    }};
}

fn main() {
    let meter = Meter::load().expect("run with the copy-count shim in LD_PRELOAD");

    // Positive control: one 16384-byte copy into an existing buffer and one
    // `to_vec` are two memcpy calls of 16384 bytes.
    let src = vec![1u8; 16384];
    let mut dst = vec![0u8; 16384];
    meter.start();
    dst.copy_from_slice(std::hint::black_box(&src));
    let v = std::hint::black_box(&src).to_vec();
    let m = meter.stop();
    std::hint::black_box((&dst, &v));
    println!("control {} {}", m[0], m[1]);

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = CertificateDer::from(ck.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    let server_config = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut server = UnbufferedServerConnection::new(Arc::new(server_config)).unwrap();
    let mut client = UnbufferedClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();

    let (mut to_client, mut to_server) = (Vec::new(), Vec::new());
    for _ in 0..20 {
        let a = step!(client, &mut to_client, &mut to_server);
        let b = step!(server, &mut to_server, &mut to_client);
        if a && b && to_client.is_empty() && to_server.is_empty() {
            break;
        }
    }
    assert!(!client.is_handshaking() && !server.is_handshaking());

    for record in [1024usize, 4096, 16384] {
        let records = 64usize;
        let plaintext = vec![0xabu8; record * records];
        let mut wire = Vec::with_capacity(records * (record + 64));
        let mut out = vec![0u8; record + 64];

        // Send: one `encrypt` per record-sized chunk, into a buffer the
        // caller owns, as ringline's pool slot is.
        let st = server.process_tls_records(&mut []);
        let ConnectionState::WriteTraffic(mut wt) = st.state.unwrap() else {
            panic!("server cannot send application data");
        };
        let mut copied = 0u64;
        for chunk in plaintext.chunks(record) {
            meter.start();
            let n = wt.encrypt(chunk, &mut out).unwrap();
            let m = meter.stop();
            copied += m[1] + m[3];
            wire.extend_from_slice(&out[..n]);
        }
        println!(
            "send {record} {:.4}",
            copied as f64 / plaintext.len() as f64
        );

        // Receive: every record is already in the incoming buffer. The
        // `drain` that discards processed records runs outside the meter.
        to_client.clear();
        to_client.extend_from_slice(&wire);
        let mut received = 0usize;
        let mut copied = 0u64;
        loop {
            meter.start();
            let st = client.process_tls_records(&mut to_client[..]);
            let mut discard = st.discard;
            let mut more = false;
            if let ConnectionState::ReadTraffic(mut rt) = st.state.unwrap() {
                while let Some(r) = rt.next_record() {
                    let r = r.unwrap();
                    received += r.payload.len();
                    discard += r.discard;
                    more = true;
                }
            }
            let m = meter.stop();
            copied += m[1] + m[3];
            to_client.drain(..discard);
            if !more {
                break;
            }
        }
        assert_eq!(received, plaintext.len(), "received plaintext");
        println!("recv {record} {:.4}", copied as f64 / received as f64);
    }
}
