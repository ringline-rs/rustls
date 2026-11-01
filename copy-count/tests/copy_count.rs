//! Bytes copied per plaintext byte on the unbuffered send and receive paths,
//! measured by `src/main.rs` with the memcpy/memmove counting shim in
//! `LD_PRELOAD`. The bounds are what ringline-tls does today; a change or an
//! upstream merge that adds a per-record memcpy or memmove of 256 bytes or
//! more, or another copy of the plaintext, fails here. A copy done another
//! way, such as a loop over the bytes, is not counted. Lower a bound when a
//! change removes a copy.
//!
//! Measured on aarch64 Linux at 1, 4 and 16 KiB records:
//!
//! - ring: send 1.00, the copy of the plaintext into the caller's buffer,
//!   sealed there by `MessageEncrypter::encrypt_into`. Receive 0.00:
//!   `next_record` lends the record decrypted in place in the caller's
//!   buffer.
//! - aws-lc-rs on TLS13_AES_256_GCM_SHA384: send 288 bytes per record and
//!   nothing per plaintext byte, because the AES-GCM encrypter seals the
//!   plaintext out of place into the caller's buffer. Receive 288 bytes per
//!   record in a release build. A debug build also copies 1.00 per plaintext
//!   byte on receive: aws-lc-rs's `open_within` ends with a `copy_within`
//!   that moves the plaintext onto itself when it has no prefix, and a
//!   release build optimises that call out. The 288 bytes per record are AWS-LC
//!   copying the AES-GCM key (`GCM128_KEY`) into a stack context on every
//!   seal and open, in place or out of place.
//! - aws-lc-rs in FIPS mode (`aws-lc-rs-fips`), which ringline-tls's `fips`
//!   feature turns on, for example in `cargo test --all-features -p
//!   ringline-tls -p ringline-tls-copy-count`: send 1.00 plus 288 bytes per record,
//!   because in FIPS mode the encrypter copies the plaintext into the
//!   caller's buffer and seals it there. Receive as without FIPS mode.

#![cfg(target_os = "linux")]

use std::process::Command;

/// The most a path may copy: `per_byte` bytes per plaintext byte plus
/// `per_record` bytes per record.
struct Bound {
    per_byte: f64,
    per_record: f64,
}

/// aws-lc-rs's receive bound per plaintext byte. The test and the binary are
/// built by the same cargo invocation, so they share a profile.
/// `cfg!(debug_assertions)` stands for opt-level 0, at which the
/// `copy_within` described above is not optimised out; no profile in this
/// workspace sets one without the other.
fn aws_lc_rs_recv_per_byte() -> f64 {
    if cfg!(debug_assertions) { 1.1 } else { 0.1 }
}

/// The bound for one provider and direction.
fn bound(provider: &str, direction: &str) -> Bound {
    let (per_byte, per_record) = match (provider, direction) {
        ("ring", "send") => (1.1, 0.0),
        ("ring", "recv") => (0.1, 0.0),
        ("aws-lc-rs", "send") => (0.1, 300.0),
        ("aws-lc-rs" | "aws-lc-rs-fips", "recv") => (aws_lc_rs_recv_per_byte(), 300.0),
        ("aws-lc-rs-fips", "send") => (1.1, 300.0),
        _ => panic!("no bound for {provider} {direction}"),
    };
    Bound {
        per_byte,
        per_record,
    }
}

#[test]
fn bytes_copied_per_plaintext_byte() {
    let output = Command::new(env!("CARGO_BIN_EXE_ringline-tls-copy-count"))
        .env("LD_PRELOAD", env!("COPY_COUNT_SHIM"))
        .output()
        .expect("run the copy-count binary");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "copy-count failed: {}\n{stdout}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let mut controls = 0;
    let mut sends = 0;
    let mut recvs = 0;
    for line in stdout.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        match fields.as_slice() {
            ["control", calls, bytes] => {
                // Without the shim the counters would read zero and every
                // bound below would pass.
                assert_eq!(
                    (*calls, *bytes),
                    ("2", "32768"),
                    "the shim counts a known pair of copies"
                );
                controls += 1;
            }
            [direction @ ("send" | "recv"), provider, record, ratio] => {
                let record: f64 = record.parse().unwrap();
                let ratio: f64 = ratio.parse().unwrap();
                let b = bound(provider, direction);
                let max = b.per_byte + b.per_record / record;
                assert!(
                    ratio <= max,
                    "{direction} with {provider} at {record}-byte records copies {ratio} bytes \
                     per plaintext byte, above {max}"
                );
                if *direction == "send" {
                    sends += 1;
                } else {
                    recvs += 1;
                }
            }
            _ => panic!("unexpected output line: {line}"),
        }
    }
    assert_eq!(
        (controls, sends, recvs),
        (1, 6, 6),
        "one control line and one line per provider and record size:
{stdout}"
    );
}
