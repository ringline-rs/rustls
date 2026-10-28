//! Bytes copied per plaintext byte on the unbuffered send and receive paths,
//! measured by `src/main.rs` with the memcpy/memmove counting shim in
//! `LD_PRELOAD`. The bounds are what ringline-tls does today; a change or an
//! upstream merge that adds a memcpy or memmove of 256 bytes or more fails
//! here. A copy done another way, such as a loop over the bytes, is not
//! counted. Lower a bound when a change removes a copy.
//!
//! rustls 0.23.46, measured on aarch64 Linux: send 2.02 at 1 KiB records and
//! 2.00 at 16 KiB (the `PrefixedPayload` copy and the copy of the sealed
//! record into the caller's buffer); receive 1.00 (`into_vec` after the
//! in-place decrypt).

#![cfg(target_os = "linux")]

use std::process::Command;

/// Most bytes copied per plaintext byte on send.
const SEND_MAX: f64 = 2.1;
/// Most bytes copied per plaintext byte on receive.
const RECV_MAX: f64 = 1.1;

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
            ["send", record, ratio] => {
                let ratio: f64 = ratio.parse().unwrap();
                assert!(
                    ratio <= SEND_MAX,
                    "send at {record}-byte records copies {ratio} bytes per plaintext byte, \
                     above {SEND_MAX}"
                );
                sends += 1;
            }
            ["recv", record, ratio] => {
                let ratio: f64 = ratio.parse().unwrap();
                assert!(
                    ratio <= RECV_MAX,
                    "receive at {record}-byte records copies {ratio} bytes per plaintext byte, \
                     above {RECV_MAX}"
                );
                recvs += 1;
            }
            _ => panic!("unexpected output line: {line}"),
        }
    }
    assert_eq!(
        (controls, sends, recvs),
        (1, 3, 3),
        "one control line and one line per record size:
{stdout}"
    );
}
