//! Builds `shim.c` into a shared object for `LD_PRELOAD` and passes its path
//! to the test as `COPY_COUNT_SHIM`. Linux only: other targets get an empty
//! path and the test is compiled out.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=shim.c");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        println!("cargo:rustc-env=COPY_COUNT_SHIM=");
        return;
    }
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("libcopycount.so");
    let compiler = cc::Build::new().get_compiler();
    let status = Command::new(compiler.path())
        .args(["-shared", "-fPIC", "-O2", "-o"])
        .arg(&out)
        .arg("shim.c")
        .arg("-ldl")
        .status()
        .expect("run the C compiler");
    assert!(status.success(), "building shim.c failed");
    println!("cargo:rustc-env=COPY_COUNT_SHIM={}", out.display());
}
