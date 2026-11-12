//! Builds `writ-se`, the Secure Enclave helper (swift/writ-se.swift), on macOS: its path is
//! `writ_platform_macos::secure_enclave::BUILT_HELPER`, for the tests (`make install` and
//! `make run` build their own copy beside `writd`, from the Makefile). On another OS, nothing.

// A build script: failing the build loudly is how it says swiftc couldn't build the helper.
#![allow(clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=swift/writ-se.swift");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    let helper = out.join("writ-se");
    // PATH: the toolchain's own swiftc (Xcode's command line tools), as cargo finds cc.
    let status = Command::new("swiftc")
        .args(["-O", "-swift-version", "6", "-o"])
        .arg(&helper)
        .arg("swift/writ-se.swift")
        .status()
        .unwrap_or_else(|e| panic!("cannot run swiftc to build writ-se: {e}"));
    assert!(status.success(), "swiftc failed to build writ-se");
    println!("cargo:rustc-env=WRIT_SE_HELPER={}", helper.display());
}
