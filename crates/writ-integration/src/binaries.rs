//! The workspace binaries. `make test` builds them first, on their own (`-p writd -p writ-cli
//! -p writ-sign`, in `target/bins`, so no test-only feature of another crate reaches them),
//! and names the directory in `WRIT_BIN_DIR`. Without it, a test refuses to run: the binaries
//! next to the test binary are built with the workspace's test features unified in, or are a
//! stale build, and a test passing against them proves nothing about what ships (the review
//! after M5.5).

use std::path::PathBuf;

/// The path of a workspace binary (`writd`, `writ`, `writ-sign`).
pub fn bin(name: &str) -> PathBuf {
    let dir = std::env::var_os("WRIT_BIN_DIR")
        .map(PathBuf::from)
        .expect("WRIT_BIN_DIR is not set: run the tests with `make test`, which builds the binaries as they ship and names them");
    let path = dir.join(name);
    assert!(
        path.exists(),
        "{} missing: run `make test` (it builds the binaries on their own first)",
        path.display()
    );
    path
}
