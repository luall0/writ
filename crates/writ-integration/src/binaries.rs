//! The workspace binaries, next to the test binary in the target directory. `make test`
//! builds them first (`cargo build --workspace --bins`).

use std::path::PathBuf;

/// The path of a workspace binary (`writd`, `writ`, `writ-sign`).
pub fn bin(name: &str) -> PathBuf {
    // The test binary is target/<profile>/deps/<test>; the binaries are in target/<profile>.
    let exe = std::env::current_exe().unwrap();
    let profile = exe
        .parent()
        .and_then(|deps| deps.parent())
        .expect("the test binary lives in target/<profile>/deps");
    let path = profile.join(name);
    assert!(
        path.exists(),
        "{} missing: run `cargo build --workspace --bins` first (make test does)",
        path.display()
    );
    path
}
