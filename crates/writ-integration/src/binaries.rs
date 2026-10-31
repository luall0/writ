//! The workspace binaries. `make test` builds them first, on their own (`-p writd -p writ-cli
//! -p writ-sign`, in `target/bins`, so no test-only feature of another crate reaches them),
//! and names the directory in `WRIT_BIN_DIR`; without it, they are looked for next to the
//! test binary.

use std::path::PathBuf;

/// The path of a workspace binary (`writd`, `writ`, `writ-sign`).
pub fn bin(name: &str) -> PathBuf {
    let dir = match std::env::var_os("WRIT_BIN_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => {
            // The test binary is target/<profile>/deps/<test>; next to target/<profile>.
            let exe = std::env::current_exe().unwrap();
            exe.parent()
                .and_then(|deps| deps.parent())
                .expect("the test binary lives in target/<profile>/deps")
                .to_owned()
        }
    };
    let path = dir.join(name);
    assert!(
        path.exists(),
        "{} missing: run `make test` (it builds the binaries on their own first)",
        path.display()
    );
    path
}
