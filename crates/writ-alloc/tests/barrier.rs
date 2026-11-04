//! The zeroing survives the optimizer. A store to a block about to be freed is dead to it:
//! without the barrier in `wipe`, an optimized build drops the zeroing and frees the block as
//! it was. The unit tests can't see that (their checker reads each block, so the zeroes are
//! never dead there), so this test compiles a program on the wiping allocator with `rustc
//! -O`, as the binaries ship, and reads the machine code of its `__rust_dealloc`: the block is
//! zeroed before it is freed. The same program with the barrier taken out must lose its
//! zeroing, or this check would prove nothing on this compiler.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::Path;
use std::process::Command;

/// The barrier, as `wipe.rs` writes it.
const BARRIER: &str =
    r#"unsafe { core::arch::asm!("/* {0} */", in(reg) ptr, options(nostack, preserves_flags)) };"#;

/// A program on the wiping allocator (`wipe.rs` as is, or without its barrier): its assembly.
fn assembly(dir: &Path, name: &str, wipe: &str) -> String {
    let module = dir.join(format!("{name}_wipe.rs"));
    std::fs::write(&module, wipe).unwrap();
    let main = dir.join(format!("{name}.rs"));
    std::fs::write(
        &main,
        format!(
            "#[path = {module:?}]\nmod wipe;\n\
             #[global_allocator]\nstatic ALLOCATOR: wipe::Wiping = wipe::Wiping::system();\n\
             fn main() {{\n    \
                 let secret = std::hint::black_box(vec![0x5au8; 4096]);\n    \
                 drop(secret);\n\
             }}\n"
        ),
    )
    .unwrap();
    let out = dir.join(format!("{name}.s"));
    // PATH: the toolchain's own rustc (rustup's proxy, pinned by rust-toolchain.toml, which
    // the workspace directory selects).
    let compiled = Command::new("rustc")
        .args([
            "--edition",
            "2024",
            "-O",
            "--crate-type",
            "bin",
            "--emit",
            "asm",
            "-o",
        ])
        .arg(&out)
        .arg(&main)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    assert_eq!(
        compiled.status.code(),
        Some(0),
        "rustc: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    std::fs::read_to_string(out).unwrap()
}

/// The instructions of the allocator's `__rust_dealloc`, from its label to its end.
fn dealloc_body(assembly: &str) -> String {
    let mut lines = assembly.lines();
    lines
        .by_ref()
        .find(|line| line.ends_with(':') && line.contains("__rust_dealloc"))
        .expect("no __rust_dealloc in the assembly");
    lines
        .take_while(|line| !line.contains(".cfi_endproc"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn zeroes(body: &str) -> bool {
    body.contains("memset") || body.contains("bzero")
}

fn frees(body: &str) -> bool {
    body.contains("free")
}

#[test]
fn the_zeroing_survives_optimization_and_only_thanks_to_the_barrier() {
    let dir = tempfile::tempdir().unwrap();
    let source = include_str!("../src/wipe.rs");
    assert_eq!(
        source.matches(BARRIER).count(),
        1,
        "wipe.rs's barrier moved"
    );

    let kept = dealloc_body(&assembly(dir.path(), "kept", source));
    assert!(frees(&kept), "{kept}");
    assert!(
        zeroes(&kept),
        "the block is freed without being zeroed:\n{kept}"
    );

    let removed = dealloc_body(&assembly(
        dir.path(),
        "removed",
        &source.replace(BARRIER, ""),
    ));
    assert!(frees(&removed), "{removed}");
    assert!(
        !zeroes(&removed),
        "without the barrier the zeroing stayed: this check can't tell them apart here\n{removed}"
    );
}
