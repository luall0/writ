//! `writ admin show <target>` and `writ admin apply <target> <file>`: the policy, `approvers`
//! or `readers` in force, and a signed change of one. `apply` fetches the version in force,
//! shows what changes line by line (every line cleaned of what a terminal would act on), and
//! signs a `writ-admin/1` document naming that version: a change made meanwhile is refused by
//! the daemon, never overwritten.

use std::io::Write as _;
use std::path::Path;

use anyhow::{Context, bail};
use writ_core::authority::{AdminTarget, AdminText};
use writ_core::canonical::Canonical;
use writ_core::signed::Admin;
use writ_proto::{AdminApplied, AdminRequest, AdminShown, Command};

use super::{Signer, connect, read_line};
use crate::display::clean;
use crate::{Exit, Paths};

/// The most cells the line diff computes (lines before × lines after); past it, the new text
/// is shown whole instead.
const MAX_DIFF_CELLS: usize = 4_000_000;

/// `writ admin show <target>`: the text in force on stdout, as is (to edit and apply), its
/// version and digest on stderr.
pub async fn show(paths: &Paths, url: &str, target: AdminTarget) -> anyhow::Result<Exit> {
    connect(paths, url)
        .await?
        .run(async |session| {
            let shown: AdminShown = session.call(&Command::AdminShow { target }, b"").await??;
            eprintln!(
                "{}: version {} (sha256 {})",
                shown.target, shown.version, shown.digest
            );
            print!("{}", shown.text);
            Ok(Exit::Ok)
        })
        .await
}

/// `writ admin apply <target> <file>`.
pub async fn apply(
    paths: &Paths,
    url: &str,
    signer: &Signer,
    target: AdminTarget,
    file: &Path,
    yes: bool,
) -> anyhow::Result<Exit> {
    let text =
        std::fs::read_to_string(file).with_context(|| format!("cannot read {}", file.display()))?;
    let text = AdminText::try_from(text).with_context(|| file.display().to_string())?;
    connect(paths, url)
        .await?
        .run(async |session| {
            let shown: AdminShown = session.call(&Command::AdminShow { target }, b"").await??;
            if shown.text == text.as_str() {
                println!(
                    "{target} version {} already holds this text: nothing to change.",
                    shown.version
                );
                return Ok(Exit::Ok);
            }
            println!(
                "Change of {target}: version {} (sha256 {}) replaced by {}",
                shown.version,
                shown.digest,
                file.display()
            );
            print!("{}", diff(&shown.text, text.as_str()));
            println!(
                "Signing replaces {target} for every lease, at once (sha256 {}).",
                text.digest()
            );
            if !yes {
                print!("Sign this change? [y/N] ");
                std::io::stdout().flush()?;
                if !matches!(read_line()?.as_str(), "y" | "Y" | "yes") {
                    println!("Not signed.");
                    return Ok(Exit::Ok);
                }
            }
            let document =
                Admin::new(target, shown.digest.clone(), text.clone()).canonical_bytes()?;
            let request = AdminRequest {
                signature: signer.sign(&document)?,
                document: String::from_utf8(document)?,
            };
            let applied: AdminApplied = session
                .call(&Command::AdminApply, &writ_proto::encode_body(&request)?)
                .await??;
            println!(
                "Applied: {} is version {} (sha256 {}), signed by {}.",
                applied.target, applied.version, applied.digest, applied.signed_by
            );
            Ok(Exit::Ok)
        })
        .await
}

/// The lines that change from `before` to `after`: `-` removed, `+` added, two lines of
/// context around each change, every line [`clean`]ed. Past [`MAX_DIFF_CELLS`], the new
/// text whole.
pub fn diff(before: &str, after: &str) -> String {
    let (a, b): (Vec<&str>, Vec<&str>) = (before.lines().collect(), after.lines().collect());
    let cells = a
        .len()
        .saturating_add(1)
        .saturating_mul(b.len().saturating_add(1));
    if cells > MAX_DIFF_CELLS {
        let mut out = String::from("  (too long to compare: the new text whole)\n");
        for line in &b {
            out.push_str(&format!("+ {}\n", clean(line)));
        }
        return out;
    }
    // The longest common subsequence, from the end: lcs[i][j] for a[i..] and b[j..].
    let width = b.len().saturating_add(1);
    let mut lcs = vec![0u32; cells];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            let here = i.saturating_mul(width).saturating_add(j);
            let value = if a.get(i) == b.get(j) {
                lcs.get(here.saturating_add(width).saturating_add(1))
                    .copied()
                    .unwrap_or(0)
                    .saturating_add(1)
            } else {
                let down = lcs.get(here.saturating_add(width)).copied().unwrap_or(0);
                let right = lcs.get(here.saturating_add(1)).copied().unwrap_or(0);
                down.max(right)
            };
            if let Some(cell) = lcs.get_mut(here) {
                *cell = value;
            }
        }
    }
    let at = |i: usize, j: usize| {
        lcs.get(i.saturating_mul(width).saturating_add(j))
            .copied()
            .unwrap_or(0)
    };
    let mut ops: Vec<(char, &str)> = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        match (a.get(i), b.get(j)) {
            (Some(x), Some(y)) if x == y => {
                ops.push((' ', x));
                i = i.saturating_add(1);
                j = j.saturating_add(1);
            }
            (Some(x), Some(_)) if at(i.saturating_add(1), j) >= at(i, j.saturating_add(1)) => {
                ops.push(('-', x));
                i = i.saturating_add(1);
            }
            (_, Some(y)) => {
                ops.push(('+', y));
                j = j.saturating_add(1);
            }
            (Some(x), None) => {
                ops.push(('-', x));
                i = i.saturating_add(1);
            }
            (None, None) => break,
        }
    }
    // Two lines of context around each change.
    let near = |k: usize| {
        let from = k.saturating_sub(2);
        let to = k.saturating_add(3).min(ops.len());
        ops.get(from..to)
            .is_some_and(|window| window.iter().any(|(op, _)| *op != ' '))
    };
    let mut out = String::new();
    let mut skipped = false;
    for (k, (op, line)) in ops.iter().enumerate() {
        if *op == ' ' && !near(k) {
            skipped = true;
            continue;
        }
        if skipped {
            out.push_str("  …\n");
            skipped = false;
        }
        out.push_str(&format!("{op} {}\n", clean(line)));
    }
    out
}

/// Refuses a target that isn't one, with the three it may be.
pub fn target(text: &str) -> anyhow::Result<AdminTarget> {
    match text.parse() {
        Ok(target) => Ok(target),
        Err(_) => bail!("{text:?}: the file to change is policy, approvers or readers"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_diff_shows_the_changed_lines_with_context_cleaned() {
        let before = "a\nb\nc\nd\ne\nf\ng\n";
        let after = "a\nb\nc\nD\ne\nf\ng\nh\n";
        assert_eq!(
            diff(before, after),
            "  …\n  b\n  c\n- d\n+ D\n  e\n  f\n  g\n+ h\n"
        );
        // A hostile line: shown escaped, never acted on.
        let shown = diff("", "x\u{1b}[2Jy\n");
        assert_eq!(shown, "+ x\\u{1b}[2Jy\n");
        // Far apart: the unchanged middle is cut.
        let long: String = (0..20).map(|n| format!("{n}\n")).collect();
        let changed = long.replace("0\n", "zero\n").replace("19\n", "nineteen\n");
        let shown = diff(&long, &changed);
        assert!(shown.contains("  …\n"), "{shown}");
        assert!(shown.starts_with("- 0\n+ zero\n  1\n  2\n"), "{shown}");
    }
}
