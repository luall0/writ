//! `writd check-upgrade <writd.yaml>` (M7.9.6): this binary's dry run on an installed daemon,
//! before an upgrade changes anything. Run by the installer as the daemon's user, while the
//! old daemon runs: `writd.yaml` read as a start reads it; the state copied (SQLite's own copy,
//! read only) into a private temporary directory and migrated there, never in place; the policy
//! in force read from the copy as a start would read it. It says what the start will migrate,
//! what will wait for a signature (`writ migrate`), and what blocks the upgrade: anything that
//! would stop this binary's daemon from starting. Nothing it reads is acted on: the state is
//! sealed (no MAC checked), this is a report.

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use writ_core::config::{POLICY_FORMAT, migrate};
use writ_store::{STATE_VERSION, Store};

use crate::config::Config;

/// A private temporary directory, removed when dropped (best effort: its files are a copy).
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> anyhow::Result<Self> {
        let suffix: [u8; 8] = writ_crypto::keys::random_array()?;
        let name: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("writd-check-upgrade-{name}"));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .with_context(|| format!("cannot make {}", path.display()))?;
        Ok(Self(path))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The report, line by line, and what blocks.
#[derive(Default)]
struct Report {
    lines: Vec<String>,
    blocks: Vec<String>,
}

impl Report {
    fn say(&mut self, line: impl Into<String>) {
        self.lines.push(line.into());
    }
    fn block(&mut self, why: impl Into<String>) {
        self.blocks.push(why.into());
    }
}

/// The check: the report on stdout; an error (exit 1) naming each block when something would
/// stop this binary's daemon from starting.
pub fn check_upgrade(path: &Path) -> anyhow::Result<()> {
    let report = examine(path);
    for line in &report.lines {
        println!("{line}");
    }
    if report.blocks.is_empty() {
        println!("Nothing blocks the upgrade.");
        return Ok(());
    }
    for why in &report.blocks {
        println!("Blocks the upgrade: {why}");
    }
    bail!(
        "the upgrade is blocked ({} {}): nothing was changed",
        report.blocks.len(),
        if report.blocks.len() == 1 {
            "reason"
        } else {
            "reasons"
        }
    )
}

fn examine(path: &Path) -> Report {
    let mut report = Report::default();
    let config = match Config::load(path) {
        Ok(config) => {
            report.say(format!("{}: read as this writd reads it.", path.display()));
            config
        }
        Err(e) => {
            report.block(format!("{}: {e:#}", path.display()));
            return report;
        }
    };
    let db = config.state_dir.join("leases.db");
    if !db.exists() {
        report.say("The state: none yet (no writd ran here): nothing to migrate.");
        return report;
    }
    if let Err(e) = state(&config, &db, &mut report) {
        report.block(format!("{e:#}"));
    }
    report
}

/// The state's version, its steps run on a copy, then the policy in force read from it.
fn state(config: &Config, db: &Path, report: &mut Report) -> anyhow::Result<()> {
    let version = Store::version_at(db).context("the state")?;
    let scratch = Scratch::new()?;
    let copy = scratch.0.join("leases.db");
    Store::copy_state(db, &copy).context("the state can't be copied")?;
    let (store, migrated) = match Store::open_migrating(&copy, &scratch.0.join("backups"), now()?) {
        Ok(opened) => opened,
        Err(e) => {
            report.block(format!("the state (version {version}): {e}"));
            return Ok(());
        }
    };
    match migrated {
        Some(m) => report.say(format!(
            "The state: version {}; this writd migrates it to version {} at its start, after a \
             copy of it in {} (the steps ran on a copy here).",
            m.from,
            m.to,
            config.state_dir.join("backups").display()
        )),
        None => report.say(format!(
            "The state: version {STATE_VERSION}, this writd's: nothing to migrate."
        )),
    }
    let Some((_, files)) = store.authority_in_force()? else {
        report.say("The policy: none in force yet (writd init records it).");
        return Ok(());
    };
    let text = files
        .get(&writ_core::authority::AdminTarget::Policy)
        .map(|v| v.text.as_str())
        .unwrap_or_default();
    policy(text, config, report);
    Ok(())
}

/// The policy in force, as a start reads it, and the migration it will owe.
fn policy(text: &str, config: &Config, report: &mut Report) {
    let format = match migrate::format_of(text) {
        Ok(format) => format,
        Err(e) => {
            report.block(format!("the policy in force can't be read: {e}"));
            return;
        }
    };
    // What the start does with it: refused, read, or held while its migration is owed.
    if let Err(e) = crate::authority::read_policy(text, config.min_ttl) {
        report.block(format!(
            "the policy in force (format {format}) doesn't start this writd: {e:#}"
        ));
        return;
    }
    if format == POLICY_FORMAT {
        report.say(format!(
            "The policy in force: format {POLICY_FORMAT}, this writd's: nothing to migrate."
        ));
        return;
    }
    report.say(format!(
        "The policy in force: format {format}; this writd reads format {POLICY_FORMAT}. After \
         the start, every request is refused until an approver signs its migration: writ \
         migrate."
    ));
    match migrate::propose(text, config.min_ttl) {
        Ok(_) => {
            report.say("  The daemon's rewrite is ready: writ migrate shows it, then signs it.")
        }
        Err(migrate::MigrateError::Reasons(reasons)) => {
            report.say(
                "  The daemon can't rewrite it: write the policy you want, then writ migrate \
                 --file <policy>. Why:",
            );
            for reason in reasons {
                report.say(format!("    {reason}"));
            }
        }
        Err(other) => report.say(format!("  The daemon can't rewrite it: {other}")),
    }
}

fn now() -> anyhow::Result<writ_core::units::Timestamp> {
    crate::now()
}
