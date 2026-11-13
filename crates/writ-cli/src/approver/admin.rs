//! `writ admin show <target>` and `writ admin apply <target> <file>`: the policy, `approvers`
//! or `readers` in force, and a signed change of one. `apply` fetches the version in force,
//! shows what changes line by line (every line cleaned of what a terminal would act on), and
//! signs a `writ-admin/2` document naming that version: a change made meanwhile is refused by
//! the daemon, never overwritten. And `writ admin token <id>`: a token read here, encrypted
//! here to the daemon keystore's recipient, and signed as a `writ-token/2` naming the token
//! file it replaces: the daemon host never sees it in clear on its disk.

use std::io::Write as _;
use std::path::Path;

use anyhow::{Context, bail};
use writ_core::authority::{AdminTarget, AdminText, SealedToken};
use writ_core::canonical::Canonical;
use writ_core::names::KeyId;
use writ_core::signed::{Admin, Replaced, Token};
use writ_crypto::passphrase::PassphraseError;
use writ_proto::{
    AdminApplied, AdminRequest, AdminShown, Command, Info, TlsRequest, TlsRotated, TlsShown,
    TokenApplied, TokenRequest, TokenShown,
};

use super::{Signer, connect, read_line};
use crate::client::Approvals;
use crate::display::clean;
use crate::{Exit, Paths};

/// The most cells the line diff computes (lines before × lines after); past it, the new text
/// is shown whole instead.
const MAX_DIFF_CELLS: usize = 4_000_000;

/// A file in force as the daemon showed it, checked against what the connection
/// authenticated and against itself ([`in_force`]): only that check makes one (its field is
/// private), and a `writ-admin/2` is only signed over one ([`sign_applied`]).
pub(super) struct ShownInForce(AdminShown);

impl std::ops::Deref for ShownInForce {
    type Target = AdminShown;
    fn deref(&self) -> &AdminShown {
        &self.0
    }
}

/// The file `target` in force, from the daemon, refused unless the reply is the one asked for:
/// the daemon it names is the one the connection authenticated, the target is `target`, and
/// the text is the one its digest names (the review after M7.6, L-1: a relay answering with
/// the real daemon's name, version and digest but another text got its own lines signed, the
/// diff showing only the approver's edit).
pub(super) async fn in_force(
    session: &Approvals,
    target: AdminTarget,
) -> anyhow::Result<ShownInForce> {
    let shown: AdminShown = session.call(&Command::AdminShow { target }, b"").await??;
    checked_in_force(&session.authenticated()?, target, shown)
}

/// [`in_force`]'s checks on a reply.
fn checked_in_force(
    authenticated: &crate::client::Authenticated,
    target: AdminTarget,
    shown: AdminShown,
) -> anyhow::Result<ShownInForce> {
    authenticated.check_daemon(&shown.daemon)?;
    if shown.target != target {
        bail!(
            "asked for the {target} in force, the daemon answered with its {}: nothing was signed",
            shown.target
        );
    }
    let digest = writ_core::authority::TextDigest::of(&shown.text);
    if digest != shown.digest {
        bail!(
            "the {target} the daemon sent is not the text its digest names (sha256 {}, the text \
             sent hashes to {digest}): something changed it on the way, so nothing was signed",
            shown.digest
        );
    }
    Ok(ShownInForce(shown))
}

/// `writ admin show <target>`: the text in force on stdout, as is (to edit and apply), its
/// version and digest on stderr.
pub async fn show(paths: &Paths, url: &str, target: AdminTarget) -> anyhow::Result<Exit> {
    connect(paths, url)
        .await?
        .run(async |session| {
            let shown = in_force(session, target).await?;
            eprintln!(
                "{}: version {} (sha256 {})",
                shown.target, shown.version, shown.digest
            );
            print!("{}", shown.text);
            Ok(Exit::Ok)
        })
        .await
}

/// `writ recovery new` (M7.6): a new recovery key, printed once, saved nowhere.
pub fn recovery_new() -> anyhow::Result<Exit> {
    let (secret, recipient) = writ_crypto::recovery::new_key();
    println!("Recovery key (write it down, then clear this screen; it is saved nowhere):");
    println!();
    println!("    {}", secret.as_str());
    println!();
    println!("Its recipient, to declare on the daemon:");
    println!();
    println!("    writ admin recipient add recovery recipient={recipient}");
    println!();
    println!("Then check it with `writ recovery check`.");
    drop(secret);
    Ok(Exit::Ok)
}

/// `writ recovery check` (M7.6): the recovery key read here opens the daemon's challenge.
pub async fn recovery_check(paths: &Paths, url: &str) -> anyhow::Result<Exit> {
    connect(paths, url)
        .await?
        .run(async |session| {
            let shown: writ_proto::RecoveryShown =
                session.call(&Command::RecoveryShow, b"").await??;
            let challenge = writ_crypto::sealed::decode(&shown.challenge)
                .map_err(|e| anyhow::anyhow!("the daemon's challenge: {e}"))?;
            let typed = writ_crypto::passphrase::read("Recovery key: ", None, false)?;
            let checked = writ_crypto::recovery::check(
                typed.as_str(),
                &shown.recipient,
                &challenge,
                &shown.digest,
            );
            drop(typed);
            match checked {
                Ok(()) => {
                    println!(
                        "Recovery key checked: it is recipient {} ({}), and it opens the daemon's \
                         keystore.",
                        clean(&shown.name),
                        clean(&shown.recipient)
                    );
                    Ok(Exit::Ok)
                }
                Err(e) => bail!("not the daemon's recovery key: {}", clean(&e.to_string())),
            }
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
            let shown = in_force(session, target).await?;
            let what = format!("replaced by {}", file.display());
            sign_change(session, signer, &shown, &text, &what, yes).await
        })
        .await
}

/// Shows a change of the file in force (`shown`) to `text` line by line, asks (unless `yes`),
/// signs a `writ-admin/2` naming the version it replaces, sends it, and prints what the
/// daemon did: the version, the keys it made (to register) and deleted, the leases it
/// revoked. `what` says where the new text comes from.
pub(super) async fn sign_change(
    session: &Approvals,
    signer: &Signer,
    shown: &ShownInForce,
    text: &AdminText,
    what: &str,
    yes: bool,
) -> anyhow::Result<Exit> {
    sign_applied(session, signer, shown, text, what, yes)
        .await
        .map(|_| Exit::Ok)
}

/// [`sign_change`], answering what the daemon applied (none: nothing to change, or not
/// signed).
pub(super) async fn sign_applied(
    session: &Approvals,
    signer: &Signer,
    shown: &ShownInForce,
    text: &AdminText,
    what: &str,
    yes: bool,
) -> anyhow::Result<Option<AdminApplied>> {
    let target = shown.target;
    if shown.text == text.as_str() {
        println!(
            "{target} version {} already holds this text: nothing to change.",
            shown.version
        );
        return Ok(None);
    }
    println!(
        "Change of {target}: version {} (sha256 {}) {what}",
        shown.version, shown.digest
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
            return Ok(None);
        }
    }
    let replaced = Replaced {
        version: shown.version,
        digest: shown.digest.clone(),
    };
    let document =
        Admin::new(shown.daemon.clone(), target, replaced, text.clone()).canonical_bytes()?;
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
    for lease in &applied.revoked {
        println!("Revoked lease {lease}: the approver key that signed it was removed.");
    }
    for key in &applied.created {
        println!(
            "New {} {} (register it on the remote): {}",
            key.role.as_str(),
            key.id,
            clean(&key.public_key)
        );
    }
    for key in &applied.removed {
        match (&key.public_key, &key.fingerprint) {
            (Some(public), Some(fingerprint)) => println!(
                "Deleted {} {} ({}; its public half stays in the audit log): {}",
                clean(&key.description),
                key.id,
                clean(fingerprint),
                clean(public)
            ),
            _ => println!("Deleted {} {}.", clean(&key.description), key.id),
        }
    }
    Ok(Some(applied))
}

/// `writ admin token <id>`: the keystore's recipient from `writ info`, the token file in force
/// for `id`, the token (asked for with no echo, or one line of stdin), encrypted here, then one
/// signature over the `writ-token/2` document.
pub async fn token(
    paths: &Paths,
    url: &str,
    signer: &Signer,
    id: &KeyId,
    yes: bool,
) -> anyhow::Result<Exit> {
    connect(paths, url)
        .await?
        .run(async |session| {
            let info: Info = session.call(&Command::Info, b"").await??;
            let Some(recipient) = info.recipient else {
                bail!(
                    "the daemon serves no keystore recipient: its development keystore takes \
                     tokens as files"
                );
            };
            let shown: TokenShown = session
                .call(&Command::TokenShow { id: id.clone() }, b"")
                .await??;
            // Before the token is asked for: it is encrypted to what this daemon serves.
            session.authenticated()?.check_daemon(&shown.daemon)?;
            if shown.id != *id {
                bail!(
                    "asked for token {id}, the daemon answered for {}: nothing was signed",
                    shown.id
                );
            }
            let sealed = {
                let typed = writ_crypto::passphrase::read(&format!("Token {id}: "), None, false)
                    .map_err(token_error)?;
                if typed.trim().is_empty() {
                    bail!("no token: the line was empty");
                }
                // A hardware keystore's tokens go to its devices and the recovery key (M7.6).
                match info.token_recipients.is_empty() {
                    true => writ_crypto::sealed::seal(&recipient, typed.trim().as_bytes())?,
                    false => writ_crypto::sealed::seal_to(
                        &info.token_recipients,
                        typed.trim().as_bytes(),
                    )?,
                }
            };
            let sealed = SealedToken::try_from(sealed)?;
            let to = match info.token_recipients.is_empty() {
                true => format!("the daemon's recipient {}", clean(recipient.trim())),
                false => format!(
                    "the daemon's recipients {}",
                    info.token_recipients
                        .iter()
                        .map(|r| clean(r.trim()))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            };
            println!(
                "Token {id}: encrypted to {to}; it replaces {}.",
                match &shown.previous {
                    writ_core::authority::PreviousToken::None => "no token".to_owned(),
                    other => format!("the token file sha256 {other}"),
                }
            );
            if !yes {
                print!("Sign this token change? [y/N] ");
                std::io::stdout().flush()?;
                if !matches!(read_line()?.as_str(), "y" | "Y" | "yes") {
                    println!("Not signed.");
                    return Ok(Exit::Ok);
                }
            }
            let document =
                Token::new(shown.daemon, id.clone(), shown.previous, sealed).canonical_bytes()?;
            let request = TokenRequest {
                signature: signer.sign(&document)?,
                document: String::from_utf8(document)?,
            };
            let applied: TokenApplied = session
                .call(&Command::TokenApply, &writ_proto::encode_body(&request)?)
                .await??;
            println!(
                "Token {} in force (file sha256 {}), signed by {}.",
                applied.id, applied.digest, applied.signed_by
            );
            Ok(Exit::Ok)
        })
        .await
}

/// `writ admin ca show` (M7.6): the SSH CA in force, the CAs it replaced still trusted.
pub async fn ca_show(paths: &Paths, url: &str) -> anyhow::Result<Exit> {
    connect(paths, url)
        .await?
        .run(async |session| {
            let shown = ca_in_force(session).await?;
            println!("SSH CA of daemon {}: {}", shown.daemon, shown.fingerprint);
            println!("public key: {}", clean(&shown.public_key));
            println!("backend: {}", clean(&shown.backend));
            if shown.retired.is_empty() {
                println!("no other CA is trusted");
            }
            for retired in &shown.retired {
                println!(
                    "a CA it replaced, {}, is trusted until {} (its last lease's end)",
                    retired.fingerprint,
                    writ_core::units::Timestamp::from_unix(
                        i64::try_from(retired.until).unwrap_or(i64::MAX)
                    )
                    .map(|t| t.to_string())
                    .unwrap_or_else(|_| retired.until.to_string())
                );
            }
            Ok(Exit::Ok)
        })
        .await
}

/// `writ admin ca rotate [--backend] [--yes]` (M7.6): the CA in force shown, then one
/// signature over a `writ-ca/1` naming it.
pub async fn ca_rotate(
    paths: &Paths,
    url: &str,
    signer: &Signer,
    backend: Option<&str>,
    yes: bool,
) -> anyhow::Result<Exit> {
    connect(paths, url)
        .await?
        .run(async |session| {
            let shown = ca_in_force(session).await?;
            let backend = backend.unwrap_or(&shown.backend).to_owned();
            if !shown.backends.iter().any(|b| b.name == backend) {
                let names: Vec<String> = shown.backends.iter().map(|b| clean(&b.name)).collect();
                bail!(
                    "the daemon has no backend {} (it has: {})",
                    clean(&backend),
                    names.join(", ")
                );
            }
            println!(
                "The SSH CA of daemon {}: {}, its key on {}.",
                shown.daemon,
                shown.fingerprint,
                clean(&shown.backend)
            );
            println!(
                "A new key on {} replaces it at once: new leases are certified by it; leases the \
                 old CA certified keep working until they end.",
                clean(&backend)
            );
            if !yes {
                print!("Sign this CA rotation? [y/N] ");
                std::io::stdout().flush()?;
                if !matches!(read_line()?.as_str(), "y" | "Y" | "yes") {
                    println!("Not signed.");
                    return Ok(Exit::NotSigned);
                }
            }
            let backend: writ_core::config::BackendName = backend
                .clone()
                .try_into()
                .map_err(|e| anyhow::anyhow!("--backend: {e}"))?;
            let document = writ_core::signed::CaRotation::new(
                shown.daemon.clone(),
                shown.fingerprint.clone(),
                backend,
            )
            .canonical_bytes()?;
            let request = writ_proto::CaRequest {
                signature: signer.sign(&document)?,
                document: String::from_utf8(document)?,
            };
            let rotated: writ_proto::CaRotated = session
                .call(&Command::CaRotate, &writ_proto::encode_body(&request)?)
                .await??;
            println!(
                "SSH CA rotated: {} (key on {}), replacing {}.",
                rotated.fingerprint,
                clean(&rotated.backend),
                rotated.previous
            );
            Ok(Exit::Ok)
        })
        .await
}

/// The SSH CA in force, from the daemon, refused unless the daemon it names is the one the
/// connection authenticated and its fingerprint is its public key's.
async fn ca_in_force(session: &Approvals) -> anyhow::Result<writ_proto::CaShown> {
    let shown: writ_proto::CaShown = session.call(&Command::CaShow, b"").await??;
    session.authenticated()?.check_daemon(&shown.daemon)?;
    let key = writ_crypto::ssh_key::PublicKey::from_openssh(shown.public_key.trim())
        .map_err(|_| anyhow::anyhow!("the daemon sent a CA key that doesn't read"))?;
    let fingerprint = writ_crypto::keys::fingerprint(&key);
    if fingerprint != shown.fingerprint.as_str() {
        bail!(
            "the daemon names CA {} but sent the key of {fingerprint}: nothing was signed",
            shown.fingerprint
        );
    }
    Ok(shown)
}

/// `writ admin tls rotate [--backend <name>]` (M7.5): the certificate in force and its key's
/// backend (`writ admin tls show`'s reply), one signature over the `writ-tls/1` naming it and
/// the backend the new key is made on (the current one by default), the new certificate's
/// fingerprint. Reached over HTTPS, the pin is replaced in `tls_pins` (the old certificate
/// vouched for the reply) and checked with a new connection; over SSH, the line to pin is
/// printed.
pub async fn tls_rotate(
    paths: &Paths,
    url: &str,
    signer: &Signer,
    backend: Option<&str>,
    yes: bool,
) -> anyhow::Result<Exit> {
    let endpoint = crate::client::Endpoint::parse(url)?;
    let rotated = connect(paths, url)
        .await?
        .run(async |session| {
            let shown: TlsShown = session.call(&Command::TlsShow, b"").await??;
            let authenticated = session.authenticated()?;
            authenticated.check_daemon(&shown.daemon)?;
            // Over HTTPS the certificate in force is the one this connection checked.
            authenticated.check_certificate(shown.fingerprint.as_str())?;
            let backend = backend.unwrap_or(&shown.backend).to_owned();
            let Some(offered) = shown.backends.iter().find(|b| b.name == backend) else {
                let names: Vec<String> = shown.backends.iter().map(|b| clean(&b.name)).collect();
                bail!(
                    "the daemon has no backend {} (it has: {})",
                    clean(&backend),
                    names.join(", ")
                );
            };
            if !offered.algorithms.iter().any(|a| a == "p256") {
                bail!(
                    "{} makes no p256 key: the TLS key is P-256",
                    clean(&backend)
                );
            }
            println!(
                "The HTTPS approval API of daemon {}: certificate {}, its key on {}.",
                shown.daemon,
                shown.fingerprint,
                clean(&shown.backend)
            );
            println!(
                "A new key on {} and its certificate replace them at once: every approver \
                 re-pins it (writ does it here when it reaches the daemon over HTTPS).",
                clean(&backend)
            );
            if !yes {
                print!("Sign this TLS key rotation? [y/N] ");
                std::io::stdout().flush()?;
                if !matches!(read_line()?.as_str(), "y" | "Y" | "yes") {
                    println!("Not signed.");
                    return Ok(None);
                }
            }
            let backend: writ_core::config::BackendName = backend
                .clone()
                .try_into()
                .map_err(|e| anyhow::anyhow!("--backend: {e}"))?;
            let document = writ_core::signed::TlsRotation::new(
                shown.daemon.clone(),
                shown.fingerprint.clone(),
                backend,
            )
            .canonical_bytes()?;
            let request = TlsRequest {
                signature: signer.sign(&document)?,
                document: String::from_utf8(document)?,
            };
            let rotated: TlsRotated = session
                .call(&Command::TlsRotate, &writ_proto::encode_body(&request)?)
                .await??;
            println!(
                "TLS key rotated: certificate {} (key on {}), replacing {}.",
                rotated.fingerprint,
                clean(&rotated.backend),
                rotated.previous
            );
            Ok(Some(rotated))
        })
        .await?;
    let Some(rotated) = rotated else {
        return Ok(Exit::Ok);
    };
    let name = endpoint.known_hosts_name();
    match &endpoint {
        crate::client::Endpoint::Https { .. } => {
            crate::https::repin(
                &paths.tls_pins,
                &name,
                rotated.previous.as_str(),
                rotated.fingerprint.as_str(),
            )?;
            println!(
                "Pinned in {}: {name} {}.",
                paths.tls_pins.display(),
                rotated.fingerprint
            );
            // The new pin, on a new connection: the daemon answers with its new certificate.
            connect(paths, url)
                .await?
                .run(async |session| {
                    let _: Info = session.call(&Command::Info, b"").await??;
                    Ok(())
                })
                .await?;
            println!("Checked: the daemon answers with the new certificate.");
        }
        _ => println!(
            "Pin it wherever you reach the daemon over HTTPS: `<host>:<port> {}` in \
             ~/.writ/tls_pins (writd tls-fingerprint prints it on the daemon's host).",
            rotated.fingerprint
        ),
    }
    println!(
        "Other approvers' machines are refused until they re-pin it (the old certificate is no \
         longer served)."
    );
    Ok(Exit::Ok)
}

/// A token that couldn't be read, said as a token (the reader is the passphrase's).
fn token_error(error: PassphraseError) -> anyhow::Error {
    match error {
        PassphraseError::TooLong => anyhow::anyhow!("the token is longer than 1024 bytes"),
        PassphraseError::NoInput => anyhow::anyhow!("no token: the input ended first"),
        PassphraseError::NotUtf8 => anyhow::anyhow!("the token is not UTF-8"),
        other => anyhow::anyhow!("cannot read the token: {other}"),
    }
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

    /// The review after M7.6 (L-1): a file in force is taken only from the daemon the
    /// connection authenticated, for the target asked, and as the text its digest names.
    #[test]
    fn a_file_in_force_is_checked_against_the_connection_the_target_and_its_digest() {
        let fingerprint = || -> writ_core::names::KeyFingerprint {
            let key = writ_crypto::keys::generate(writ_crypto::keys::KeyKind::Ed25519).unwrap();
            writ_crypto::keys::fingerprint(key.public_key())
                .parse()
                .unwrap()
        };
        let (daemon, other) = (fingerprint(), fingerprint());
        let authenticated = crate::client::Authenticated::HostKey(daemon.clone());
        let text = "approver ssh-ed25519 AAAA\n".to_owned();
        let shown = |daemon: &writ_core::names::KeyFingerprint, target, text: &str| AdminShown {
            daemon: daemon.clone(),
            target,
            version: 3,
            digest: writ_core::authority::TextDigest::of("approver ssh-ed25519 AAAA\n"),
            text: text.to_owned(),
        };
        let ok = checked_in_force(
            &authenticated,
            AdminTarget::Approvers,
            shown(&daemon, AdminTarget::Approvers, &text),
        )
        .unwrap();
        assert_eq!(ok.text, text);
        let refused = |reply| {
            crate::error_of(checked_in_force(
                &authenticated,
                AdminTarget::Approvers,
                reply,
            ))
        };
        assert!(
            refused(shown(&other, AdminTarget::Approvers, &text))
                .starts_with(&format!("the reply names daemon {other}, but the daemon"))
        );
        assert_eq!(
            refused(shown(&daemon, AdminTarget::Readers, &text)),
            "asked for the approvers in force, the daemon answered with its readers: nothing was \
             signed"
        );
        let altered = format!("{text}eve ssh-ed25519 BBBB\n");
        assert_eq!(
            refused(shown(&daemon, AdminTarget::Approvers, &altered)),
            format!(
                "the approvers the daemon sent is not the text its digest names (sha256 {}, the \
                 text sent hashes to {}): something changed it on the way, so nothing was signed",
                writ_core::authority::TextDigest::of(&text),
                writ_core::authority::TextDigest::of(&altered)
            )
        );
    }

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
