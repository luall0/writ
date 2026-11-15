//! `writ admin show <target>` and `writ admin apply <target> <file>`: the policy, `approvers`
//! or `readers` in force, and a signed change of one. `apply` fetches the version in force,
//! shows what changes line by line (every line cleaned of what a terminal would act on), and
//! signs a `writ-admin/2` document naming that version: a change made meanwhile is refused by
//! the daemon, never overwritten. And `writ admin token <id>`: a token read here, encrypted
//! here to the daemon keystore's recipient, and signed as a `writ-token/3` naming the id's
//! change count and the token file it replaces: the daemon host never sees it in clear on its
//! disk.

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

use super::{Signer, confirm, connect};
use crate::client::Approvals;
use crate::display::clean;
use crate::{Exit, Paths};

/// The most cells the line diff computes (lines before × lines after, once the lines both texts
/// share at their start and end are set aside); past it, the change is refused, to be split.
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

/// `writ migrate` (M7.9.6): the migration the policy in force owes, shown and signed. The
/// daemon's rewrite of the text in force (or `file`, the operator's own policy, needed when
/// the daemon has none) is shown as the change of the policy it is, line by line, then signed
/// as its `writ-admin/2` naming the version in force: one approval. Nothing owed: said, and
/// nothing signed. Declined: nothing changes, and it can be run again.
pub async fn migrate(
    paths: &Paths,
    url: &str,
    signer: &Signer,
    file: Option<&Path>,
    yes: bool,
) -> anyhow::Result<Exit> {
    let own = file
        .map(|file| {
            let text = std::fs::read_to_string(file)
                .with_context(|| format!("cannot read {}", file.display()))?;
            AdminText::try_from(text).with_context(|| file.display().to_string())
        })
        .transpose()?;
    connect(paths, url)
        .await?
        .run(async |session| {
            let shown: writ_proto::MigrationShown =
                session.call(&Command::MigrationShow, b"").await??;
            let Some(owed) = shown.owed else {
                println!(
                    "Nothing to migrate: the policy in force is of the format this daemon reads."
                );
                return Ok(Exit::Ok);
            };
            // The text in force checked as `writ admin apply` checks it: the daemon the
            // connection authenticated, the policy, the text its digest names.
            let in_force = checked_in_force(
                &session.authenticated()?,
                AdminTarget::Policy,
                shown.in_force,
            )?;
            println!(
                "The policy in force is format {}; this daemon reads format {} and refuses every \
                 request until a policy of format {} is signed.",
                owed.from, owed.to, owed.to
            );
            let (text, what) = match (own, shown.proposal) {
                (Some(text), _) => {
                    let what = match file {
                        Some(file) => format!("replaced by {}", file.display()),
                        None => "replaced".to_owned(),
                    };
                    (text, what)
                }
                (None, Some(proposal)) => (
                    AdminText::try_from(proposal).context("the daemon's rewrite")?,
                    format!("rewritten to format {} by the daemon", owed.to),
                ),
                (None, None) => {
                    println!("The daemon can't rewrite it:");
                    for reason in &shown.reasons {
                        println!("  {}", clean(reason));
                    }
                    println!(
                        "Write the policy you want in format {} (writ admin show policy, once \
                         migrated, prints the layout), then: writ migrate --file <policy>",
                        owed.to
                    );
                    return Ok(Exit::Error);
                }
            };
            sign_change(session, signer, &in_force, &text, &what, yes).await
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
        .map(|signing| signing.exit())
}

/// What became of a change [`sign_applied`] was asked to sign.
pub(super) enum Signing {
    /// Signed, and the daemon applied it (what it did, printed).
    Applied,
    /// The file in force holds the text already: nothing to sign.
    Unchanged,
    /// The approver answered no.
    NotSigned,
}

impl Signing {
    /// How the command ends: an answered no is [`Exit::NotSigned`], on every command.
    pub(super) fn exit(&self) -> Exit {
        match self {
            Self::Applied | Self::Unchanged => Exit::Ok,
            Self::NotSigned => Exit::NotSigned,
        }
    }
}

/// [`sign_change`], answering what became of the change.
pub(super) async fn sign_applied(
    session: &Approvals,
    signer: &Signer,
    shown: &ShownInForce,
    text: &AdminText,
    what: &str,
    yes: bool,
) -> anyhow::Result<Signing> {
    let target = shown.target;
    if shown.text == text.as_str() {
        println!(
            "{target} version {} already holds this text: nothing to change.",
            shown.version
        );
        return Ok(Signing::Unchanged);
    }
    // Before anything is printed: a change too large to show is refused whole.
    let lines = diff(&shown.text, text.as_str())?;
    println!(
        "Change of {target}: version {} (sha256 {}) {what}",
        shown.version, shown.digest
    );
    print!("{lines}");
    println!(
        "Signing replaces {target} for every lease, at once (sha256 {}).",
        text.digest()
    );
    if !yes && !confirm("Sign this change?")? {
        println!("Not signed.");
        return Ok(Signing::NotSigned);
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
    // What the change did to the keystore's data key (the review after M7.6, S-8).
    for line in &applied.keystore {
        println!("Keystore: {}.", clean(line));
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
    Ok(Signing::Applied)
}

/// `writ admin token <id>`: the keystore's recipient from `writ info`, the token file in force
/// for `id`, the token (asked for with no echo, or one line of stdin), encrypted here, then one
/// signature over the `writ-token/3` document.
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
            if !yes && !confirm("Sign this token change?")? {
                println!("Not signed.");
                return Ok(Exit::NotSigned);
            }
            let replaced = writ_core::signed::TokenReplaced {
                version: shown.version,
                previous: shown.previous,
            };
            let document =
                Token::new(shown.daemon, id.clone(), replaced, sealed).canonical_bytes()?;
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
            if !yes && !confirm("Sign this CA rotation?")? {
                println!("Not signed.");
                return Ok(Exit::NotSigned);
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
            // None: not signed.
            if !yes && !confirm("Sign this TLS key rotation?")? {
                println!("Not signed.");
                return Ok(None);
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
        return Ok(Exit::NotSigned);
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

/// A line of the diff: `' '` kept, `'-'` removed, `'+'` added, and where it is (its text,
/// before or after, and its index there).
struct Op<'a> {
    op: char,
    line: &'a str,
    after: bool,
    at: usize,
}

/// The lines that change from `before` to `after`: `-` removed, `+` added, two lines of
/// context around each change, each run of changes under the lines that enclose it (`@@
/// templates: / feature:`: the section and the entry, by indentation), every line [`clean`]ed
/// and cut into rows that fit the display's width (a continuation behind its mark and the
/// gutter). The lines both texts share at their start and end are set aside first; what is
/// left past [`MAX_DIFF_CELLS`] is refused, never shown as the whole new text (the review after
/// M7.6, U-6: a removed line was then invisible): the change is to be split.
pub fn diff(before: &str, after: &str) -> anyhow::Result<String> {
    let (a, b): (Vec<&str>, Vec<&str>) = (before.lines().collect(), after.lines().collect());
    let head = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let (rest_a, rest_b) = (
        a.get(head..).unwrap_or_default(),
        b.get(head..).unwrap_or_default(),
    );
    let tail = rest_a
        .iter()
        .rev()
        .zip(rest_b.iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (mid_a, mid_b) = (
        rest_a
            .get(..rest_a.len().saturating_sub(tail))
            .unwrap_or_default(),
        rest_b
            .get(..rest_b.len().saturating_sub(tail))
            .unwrap_or_default(),
    );
    let cells = mid_a
        .len()
        .saturating_add(1)
        .saturating_mul(mid_b.len().saturating_add(1));
    if cells > MAX_DIFF_CELLS {
        bail!(
            "the change is too large to show line by line ({} lines replaced by {}): nothing was \
             signed; split it into smaller changes, each signed on its own",
            mid_a.len(),
            mid_b.len()
        );
    }
    // The longest common subsequence of the middles, from the end: lcs[i][j] for mid_a[i..]
    // and mid_b[j..].
    let width = mid_b.len().saturating_add(1);
    let mut lcs = vec![0u32; cells];
    for i in (0..mid_a.len()).rev() {
        for j in (0..mid_b.len()).rev() {
            let here = i.saturating_mul(width).saturating_add(j);
            let value = if mid_a.get(i) == mid_b.get(j) {
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
    let kept = |i: usize| Op {
        op: ' ',
        line: b.get(i).copied().unwrap_or_default(),
        after: true,
        at: i,
    };
    let mut ops: Vec<Op> = (0..head).map(kept).collect();
    let (mut i, mut j) = (0, 0);
    let removed = |i: usize| Op {
        op: '-',
        line: mid_a.get(i).copied().unwrap_or_default(),
        after: false,
        at: head.saturating_add(i),
    };
    let added = |j: usize, op: char| Op {
        op,
        line: mid_b.get(j).copied().unwrap_or_default(),
        after: true,
        at: head.saturating_add(j),
    };
    while i < mid_a.len() || j < mid_b.len() {
        match (mid_a.get(i), mid_b.get(j)) {
            (Some(x), Some(y)) if x == y => {
                ops.push(added(j, ' '));
                i = i.saturating_add(1);
                j = j.saturating_add(1);
            }
            (Some(_), Some(_)) if at(i.saturating_add(1), j) >= at(i, j.saturating_add(1)) => {
                ops.push(removed(i));
                i = i.saturating_add(1);
            }
            (_, Some(_)) => {
                ops.push(added(j, '+'));
                j = j.saturating_add(1);
            }
            (Some(_), None) => {
                ops.push(removed(i));
                i = i.saturating_add(1);
            }
            (None, None) => break,
        }
    }
    let from = head.saturating_add(mid_b.len());
    ops.extend((from..from.saturating_add(tail)).map(kept));
    // Two lines of context around each change.
    let near = |k: usize| {
        let from = k.saturating_sub(2);
        let to = k.saturating_add(3).min(ops.len());
        ops.get(from..to)
            .is_some_and(|window| window.iter().any(|o| o.op != ' '))
    };
    // A row: the mark, the gutter on a continuation, within the display's width.
    let room = crate::display::WIDTH.saturating_sub(4);
    let mut out = String::new();
    let mut skipped = false;
    let mut in_hunk = false;
    for (k, op) in ops.iter().enumerate() {
        if op.op == ' ' && !near(k) {
            skipped = true;
            in_hunk = false;
            continue;
        }
        if skipped {
            out.push_str("  …\n");
            skipped = false;
        }
        if !in_hunk {
            in_hunk = true;
            // The lines enclosing the hunk's first change, in the text it is in.
            if let Some(first) = ops.iter().skip(k).find(|o| o.op != ' ') {
                let text = if first.after { &b } else { &a };
                let enclosing = enclosing(text, first.at);
                if !enclosing.is_empty() {
                    let header: Vec<String> = enclosing.iter().map(|l| clean(l)).collect();
                    out.push_str(&crate::display::one_row(
                        &format!("@@ {}", header.join(" / ")),
                        crate::display::WIDTH,
                        "",
                    ));
                    out.push('\n');
                }
            }
        }
        for (n, row) in crate::display::cut(&clean(op.line), room)
            .iter()
            .enumerate()
        {
            match n {
                0 => out.push_str(&format!("{} {row}\n", op.op)),
                _ => out.push_str(&format!("{}{}{row}\n", op.op, crate::display::GUTTER)),
            }
        }
    }
    Ok(out)
}

/// The lines that enclose line `at` of `lines` by indentation, outermost first: each the
/// nearest line above with less indentation than the last (blank and comment lines skipped),
/// up to one at the left margin (`templates:`, then `feature:`). None for a line at the margin.
fn enclosing<'a>(lines: &[&'a str], at: usize) -> Vec<&'a str> {
    let indent = |line: &str| line.len().saturating_sub(line.trim_start().len());
    let mut level = lines.get(at).map_or(0, |line| indent(line));
    let mut found = Vec::new();
    for line in lines.get(..at).unwrap_or_default().iter().rev() {
        if level == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if indent(line) < level {
            found.push(trimmed);
            level = indent(line);
        }
    }
    found.reverse();
    found
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
            diff(before, after).unwrap(),
            "  …\n  b\n  c\n- d\n+ D\n  e\n  f\n  g\n+ h\n"
        );
        // A hostile line: shown escaped, never acted on.
        let shown = diff("", "x\u{1b}[2Jy\n").unwrap();
        assert_eq!(shown, "+ x\\u{1b}[2Jy\n");
        // Far apart: the unchanged middle is cut.
        let long: String = (0..20).map(|n| format!("{n}\n")).collect();
        let changed = long.replace("0\n", "zero\n").replace("19\n", "nineteen\n");
        let shown = diff(&long, &changed).unwrap();
        assert!(shown.contains("  …\n"), "{shown}");
        assert!(shown.starts_with("- 0\n+ zero\n  1\n  2\n"), "{shown}");
    }

    /// The review after M7.6 (U-6 a): past its bound the diff showed the whole new text as
    /// additions, so a removed line was nowhere. The lines both texts share are set aside
    /// first; what is left past the bound is refused, never shown otherwise.
    #[test]
    fn a_long_text_with_one_change_shows_that_change_and_a_change_past_the_bound_is_refused() {
        let lines = |prefix: &str, n: usize| -> String {
            (0..n).map(|i| format!("{prefix}{i}\n")).collect()
        };
        // 3,000 lines each side (9 million cells compared whole): one entry removed.
        let before = format!(
            "{}  - refs/heads/main\n{}",
            lines("a", 1500),
            lines("z", 1500)
        );
        let after = format!("{}{}", lines("a", 1500), lines("z", 1500));
        let shown = diff(&before, &after).unwrap();
        assert_eq!(
            shown,
            "  …\n@@ a1499\n  a1498\n  a1499\n-   - refs/heads/main\n  z0\n  z1\n"
        );
        // The bound on both sides: 1,999 × 1,999 changed lines (4,000,000 cells) compared,
        // 1,999 × 2,000 refused.
        let at = diff(&lines("b", 1999), &lines("c", 1999)).unwrap();
        assert_eq!(at.lines().filter(|l| l.starts_with("- ")).count(), 1999);
        assert_eq!(at.lines().filter(|l| l.starts_with("+ ")).count(), 1999);
        let shared = lines("same", 100);
        assert_eq!(
            crate::error_of(diff(
                &format!("{shared}{}{shared}", lines("b", 1999)),
                &format!("{shared}{}{shared}", lines("c", 2000))
            )),
            "the change is too large to show line by line (1999 lines replaced by 2000): \
             nothing was signed; split it into smaller changes, each signed on its own"
        );
    }

    /// The review after M7.6 (U-6 b): `- max_pushes: 5 / + max_pushes: 500` didn't say whose.
    /// Each hunk names the lines that enclose its first change, the section and the entry.
    #[test]
    fn a_hunk_names_the_section_and_the_entry_it_changes() {
        let entry = |name: &str, pushes: u32| {
            format!(
                "  {name}:\n    operations: [fetch, push]\n    branches: [\"agent/*\"]\n    \
                 max_ttl: 4h\n    max_pushes: {pushes}\n    max_signatures: 5\n"
            )
        };
        let policy = |second: u32| {
            format!(
                "format: 2\nkeys:\n  k: {{ use: signing }}\n\nrepos: {{}}\n\ntemplates:\n{}{}",
                entry("first", 5),
                entry("second", second)
            )
        };
        let shown = diff(&policy(5), &policy(500)).unwrap();
        assert_eq!(
            shown,
            "  …\n@@ templates: / second:\n      branches: [\"agent/*\"]\n      max_ttl: 4h\n-     \
             max_pushes: 5\n+     max_pushes: 500\n      max_signatures: 5\n"
        );
        // A change at the margin has nothing around it: no header (approvers and readers are
        // one line an entry).
        assert_eq!(diff("a\n", "b\n").unwrap(), "- a\n+ b\n");
        // A comment or a blank line above is no enclosing line.
        let shown = diff(
            "templates:\n  t:\n\n    # the count\n    max_pushes: 1\n",
            "templates:\n  t:\n\n    # the count\n    max_pushes: 2\n",
        )
        .unwrap();
        assert!(shown.contains("@@ templates: / t:\n"), "{shown}");
    }

    /// The review after M7.6 (U-6 c): a long line wrapped to column 0. Each row fits the
    /// display, a continuation behind its mark and the gutter.
    #[test]
    fn every_row_of_a_diff_fits_the_display_and_a_continuation_keeps_its_mark() {
        let long = format!("protected_refs: [{}]", "\"refs/heads/x\", ".repeat(60));
        let shown = diff("a: 1\n", &format!("a: 1\n{long}\n")).unwrap();
        let rows: Vec<&str> = shown.lines().collect();
        assert!(rows.len() > 10, "{shown}");
        for row in &rows {
            assert!(
                crate::display::width(row) <= crate::display::WIDTH,
                "{row:?}"
            );
        }
        assert!(rows.iter().skip(2).all(|r| r.starts_with("+│ ")), "{shown}");
        let kept: String = rows
            .iter()
            .skip(1)
            .map(|r| r.trim_start_matches("+ ").trim_start_matches("+│ "))
            .collect();
        assert_eq!(kept.replace(' ', ""), long.replace(' ', ""));
        // The header is cut to the width too.
        let name = "n".repeat(200);
        let shown = diff(
            &format!("templates:\n  {name}:\n    a: 1\n"),
            &format!("templates:\n  {name}:\n    a: 2\n"),
        )
        .unwrap();
        for row in shown.lines() {
            assert!(
                crate::display::width(row) <= crate::display::WIDTH,
                "{row:?}"
            );
        }
    }
}
