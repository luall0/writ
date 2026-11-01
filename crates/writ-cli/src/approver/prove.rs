//! `writ prove-key <key id> --namespace <ns>`: proves an agent signing key to a remote that
//! asks for it before it shows commits as verified (Forgejo and Gitea: namespace `gitea`).
//! Used in place of `ssh-keygen -Y sign -n <ns>` in the remote's instructions: the message on
//! stdin, signed exactly as it is (no newline added or removed), the armored signature on
//! stdout, everything else on stderr.
//!
//! The message is the remote's text: shown escaped, never interpreted. A proof is an
//! approval: the approver's agent signs a `writ-proof/1` document naming the key, the
//! namespace and the message (one Touch ID), and the daemon signs only that. Checks here
//! are conveniences: the daemon checks the namespace, the size, the key and the signature
//! again.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};

use anyhow::{Context, bail};
use writ_core::names::{KeyId, ProofNamespace};
use writ_core::signed::{MAX_PROOF_MESSAGE_BYTES, Proof, ProofMessage};
use writ_crypto::ssh_key::{HashAlg, PublicKey};
use writ_proto::{Command, ProveRequest, Proved};

use super::Signer;
use crate::client::Approvals;
use crate::display;
use crate::{Exit, Paths};
use writ_core::canonical::Canonical;

/// What `writ prove-key` was asked: the key, the namespace, and whether to ask first.
pub struct ProveKey {
    pub key: KeyId,
    pub namespace: ProofNamespace,
    /// Sign without asking (the proof is still shown first).
    pub yes: bool,
}

/// The message on stdin: at most [`MAX_PROOF_MESSAGE_BYTES`] bytes of UTF-8, as it is.
fn read_message(input: impl std::io::Read) -> anyhow::Result<ProofMessage> {
    let mut bytes = Vec::new();
    let limit = u64::try_from(MAX_PROOF_MESSAGE_BYTES)?.saturating_add(1);
    input
        .take(limit)
        .read_to_end(&mut bytes)
        .context("cannot read the message on stdin")?;
    if bytes.len() > MAX_PROOF_MESSAGE_BYTES {
        bail!("the message on stdin is longer than {MAX_PROOF_MESSAGE_BYTES} bytes");
    }
    let text = String::from_utf8(bytes).context("the message on stdin is not UTF-8")?;
    Ok(ProofMessage::try_from(text)?)
}

/// What is about to be signed, for the terminal.
fn render(proof: &Proof) -> String {
    let message = proof.message.as_str();
    format!(
        "Prove an agent signing key to a remote.\n\
         \x20 key        {key}\n\
         \x20 namespace  {namespace}\n\
         \x20 message    {len} bytes, exactly (hidden characters, newlines included, as \\u{{…}}):\n\
         \x20   │ {shown}\n\
         The daemon's key {key} signs this message in namespace {namespace:?}, and nothing else.\n",
        key = proof.key,
        namespace = proof.namespace.as_str(),
        len = message.len(),
        shown = display::clean(message),
    )
}

/// Asks on the terminal (stdin holds the message): only `y` or `yes` signs.
fn confirm(key: &KeyId) -> anyhow::Result<bool> {
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("no terminal to ask on: check the proof above and pass --yes")?;
    let mut out = &tty;
    write!(out, "Sign this proof for {key}? [y/N]: ").context("cannot write to the terminal")?;
    out.flush().context("cannot write to the terminal")?;
    let mut answer = String::new();
    BufReader::new(&tty)
        .read_line(&mut answer)
        .context("cannot read the answer")?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// `writ prove-key`.
pub async fn prove_key(
    paths: &Paths,
    url: &str,
    signer: &Signer,
    asked: ProveKey,
) -> anyhow::Result<Exit> {
    let message = read_message(std::io::stdin().lock())?;
    let proof = Proof::new(asked.key, asked.namespace, message);
    eprint!("{}", render(&proof));
    if !asked.yes && !confirm(&proof.key)? {
        eprintln!("Nothing signed.");
        return Ok(Exit::NotSigned);
    }
    let bytes = proof.canonical_bytes()?;
    // Sign exactly what was displayed: the bytes must decode back to it.
    if Proof::from_canonical(&bytes)? != proof {
        bail!("the proof doesn't re-encode to itself: not signing it");
    }
    let request = ProveRequest {
        signature: signer.sign(&bytes)?,
        proof: String::from_utf8(bytes)?,
    };
    let proved: Proved = Approvals::connect(paths, url)
        .await?
        .run(async |session| {
            Ok(session
                .call(&Command::Prove, &writ_proto::encode_body(&request)?)
                .await??)
        })
        .await?;
    // A convenience: what came back is the key's signature over this message, in this
    // namespace (the remote checks it again).
    let public = PublicKey::from_openssh(proved.public_key.trim())
        .context("the daemon sent an unreadable public key")?;
    writ_crypto::sshsig::verify(
        std::slice::from_ref(&public),
        proof.namespace.as_str(),
        proof.message.as_str().as_bytes(),
        &proved.signature,
    )
    .context("the daemon's signature doesn't verify over the message")?;
    eprintln!(
        "Signed by {} ({}) in namespace {}:",
        proof.key,
        public.fingerprint(HashAlg::Sha256),
        proof.namespace.as_str()
    );
    print!("{}", proved.signature);
    if !proved.signature.ends_with('\n') {
        println!();
    }
    Ok(Exit::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_message_is_read_exactly_and_bounded() {
        let message = read_message(&b"e3b0c442\n"[..]).unwrap();
        assert_eq!(message.as_str(), "e3b0c442\n");
        let longest = vec![b'a'; MAX_PROOF_MESSAGE_BYTES];
        assert_eq!(
            read_message(&longest[..]).unwrap().as_str().len(),
            MAX_PROOF_MESSAGE_BYTES
        );
        let over = vec![b'a'; MAX_PROOF_MESSAGE_BYTES + 1];
        let error = crate::error_of(read_message(&over[..]));
        assert_eq!(error, "the message on stdin is longer than 4096 bytes");
        let error = crate::error_of(read_message(&b""[..]));
        assert_eq!(
            error,
            "the message to sign is 0 bytes: it must be 1 to 4096"
        );
        let error = crate::error_of(read_message(&[0xff, 0xfe][..]));
        assert!(
            error.starts_with("the message on stdin is not UTF-8"),
            "{error}"
        );
    }

    #[test]
    fn the_display_shows_every_hidden_character() {
        let proof = Proof::new(
            "agent-01".parse().unwrap(),
            "gitea".parse().unwrap(),
            "tok\u{1b}[2Jen\u{202e}\n".to_owned().try_into().unwrap(),
        );
        let shown = render(&proof);
        assert!(
            shown.contains("│ tok\\u{1b}[2Jen\\u{202e}\\u{a}\n"),
            "{shown}"
        );
        assert!(!shown.contains('\u{1b}') && !shown.contains('\u{202e}'));
        assert!(shown.contains("namespace  gitea\n"), "{shown}");
        assert!(shown.contains("13 bytes"), "{shown}");
    }
}
