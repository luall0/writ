//! A fake `writ-se` (feature `testing`): speaks `writ-se/1` like the Swift helper, with
//! software P-256 keys (its stored bytes the key itself behind a header: a fake), and fails on
//! demand, to hold the helper signer to what a hostile or broken helper may do.
//!
//! `writ-fake-se [--fault <op>:<fault>]… [--from <n>] [--once <marker file>] [--record <file>]
//! [--context <name>] [--no-enclave]`: `op` is
//! `hello`, `create`, `public`, `sign`, `create-agreement`, `public-agreement` or `agree`;
//! `fault` is `crash` (exits mid-answer), `silent`
//! (never answers), `no-read` (stops reading the request after its operation byte, and never
//! answers), `oversize` (announces an answer past the bound), `bad-point`,
//! `other-key` (another key's point), `bad-signature` (a signature of other bytes), `refuse`
//! (refuses with a clean code), `dirty-code` (a code outside the alphabet), `extra-field`,
//! `unknown-status`, and for an agreement `short-secret` (31 bytes) or `other-secret` (another
//! key's shared secret). With `--from <n>`, a fault hits an operation from its `n`th request in
//! that process on (1, the default: every one), so a signer is built before a `sign` fault
//! hits (its probe is the first). With `--once`, the faults hit only a process that finds no
//! marker (it writes one): the next helper answers right. With `--context <name>`, each key it
//! makes is bound to that name, and a signature with a key bound to another (or made by a
//! helper with none) is refused, `sign-failed`, its point still answered: what the Secure
//! Enclave did with a key made outside the LaunchDaemon (2026-11-14). With `--record`, each request's operation and
//! its first field's length are appended to the file, one line each, before it is answered
//! (what the tests check never reached the helper).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::io::{Read, Write};

use writ_crypto::algorithm::{Hash, KeyAlgorithm};
use writ_crypto::keypair::KeyPair;

const HEADER: &[u8] = b"fake-se/1\n";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut faults: Vec<(String, String)> = Vec::new();
    let mut once = None;
    let mut record: Option<String> = None;
    let mut enclave = true;
    let mut from = 1usize;
    let mut context: Option<String> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--fault" => {
                let (op, fault) = it.next().unwrap().split_once(':').unwrap();
                faults.push((op.to_owned(), fault.to_owned()));
            }
            "--once" => once = Some(it.next().unwrap().clone()),
            "--record" => record = Some(it.next().unwrap().clone()),
            "--no-enclave" => enclave = false,
            "--from" => from = it.next().unwrap().parse().unwrap(),
            "--context" => context = Some(it.next().unwrap().clone()),
            other => panic!("unknown argument {other}"),
        }
    }
    if let Some(marker) = once {
        if std::path::Path::new(&marker).exists() {
            faults.clear();
        } else {
            std::fs::write(&marker, b"").unwrap();
        }
    }
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    let mut seen: std::collections::BTreeMap<&'static str, usize> = Default::default();
    loop {
        let mut len = [0u8; 4];
        if stdin.read_exact(&mut len).is_err() {
            return;
        }
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        // The operation first: a `no-read` fault stops reading there, the rest of the request
        // left in the pipe (a writer to it blocks once the pipe's buffer is full).
        stdin.read_exact(&mut body[..1]).unwrap();
        let wanted = op_name(body[0]);
        let count = seen.entry(wanted).or_insert(0);
        *count += 1;
        let armed = *count >= from;
        if armed && faults.iter().any(|(o, f)| o == wanted && f == "no-read") {
            loop {
                std::thread::park();
            }
        }
        stdin.read_exact(&mut body[1..]).unwrap();
        let (op, fields) = parse(&body);
        if let Some(record) = &record {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(record)
                .unwrap();
            let first = fields.first().map_or(0, Vec::len);
            writeln!(file, "{op} {first}").unwrap();
        }
        let fault = faults
            .iter()
            .find(|(o, _)| armed && o == op)
            .map(|(_, f)| f.as_str());
        let answer = match fault {
            Some("crash") => {
                stdout.write_all(&[0, 0, 0, 9, 0]).unwrap();
                stdout.flush().unwrap();
                std::process::abort();
            }
            Some("silent") => loop {
                std::thread::park();
            },
            Some("oversize") => {
                stdout.write_all(&(1u32 << 20).to_be_bytes()).unwrap();
                stdout.flush().unwrap();
                continue;
            }
            Some("refuse") => refused(b"refused-on-demand"),
            Some("dirty-code") => refused(b"Bad Code\x1b[31m"),
            Some("unknown-status") => vec![7],
            Some("extra-field") => {
                let mut ok = answer(op, &fields, enclave, context.as_deref());
                ok.extend_from_slice(&field(b"more"));
                ok
            }
            Some(
                other @ ("bad-point" | "other-key" | "bad-signature" | "short-secret"
                | "other-secret"),
            ) => tampered(op, &fields, other),
            Some(other) => panic!("unknown fault {other}"),
            None => answer(op, &fields, enclave, context.as_deref()),
        };
        stdout
            .write_all(&(answer.len() as u32).to_be_bytes())
            .unwrap();
        stdout.write_all(&answer).unwrap();
        stdout.flush().unwrap();
    }
}

fn op_name(op: u8) -> &'static str {
    match op {
        1 => "hello",
        2 => "create",
        3 => "public",
        4 => "sign",
        5 => "create-agreement",
        6 => "public-agreement",
        7 => "agree",
        other => panic!("unknown operation {other}"),
    }
}

fn parse(body: &[u8]) -> (&'static str, Vec<Vec<u8>>) {
    let op = op_name(body[0]);
    let mut fields = Vec::new();
    let mut rest = &body[1..];
    while !rest.is_empty() {
        let len = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
        fields.push(rest[4..4 + len].to_vec());
        rest = &rest[4 + len..];
    }
    (op, fields)
}

fn field(bytes: &[u8]) -> Vec<u8> {
    let mut out = (bytes.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

fn ok(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![0];
    for f in fields {
        out.extend_from_slice(&field(f));
    }
    out
}

fn refused(code: &[u8]) -> Vec<u8> {
    let mut out = vec![1];
    out.extend_from_slice(&field(code));
    out
}

/// The line binding a key to the context it was made in (`--context`).
const CONTEXT: &[u8] = b"context: ";

/// The key in `stored`, and the context it was made in.
fn bound(stored: &[u8]) -> Option<(KeyPair, Option<String>)> {
    let rest = stored.strip_prefix(HEADER)?;
    let (context, pem) = match rest.strip_prefix(CONTEXT) {
        Some(bound) => {
            let end = bound.iter().position(|b| *b == b'\n')?;
            (
                Some(String::from_utf8(bound[..end].to_vec()).ok()?),
                &bound[end + 1..],
            )
        }
        None => (None, rest),
    };
    Some((KeyPair::from_pem(pem).ok()?, context))
}

fn key(stored: &[u8]) -> Option<KeyPair> {
    bound(stored).map(|(key, _)| key)
}

fn point(key: &KeyPair) -> Vec<u8> {
    key.public_key()
        .key_data()
        .ecdsa()
        .unwrap()
        .as_sec1_bytes()
        .to_vec()
}

fn answer(op: &str, fields: &[Vec<u8>], enclave: bool, context: Option<&str>) -> Vec<u8> {
    match op {
        "hello" if !enclave => refused(b"no-secure-enclave"),
        "hello" => ok(&[b"writ-se/1"]),
        "create" if fields[0] != b"p256" => refused(b"unsupported-algorithm"),
        "create" => {
            let key = KeyPair::generate(KeyAlgorithm::P256).unwrap();
            let mut stored = HEADER.to_vec();
            if let Some(context) = context {
                stored.extend_from_slice(CONTEXT);
                stored.extend_from_slice(context.as_bytes());
                stored.push(b'\n');
            }
            stored.extend_from_slice(key.to_pem().unwrap().as_bytes());
            ok(&[&stored, &point(&key)])
        }
        "public" => match key(&fields[0]) {
            Some(key) => ok(&[&point(&key)]),
            None => refused(b"invalid-blob"),
        },
        "sign" => match bound(&fields[0]) {
            Some((_, Some(made))) if Some(made.as_str()) != context => refused(b"sign-failed"),
            Some((key, _)) => {
                let signature = key.sign(&fields[1], Some(Hash::Sha256)).unwrap();
                ok(&[signature.as_bytes()])
            }
            None => refused(b"invalid-blob"),
        },
        "create-agreement" if fields[0] != b"p256" => refused(b"unsupported-algorithm"),
        "create-agreement" => {
            let scalar = agreement_scalar();
            ok(&[&agreement_blob(&scalar), &agreement_point(&scalar)])
        }
        "public-agreement" => match agreement_key(&fields[0]) {
            Some(scalar) => ok(&[&agreement_point(&scalar)]),
            None => refused(b"invalid-blob"),
        },
        "agree" => match (
            agreement_key(&fields[0]),
            p256::PublicKey::from_sec1_bytes(&fields[1]),
        ) {
            (Some(scalar), Ok(peer)) => ok(&[&shared(&scalar, &peer)]),
            (None, _) => refused(b"invalid-blob"),
            (_, Err(_)) => refused(b"invalid-point"),
        },
        _ => unreachable!(),
    }
}

/// A fake key-agreement blob: its header, then the scalar (a fake: no secrecy).
const AGREEMENT_HEADER: &[u8] = b"fake-se-agreement/1\n";

fn agreement_scalar() -> p256::SecretKey {
    loop {
        let bytes = writ_crypto::keys::random_array::<32>().unwrap();
        if let Ok(key) = p256::SecretKey::from_slice(&bytes) {
            return key;
        }
    }
}

fn agreement_blob(key: &p256::SecretKey) -> Vec<u8> {
    let mut blob = AGREEMENT_HEADER.to_vec();
    blob.extend_from_slice(&key.to_bytes());
    blob
}

fn agreement_key(blob: &[u8]) -> Option<p256::SecretKey> {
    p256::SecretKey::from_slice(blob.strip_prefix(AGREEMENT_HEADER)?).ok()
}

fn agreement_point(key: &p256::SecretKey) -> Vec<u8> {
    use p256::elliptic_curve::sec1::ToSec1Point;
    key.public_key().to_sec1_point(false).as_bytes().to_vec()
}

fn shared(key: &p256::SecretKey, peer: &p256::PublicKey) -> Vec<u8> {
    p256::elliptic_curve::ecdh::diffie_hellman(key.to_nonzero_scalar(), peer.as_affine())
        .raw_secret_bytes()
        .to_vec()
}

fn tampered(op: &str, fields: &[Vec<u8>], fault: &str) -> Vec<u8> {
    let other = KeyPair::generate(KeyAlgorithm::P256).unwrap();
    let mut bad_point = point(&other);
    bad_point[64] ^= 1;
    match (op, fault) {
        ("create", "bad-point") => ok(&[b"fake-se/1\nx", &bad_point]),
        ("create", "other-key") => {
            let key = KeyPair::generate(KeyAlgorithm::P256).unwrap();
            let mut stored = HEADER.to_vec();
            stored.extend_from_slice(key.to_pem().unwrap().as_bytes());
            ok(&[&stored, &point(&other)])
        }
        ("public", "bad-point") => ok(&[&bad_point]),
        ("public", "other-key") => ok(&[&point(&other)]),
        ("sign", "bad-signature") => {
            let key = key(&fields[0]).unwrap();
            let signature = key.sign(b"other bytes", Some(Hash::Sha256)).unwrap();
            ok(&[signature.as_bytes()])
        }
        ("sign", "bad-point") => ok(&[&[0u8; 63]]),
        ("create-agreement", "bad-point") => {
            ok(&[&agreement_blob(&agreement_scalar()), &bad_point])
        }
        ("create-agreement", "other-key") => {
            let other = agreement_scalar();
            ok(&[
                &agreement_blob(&agreement_scalar()),
                &agreement_point(&other),
            ])
        }
        ("public-agreement", "bad-point") => ok(&[&bad_point]),
        ("public-agreement", "other-key") => ok(&[&agreement_point(&agreement_scalar())]),
        ("agree", "short-secret") => ok(&[&[7u8; 31]]),
        ("agree", "other-secret") => {
            let peer = p256::PublicKey::from_sec1_bytes(&fields[1]).unwrap();
            ok(&[&shared(&agreement_scalar(), &peer)])
        }
        _ => panic!("no {fault} for {op}"),
    }
}
