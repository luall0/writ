//! A fake `writ-se` (feature `testing`): speaks `writ-se/1` like the Swift helper, with
//! software P-256 keys (its stored bytes the key itself behind a header: a fake), and fails on
//! demand, to hold the helper signer to what a hostile or broken helper may do.
//!
//! `writ-fake-se [--fault <op>:<fault>]… [--once <marker file>] [--record <file>]
//! [--no-enclave]`: `op` is
//! `hello`, `create`, `public` or `sign`; `fault` is `crash` (exits mid-answer), `silent`
//! (never answers), `oversize` (announces an answer past the bound), `bad-point`,
//! `other-key` (another key's point), `bad-signature` (a signature of other bytes), `refuse`
//! (refuses with a clean code), `dirty-code` (a code outside the alphabet), `extra-field`,
//! `unknown-status`. With `--once`, the faults hit only a process that finds no marker (it
//! writes one): the next helper answers right. With `--record`, each request's operation and
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
    loop {
        let mut len = [0u8; 4];
        if stdin.read_exact(&mut len).is_err() {
            return;
        }
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        stdin.read_exact(&mut body).unwrap();
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
            .find(|(o, _)| o == op)
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
                let mut ok = answer(op, &fields, enclave);
                ok.extend_from_slice(&field(b"more"));
                ok
            }
            Some(other @ ("bad-point" | "other-key" | "bad-signature")) => {
                tampered(op, &fields, other)
            }
            Some(other) => panic!("unknown fault {other}"),
            None => answer(op, &fields, enclave),
        };
        stdout
            .write_all(&(answer.len() as u32).to_be_bytes())
            .unwrap();
        stdout.write_all(&answer).unwrap();
        stdout.flush().unwrap();
    }
}

fn parse(body: &[u8]) -> (&'static str, Vec<Vec<u8>>) {
    let op = match body[0] {
        1 => "hello",
        2 => "create",
        3 => "public",
        4 => "sign",
        other => panic!("unknown operation {other}"),
    };
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

fn key(stored: &[u8]) -> Option<KeyPair> {
    KeyPair::from_pem(stored.strip_prefix(HEADER)?).ok()
}

fn point(key: &KeyPair) -> Vec<u8> {
    key.public_key()
        .key_data()
        .ecdsa()
        .unwrap()
        .as_sec1_bytes()
        .to_vec()
}

fn answer(op: &str, fields: &[Vec<u8>], enclave: bool) -> Vec<u8> {
    match op {
        "hello" if !enclave => refused(b"no-secure-enclave"),
        "hello" => ok(&[b"writ-se/1"]),
        "create" if fields[0] != b"p256" => refused(b"unsupported-algorithm"),
        "create" => {
            let key = KeyPair::generate(KeyAlgorithm::P256).unwrap();
            let mut stored = HEADER.to_vec();
            stored.extend_from_slice(key.to_pem().unwrap().as_bytes());
            ok(&[&stored, &point(&key)])
        }
        "public" => match key(&fields[0]) {
            Some(key) => ok(&[&point(&key)]),
            None => refused(b"invalid-blob"),
        },
        "sign" => match key(&fields[0]) {
            Some(key) => {
                let signature = key.sign(&fields[1], Some(Hash::Sha256)).unwrap();
                ok(&[signature.as_bytes()])
            }
            None => refused(b"invalid-blob"),
        },
        _ => unreachable!(),
    }
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
        _ => panic!("no {fault} for {op}"),
    }
}
