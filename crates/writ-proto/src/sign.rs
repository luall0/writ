//! The body of `writ-sign git <repo>` (stdin): the object git asks to sign, then the objects
//! the daemon needs to compute the paths it touches (`writ_git::paths`).
//!
//! ```text
//! writ-sign/1\n
//! object <size>\n<bytes>            exactly once, first: what git asked to sign
//! commit <size>\n<bytes>            any number, in any order: the parent commits
//! tree <size>\n<bytes>              and the trees that differ
//! ```
//!
//! Sent by an untrusted client: decoded strictly (sizes in plain decimal, nothing after the
//! last object, at most [`MAX_EVIDENCE`] objects), and every object is checked by the daemon
//! against the id it must have before it is read.

/// The first line of a body.
const MAGIC: &[u8] = b"writ-sign/1\n";

/// The largest body the daemon reads (the commit and its evidence).
pub const MAX_SIGN_INPUT: usize = 16 * 1024 * 1024;

/// The most evidence objects one body may hold.
pub const MAX_EVIDENCE: usize = 100_000;

/// What an evidence object is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceKind {
    Commit,
    Tree,
}

impl EvidenceKind {
    fn name(self) -> &'static str {
        match self {
            EvidenceKind::Commit => "commit",
            EvidenceKind::Tree => "tree",
        }
    }
}

/// Why a body can't be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignInputError {
    /// Not a `writ-sign/1` body.
    Format,
    /// Over [`MAX_SIGN_INPUT`] or [`MAX_EVIDENCE`].
    TooLarge,
    /// An object's header or bytes are cut short or malformed.
    Malformed,
}

impl std::fmt::Display for SignInputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SignInputError::Format => "not a writ-sign/1 request (update writ-sign)",
            SignInputError::TooLarge => "the request is too large",
            SignInputError::Malformed => "the request is malformed",
        })
    }
}

impl std::error::Error for SignInputError {}

/// A decoded body.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SignInput {
    /// What git asked to sign.
    pub object: Vec<u8>,
    /// Parent commits and trees, for the touched paths.
    pub evidence: Vec<(EvidenceKind, Vec<u8>)>,
}

impl SignInput {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        push(&mut bytes, "object", &self.object);
        for (kind, content) in &self.evidence {
            push(&mut bytes, kind.name(), content);
        }
        bytes
    }

    /// Decodes a body; anything but the exact layout is refused.
    pub fn decode(bytes: &[u8]) -> Result<Self, SignInputError> {
        if bytes.len() > MAX_SIGN_INPUT {
            return Err(SignInputError::TooLarge);
        }
        let mut rest = bytes.strip_prefix(MAGIC).ok_or(SignInputError::Format)?;
        let (name, object, after) = next(rest)?;
        if name != b"object" {
            return Err(SignInputError::Malformed);
        }
        rest = after;
        let mut evidence = Vec::new();
        while !rest.is_empty() {
            if evidence.len() >= MAX_EVIDENCE {
                return Err(SignInputError::TooLarge);
            }
            let (name, content, after) = next(rest)?;
            let kind = match name {
                b"commit" => EvidenceKind::Commit,
                b"tree" => EvidenceKind::Tree,
                _ => return Err(SignInputError::Malformed),
            };
            evidence.push((kind, content.to_vec()));
            rest = after;
        }
        Ok(Self {
            object: object.to_vec(),
            evidence,
        })
    }
}

fn push(bytes: &mut Vec<u8>, name: &str, content: &[u8]) {
    bytes.extend_from_slice(format!("{name} {}\n", content.len()).as_bytes());
    bytes.extend_from_slice(content);
}

/// An object read from a body: its name, its bytes, and what follows it.
type Next<'a> = (&'a [u8], &'a [u8], &'a [u8]);

/// The next object of a body.
fn next(bytes: &[u8]) -> Result<Next<'_>, SignInputError> {
    let newline = bytes
        .iter()
        .take(32)
        .position(|&b| b == b'\n')
        .ok_or(SignInputError::Malformed)?;
    let (header, rest) = bytes
        .split_at_checked(newline)
        .ok_or(SignInputError::Malformed)?;
    let rest = rest.get(1..).ok_or(SignInputError::Malformed)?;
    let mut fields = header.splitn(2, |&b| b == b' ');
    let name = fields.next().ok_or(SignInputError::Malformed)?;
    let size = fields.next().ok_or(SignInputError::Malformed)?;
    let canonical = !size.is_empty()
        && size.iter().all(u8::is_ascii_digit)
        && (size == b"0" || size.first() != Some(&b'0'));
    let size: usize = std::str::from_utf8(size)
        .ok()
        .filter(|_| canonical)
        .and_then(|s| s.parse().ok())
        .ok_or(SignInputError::Malformed)?;
    let (content, rest) = rest
        .split_at_checked(size)
        .ok_or(SignInputError::Malformed)?;
    Ok((name, content, rest))
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    fn sample() -> SignInput {
        SignInput {
            object: b"tree abc\n\nmessage with object 3\n in it".to_vec(),
            evidence: vec![
                (EvidenceKind::Commit, b"tree def\n".to_vec()),
                (EvidenceKind::Tree, vec![0, 1, 2, b'\n']),
                (EvidenceKind::Tree, Vec::new()),
            ],
        }
    }

    #[test]
    fn round_trips() {
        let input = sample();
        assert_eq!(SignInput::decode(&input.encode()), Ok(input));
        let bare = SignInput {
            object: b"x".to_vec(),
            evidence: Vec::new(),
        };
        assert_eq!(bare.encode(), b"writ-sign/1\nobject 1\nx");
        assert_eq!(SignInput::decode(&bare.encode()), Ok(bare));
    }

    #[test]
    fn refuses_anything_else() {
        let good = sample().encode();
        let cases: Vec<(Vec<u8>, SignInputError)> = vec![
            (b"tree abc\n".to_vec(), SignInputError::Format),
            (b"writ-sign/2\nobject 1\nx".to_vec(), SignInputError::Format),
            (good[..good.len() - 1].to_vec(), SignInputError::Malformed),
            ([&good[..], b"x"].concat(), SignInputError::Malformed),
            (
                b"writ-sign/1\ncommit 1\nx".to_vec(),
                SignInputError::Malformed,
            ),
            (
                b"writ-sign/1\nobject 01\nx".to_vec(),
                SignInputError::Malformed,
            ),
            (
                b"writ-sign/1\nobject +1\nx".to_vec(),
                SignInputError::Malformed,
            ),
            (b"writ-sign/1\nobject 1".to_vec(), SignInputError::Malformed),
            (
                b"writ-sign/1\nobject 2\nx".to_vec(),
                SignInputError::Malformed,
            ),
            (
                b"writ-sign/1\nobject 99999999999999999999999\nx".to_vec(),
                SignInputError::Malformed,
            ),
            (
                b"writ-sign/1\nobject 1\nxblob 1\ny".to_vec(),
                SignInputError::Malformed,
            ),
            (b"writ-sign/1\n".to_vec(), SignInputError::Malformed),
        ];
        for (bytes, expected) in cases {
            assert_eq!(
                SignInput::decode(&bytes),
                Err(expected.clone()),
                "{expected}: {:?}",
                String::from_utf8_lossy(&bytes)
            );
        }
    }

    #[test]
    fn bounds_on_both_sides() {
        let empty_trees = |n: usize| SignInput {
            object: b"x".to_vec(),
            evidence: vec![(EvidenceKind::Tree, Vec::new()); n],
        };
        assert_eq!(
            SignInput::decode(&empty_trees(MAX_EVIDENCE).encode()).map(|i| i.evidence.len()),
            Ok(MAX_EVIDENCE)
        );
        assert_eq!(
            SignInput::decode(&empty_trees(MAX_EVIDENCE + 1).encode()),
            Err(SignInputError::TooLarge)
        );
        let sized = |total: usize| {
            let overhead = SignInput::default().encode().len() + 8;
            let mut input = SignInput {
                object: vec![b'a'; total - overhead],
                evidence: Vec::new(),
            };
            // Make the encoding exactly `total` bytes.
            while input.encode().len() < total {
                input.object.push(b'a');
            }
            while input.encode().len() > total {
                input.object.pop();
            }
            input.encode()
        };
        assert!(SignInput::decode(&sized(MAX_SIGN_INPUT)).is_ok());
        assert_eq!(
            SignInput::decode(&sized(MAX_SIGN_INPUT + 1)),
            Err(SignInputError::TooLarge)
        );
    }
}
