//! git's progress on a sync (`fetch --progress`), read from its stderr as it comes: the phase
//! and its two counts, for the mirror's sync status (`writ admin repo status`).
//!
//! Upstream's words, in part: the objects' total is what its pack says, and a `remote:` line is
//! its own text. So only a phase from a fixed list is read, the counts as ASCII digits into a
//! `u64`, and nothing of the text goes on: the status holds the phase and the numbers, shown in
//! Writ's own words, never enforced. Every other part of the stderr is kept, as before, for a
//! failure to be classified from.

/// The longest part of git's stderr (between two `\r` or `\n`) looked at as progress: git's
/// lines are under 100 bytes; a longer part is kept as text.
pub(crate) const MAX_PART: usize = 256;

/// What a sync is doing, as git says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Upstream preparing the pack (`remote: Enumerating objects`, `Counting objects`,
    /// `Compressing objects`).
    Preparing,
    /// git receiving the pack (`Receiving objects`).
    Receiving,
    /// git resolving its deltas, local work (`Resolving deltas`).
    Resolving,
}

impl Phase {
    /// The phase in Writ's words.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Preparing => "upstream preparing objects",
            Self::Receiving => "receiving objects",
            Self::Resolving => "resolving deltas",
        }
    }
}

/// One progress report: a phase, how much of it is done, of how much.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    pub phase: Phase,
    /// At most `total`.
    pub done: u64,
    pub total: u64,
}

impl Progress {
    /// The percent done, 0 to 100 (100 for an empty total).
    pub fn percent(&self) -> u64 {
        if self.total == 0 {
            return 100;
        }
        // `done <= total`: the product of a u64 by 100 fits in a u128, the quotient is at most 100.
        let percent = u128::from(self.done)
            .saturating_mul(100)
            .checked_div(u128::from(self.total))
            .unwrap_or(100);
        u64::try_from(percent).unwrap_or(100)
    }
}

/// The phases read, by git's words: git's own, then upstream's after `remote: `.
const PHASES: [(&str, Phase); 5] = [
    ("Receiving objects: ", Phase::Receiving),
    ("Resolving deltas: ", Phase::Resolving),
    ("remote: Enumerating objects: ", Phase::Preparing),
    ("remote: Counting objects: ", Phase::Preparing),
    ("remote: Compressing objects: ", Phase::Preparing),
];

/// Reads one part of git's stderr (without its `\r` or `\n`) as progress:
/// `<phase>: <percent>% (<done>/<total>)`, anything after it (`, 1.2 MiB | 300 KiB/s`,
/// `, done.`) ignored. Anything else is `None`, kept as text.
pub(crate) fn parse(part: &[u8]) -> Option<Progress> {
    if part.len() > MAX_PART {
        return None;
    }
    let (rest, phase) = PHASES.iter().find_map(|(words, phase)| {
        part.strip_prefix(words.as_bytes())
            .map(|rest| (rest, *phase))
    })?;
    let rest = trim_spaces(rest);
    let (_percent, rest) = digits(rest)?;
    let rest = rest.strip_prefix(b"% (")?;
    let (done, rest) = digits(rest)?;
    let rest = rest.strip_prefix(b"/")?;
    let (total, rest) = digits(rest)?;
    rest.strip_prefix(b")")?;
    Some(Progress {
        phase,
        done: done.min(total),
        total,
    })
}

/// Leading spaces dropped (git pads the percent to three columns).
fn trim_spaces(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().take_while(|b| **b == b' ').count();
    bytes.get(start..).unwrap_or_default()
}

/// A run of 1 to 20 ASCII digits read as a `u64` (an overflow is `None`), and what follows.
fn digits(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let count = bytes.iter().take_while(|b| b.is_ascii_digit()).count();
    if count == 0 || count > 20 {
        return None;
    }
    let (number, rest) = bytes.split_at_checked(count)?;
    let number = std::str::from_utf8(number).ok()?.parse().ok()?;
    Some((number, rest))
}

/// git's stderr split as it comes: each progress part handed to `on_progress`, every other
/// byte kept (at most `max`), so the text a failure is classified from is what git said
/// without its progress.
pub(crate) struct StderrSplit<'a> {
    kept: Vec<u8>,
    max: usize,
    /// The part being read, until its `\r` or `\n` (at most [`MAX_PART`] bytes).
    part: Vec<u8>,
    /// The part being read is longer than [`MAX_PART`]: kept as text up to its end.
    long: bool,
    on_progress: &'a mut (dyn FnMut(Progress) + Send),
}

impl<'a> StderrSplit<'a> {
    pub(crate) fn new(max: usize, on_progress: &'a mut (dyn FnMut(Progress) + Send)) -> Self {
        Self {
            kept: Vec::new(),
            max,
            part: Vec::with_capacity(MAX_PART),
            long: false,
            on_progress,
        }
    }

    pub(crate) fn push(&mut self, chunk: &[u8]) {
        for &byte in chunk {
            let end = byte == b'\r' || byte == b'\n';
            if self.long {
                self.keep(&[byte]);
                self.long = !end;
                continue;
            }
            if end {
                match parse(&self.part) {
                    Some(progress) => (self.on_progress)(progress),
                    None => {
                        let part = std::mem::take(&mut self.part);
                        self.keep(&part);
                        self.keep(&[byte]);
                        self.part = part;
                    }
                }
                self.part.clear();
            } else if self.part.len() >= MAX_PART {
                let part = std::mem::take(&mut self.part);
                self.keep(&part);
                self.keep(&[byte]);
                self.part = part;
                self.part.clear();
                self.long = true;
            } else {
                self.part.push(byte);
            }
        }
    }

    /// What was kept, the last part (with no end) included.
    pub(crate) fn finish(mut self) -> Vec<u8> {
        let part = std::mem::take(&mut self.part);
        match parse(&part) {
            Some(progress) => (self.on_progress)(progress),
            None => self.keep(&part),
        }
        self.kept
    }

    fn keep(&mut self, bytes: &[u8]) {
        let room = self.max.saturating_sub(self.kept.len());
        self.kept
            .extend_from_slice(bytes.get(..room.min(bytes.len())).unwrap_or_default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(chunks: &[&[u8]], max: usize) -> (Vec<u8>, Vec<Progress>) {
        let mut seen = Vec::new();
        let mut on = |p: Progress| seen.push(p);
        let mut stderr = StderrSplit::new(max, &mut on);
        for chunk in chunks {
            stderr.push(chunk);
        }
        let kept = stderr.finish();
        (kept, seen)
    }

    #[test]
    fn git_s_progress_lines_are_read_as_phases_and_counts() {
        let p = |phase, done, total| Progress { phase, done, total };
        assert_eq!(
            parse(b"Receiving objects:  45% (4500/10000), 12.00 MiB | 1.00 MiB/s"),
            Some(p(Phase::Receiving, 4500, 10000))
        );
        assert_eq!(
            parse(b"Receiving objects: 100% (10000/10000), 120.00 MiB | 2.00 MiB/s, done."),
            Some(p(Phase::Receiving, 10000, 10000))
        );
        assert_eq!(
            parse(b"Resolving deltas:   3% (30/1000)"),
            Some(p(Phase::Resolving, 30, 1000))
        );
        assert_eq!(
            parse(b"remote: Counting objects: 100% (5/5), done."),
            Some(p(Phase::Preparing, 5, 5))
        );
        assert_eq!(
            parse(b"remote: Compressing objects:  50% (2/4)"),
            Some(p(Phase::Preparing, 2, 4))
        );
        assert_eq!(p(Phase::Receiving, 4500, 10000).percent(), 45);
        assert_eq!(p(Phase::Receiving, 0, 0).percent(), 100);
        assert_eq!(p(Phase::Receiving, u64::MAX, u64::MAX).percent(), 100);
        assert_eq!(p(Phase::Receiving, u64::MAX - 1, u64::MAX).percent(), 99);
    }

    #[test]
    fn hostile_progress_never_reaches_the_status_but_as_numbers() {
        // Not a phase Writ reads, or not in git's words: text, kept.
        for part in [
            &b"Receiving objects"[..],
            b"receiving objects: 45% (1/2)",
            b"Updating files: 45% (1/2)",
            b"remote: Receiving objects: 45% (1/2)",
            b" Receiving objects: 45% (1/2)",
            b"remote: Total 5 (delta 0), reused 0 (delta 0)",
            b"Receiving objects: 45% (1/2",
            b"Receiving objects: 45%(1/2)",
            b"Receiving objects: % (1/2)",
            b"Receiving objects: 45% (/2)",
            b"Receiving objects: 45% (1/)",
            b"Receiving objects: 45% (-1/2)",
            b"Receiving objects: 45% (1/+2)",
            b"Receiving objects: 45% (\xd9\xa1/2)",
            b"Receiving objects: 45% (1\x1b[2J/2)",
            // A count past u64: no progress, never a wrapped number.
            b"Receiving objects: 45% (18446744073709551616/18446744073709551616)",
            b"Receiving objects: 45% (1/000000000000000000001)",
        ] {
            assert_eq!(parse(part), None, "{}", String::from_utf8_lossy(part));
        }
        // A done past the total is shown at the total; the percent is Writ's, not git's.
        assert_eq!(
            parse(b"Receiving objects: 999% (7/3)"),
            Some(Progress {
                phase: Phase::Receiving,
                done: 3,
                total: 3
            })
        );
        // The longest count that fits.
        assert_eq!(
            parse(b"Receiving objects: 1% (1/18446744073709551615)").map(|p| p.total),
            Some(u64::MAX)
        );
        // A part past MAX_PART is text, whatever it starts with.
        let mut long = b"Receiving objects: 45% (1/2)".to_vec();
        long.resize(MAX_PART + 1, b' ');
        assert_eq!(parse(&long), None);
    }

    #[test]
    fn progress_is_taken_out_of_stderr_and_everything_else_kept() {
        let (kept, seen) = split(
            &[
                b"remote: Enumerating objects: 5, done.\n",
                b"remote: Counting objects:  50% (1/2)\rremote: Counting objects: 100% (2/2), done.\n",
                b"Receiving objects:  50% (1/2)\rReceiv",
                b"ing objects: 100% (2/2), done.\n",
                b"fatal: the remote end hung up unexpectedly\n",
                b"Resolving deltas: 100% (1/1)",
            ],
            1 << 16,
        );
        assert_eq!(
            String::from_utf8(kept).unwrap(),
            "remote: Enumerating objects: 5, done.\nfatal: the remote end hung up unexpectedly\n"
        );
        let phases: Vec<_> = seen.iter().map(|p| (p.phase, p.done, p.total)).collect();
        assert_eq!(
            phases,
            [
                (Phase::Preparing, 1, 2),
                (Phase::Preparing, 2, 2),
                (Phase::Receiving, 1, 2),
                (Phase::Receiving, 2, 2),
                (Phase::Resolving, 1, 1),
            ]
        );
    }

    #[test]
    fn a_long_part_is_kept_whole_and_the_cap_holds() {
        let mut line = b"Receiving objects: 45% (1/2)".to_vec();
        line.resize(MAX_PART * 3, b'x');
        line.push(b'\n');
        line.extend_from_slice(b"Receiving objects: 45% (1/2)\n");
        let (kept, seen) = split(&[&line], 1 << 16);
        // The long line kept whole with its end; the short one after it read as progress.
        assert_eq!(kept.len(), MAX_PART * 3 + 1);
        assert_eq!(seen.len(), 1);
        // The cap holds for the long part and the rest.
        let (kept, _) = split(&[&line, b"error: one\nerror: two\n"], 100);
        assert_eq!(kept.len(), 100);
        // Many progress parts take none of the cap.
        let flood = b"Receiving objects:  1% (1/100)\r".repeat(10_000);
        let (kept, seen) = split(&[&flood, b"fatal: the end\n"], 64);
        assert_eq!(kept, b"fatal: the end\n");
        assert_eq!(seen.len(), 10_000);
    }
}
