//! The process reader, a capped helper (docs/architecture/platform.md): `writd run` starts
//! `writd proc-reader` first, which alone keeps `CAP_SYS_PTRACE`, and drops every capability
//! itself. The helper reads one process's links per request on a socket pair (its stdin) and
//! answers with what they say ([`serve`]); the daemon asks through a [`Helper`], which reads
//! the rest (`stat`, world-readable) and holds the pidfd around the answer ([`read_with`]).
//!
//! Before it reads a request, the helper installs a seccomp filter ([`crate::sys::confine`]):
//! from then on it can read and write its socket, `readlink`, manage its memory and exit,
//! nothing else (no `open`, so no `/proc/<pid>/mem`; no `ptrace`, `pidfd_getfd`,
//! `process_vm_*`). Any other call kills it, and the daemon refuses every Unix caller from then
//! on, as for a helper that crashed.
//!
//! The protocol, one request then one answer, little-endian:
//!
//! - request: the pid, `u32` (`0` asks for the host's namespaces);
//! - answer: a tag, then for `0` (links) the pid and mount namespaces `u64` each, deleted `u8`
//!   (0 or 1), the executable's length `u16` and its bytes; for `1` (gone) and `2`
//!   (unreadable) the reason's length `u16` and its UTF-8; for `3` (the host's namespaces) the
//!   pid and mount namespaces.
//!
//! The helper's answers are bounded and checked like any other input: a broken one ends the
//! helper's use, as an answer that doesn't come within [`ANSWER_DEADLINE`] does. It is never
//! started again (the daemon has no capability left to give it): every Unix caller is refused
//! from then on, with that reason, logged once.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use crate::procfs::{MAX_EXECUTABLE_BYTES, Namespaces, ReadError};
use crate::read::{Entry, Links, ReadLinks, ReadProcess, read_with};

/// How long one answer may take (a few system calls): past it, the helper is stuck.
pub const ANSWER_DEADLINE: Duration = Duration::from_secs(5);

/// The longest reason an answer holds.
pub const MAX_REASON_BYTES: usize = 512;

/// What the helper writes once it holds its capability and nothing else: it is ready.
const READY: u8 = b'R';

const TAG_READ: u8 = 0;
const TAG_GONE: u8 = 1;
const TAG_UNREADABLE: u8 = 2;
const TAG_HOST: u8 = 3;

/// The pid that asks for the host's namespaces (no process has pid 0).
const HOST: u32 = 0;

// ----- The helper's side -----

/// `writd proc-reader`: ends with its parent (`PR_SET_PDEATHSIG`, and its stdin closing),
/// keeps `CAP_SYS_PTRACE` alone, then [`serve_confined`]s its stdin with a
/// [`Direct`](crate::read::Direct) reader whose host is pid 1's.
pub fn serve_stdin() -> std::io::Result<()> {
    use std::os::fd::AsFd as _;
    rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))?;
    crate::caps::keep_ptrace_only()?;
    let stdin = std::io::stdin().as_fd().try_clone_to_owned()?;
    serve_confined(
        UnixStream::from(stdin),
        &crate::read::Direct::new(crate::read::Host::Init),
    )
}

/// [`serve`], once [`confine`]d: the helper's way.
pub fn serve_confined(stream: UnixStream, reader: &dyn ReadLinks) -> std::io::Result<()> {
    confine()?;
    serve(stream, reader)
}

/// Installs the helper's seccomp filter on the calling thread (and whatever it starts), for
/// good: its socket read and written, `readlink`, its memory, its exit; any other call kills
/// the process. x86_64 and aarch64 only (elsewhere, refused).
pub fn confine() -> std::io::Result<()> {
    crate::sys::confine()
}

/// Says the helper is ready, then answers requests on `stream` with `reader` until the
/// daemon closes it (or an I/O error ends it).
pub fn serve(mut stream: UnixStream, reader: &dyn ReadLinks) -> std::io::Result<()> {
    stream.write_all(&[READY])?;
    loop {
        let mut request = [0u8; 4];
        match stream.read_exact(&mut request) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let pid = u32::from_le_bytes(request);
        let answer = if pid == HOST {
            match reader.host_namespaces() {
                Ok(host) => host_answer(host),
                Err(e) => error_answer(&e),
            }
        } else {
            match reader.links(pid) {
                Ok(links) => links_answer(pid, &links),
                Err(e) => error_answer(&e),
            }
        };
        stream.write_all(&answer)?;
    }
}

fn links_answer(pid: u32, links: &Links) -> Vec<u8> {
    let executable = links.executable.as_os_str().as_encoded_bytes();
    // `procfs::executable` bounds it; past the bound, said unreadable rather than cut.
    let Ok(length) = u16::try_from(executable.len()) else {
        return error_answer(&ReadError::Unreadable(format!(
            "pid {pid}: its executable's path is too long"
        )));
    };
    let mut out = vec![TAG_READ];
    out.extend_from_slice(&links.namespaces.pid.to_le_bytes());
    out.extend_from_slice(&links.namespaces.mnt.to_le_bytes());
    out.push(u8::from(links.deleted));
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(executable);
    out
}

fn host_answer(host: Namespaces) -> Vec<u8> {
    let mut out = vec![TAG_HOST];
    out.extend_from_slice(&host.pid.to_le_bytes());
    out.extend_from_slice(&host.mnt.to_le_bytes());
    out
}

fn error_answer(error: &ReadError) -> Vec<u8> {
    let (tag, why) = match error {
        ReadError::Gone(why) => (TAG_GONE, why),
        ReadError::Unreadable(why) => (TAG_UNREADABLE, why),
    };
    let mut end = why.len().min(MAX_REASON_BYTES);
    while !why.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let why = why.get(..end).unwrap_or_default().as_bytes();
    let mut out = vec![tag];
    out.extend_from_slice(&u16::try_from(why.len()).unwrap_or(0).to_le_bytes());
    out.extend_from_slice(why);
    out
}

// ----- The daemon's side -----

/// The daemon's end of the helper: asks it one process at a time.
pub struct Helper {
    /// `Ended` once the helper can't be trusted to answer any more, with why.
    state: Mutex<State>,
}

enum State {
    Open {
        stream: UnixStream,
        child: Option<Child>,
    },
    Ended(String),
}

impl std::fmt::Debug for Helper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Helper")
    }
}

impl Helper {
    /// Starts `program args…` with its stdin a socket pair's end, and waits until it says it
    /// is ready (it holds its capability, nothing else), at most [`ANSWER_DEADLINE`].
    pub fn spawn(program: &Path, args: &[&str]) -> std::io::Result<Self> {
        let (mine, theirs) = UnixStream::pair()?;
        let child = Command::new(program)
            .args(args)
            .stdin(Stdio::from(std::os::fd::OwnedFd::from(theirs)))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .env_clear()
            .spawn()?;
        Self::ready(mine, Some(child), ANSWER_DEADLINE)
    }

    /// The daemon's end of a helper already started on the other end of `stream` (a thread,
    /// in the tests): waits until it says it is ready. Each answer within `deadline`.
    pub fn over(stream: UnixStream, deadline: Duration) -> std::io::Result<Self> {
        Self::ready(stream, None, deadline)
    }

    fn ready(
        mut stream: UnixStream,
        child: Option<Child>,
        deadline: Duration,
    ) -> std::io::Result<Self> {
        stream.set_read_timeout(Some(deadline))?;
        stream.set_write_timeout(Some(deadline))?;
        let mut ready = [0u8; 1];
        let said = stream.read_exact(&mut ready);
        if said.is_err() || ready != [READY] {
            if let Some(mut child) = child {
                let _ = child.kill();
                let _ = child.wait();
            }
            return Err(std::io::Error::other(match said {
                Err(e) => format!("the process reader didn't start: {e}"),
                Ok(()) => "the process reader said something else than ready".to_owned(),
            }));
        }
        Ok(Self {
            state: Mutex::new(State::Open { stream, child }),
        })
    }

    /// One request and its answer; any failure ends the helper's use for good.
    fn ask(&self, pid: u32) -> Result<Answer, ReadError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let result = match &mut *state {
            State::Ended(why) => return Err(ReadError::Unreadable(why.clone())),
            State::Open { stream, .. } => exchange(stream, pid),
        };
        match result {
            Ok(answer) => Ok(answer),
            Err(why) => {
                let why = format!("the process reader can't be used any more ({why})");
                tracing::error!(error = %why, "every caller on a Unix socket is refused from now on");
                if let State::Open {
                    child: Some(child), ..
                } = &mut *state
                {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                *state = State::Ended(why.clone());
                Err(ReadError::Unreadable(why))
            }
        }
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let State::Open { stream, child } = state {
            // Its stdin closed, it ends.
            let _ = stream.shutdown(std::net::Shutdown::Both);
            if let Some(child) = child {
                let _ = child.wait();
            }
        }
    }
}

enum Answer {
    Read(Links),
    Host(Namespaces),
    Error(ReadError),
}

fn exchange(stream: &mut UnixStream, pid: u32) -> Result<Answer, String> {
    stream
        .write_all(&pid.to_le_bytes())
        .map_err(|e| format!("asking it: {e}"))?;
    let mut answer = Reader(stream);
    match answer.u8()? {
        TAG_READ => {
            let namespaces = Namespaces {
                pid: answer.u64()?,
                mnt: answer.u64()?,
            };
            let deleted = match answer.u8()? {
                0 => false,
                1 => true,
                other => return Err(format!("its answer has a deleted flag of {other}")),
            };
            let bytes = answer.bytes(MAX_EXECUTABLE_BYTES)?;
            Ok(Answer::Read(Links {
                executable: PathBuf::from(OsString::from_vec(bytes)),
                deleted,
                namespaces,
            }))
        }
        TAG_HOST => Ok(Answer::Host(Namespaces {
            pid: answer.u64()?,
            mnt: answer.u64()?,
        })),
        tag @ (TAG_GONE | TAG_UNREADABLE) => {
            let why = String::from_utf8(answer.bytes(MAX_REASON_BYTES)?)
                .map_err(|_| "its reason isn't UTF-8".to_owned())?;
            Ok(Answer::Error(if tag == TAG_GONE {
                ReadError::Gone(why)
            } else {
                ReadError::Unreadable(why)
            }))
        }
        other => Err(format!("its answer has an unknown tag {other}")),
    }
}

/// Reads an answer's fields, each a short read or a deadline missed an error.
struct Reader<'a>(&'a mut UnixStream);

impl Reader<'_> {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), String> {
        self.0.read_exact(buf).map_err(|e| match e.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                "no answer within its deadline".to_owned()
            }
            std::io::ErrorKind::UnexpectedEof => "it has ended".to_owned(),
            _ => format!("reading its answer: {e}"),
        })
    }
    fn u8(&mut self) -> Result<u8, String> {
        let mut b = [0u8; 1];
        self.fill(&mut b)?;
        let [value] = b;
        Ok(value)
    }
    fn u64(&mut self) -> Result<u64, String> {
        let mut b = [0u8; 8];
        self.fill(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn bytes(&mut self, most: usize) -> Result<Vec<u8>, String> {
        let mut b = [0u8; 2];
        self.fill(&mut b)?;
        let length = usize::from(u16::from_le_bytes(b));
        if length > most {
            return Err(format!("its answer holds {length} bytes, more than {most}"));
        }
        let mut out = vec![0u8; length];
        self.fill(&mut out)?;
        Ok(out)
    }
}

impl ReadLinks for Helper {
    fn links(&self, pid: u32) -> Result<Links, ReadError> {
        if pid == HOST {
            return Err(ReadError::Gone("pid 0: no such process".to_owned()));
        }
        match self.ask(pid)? {
            Answer::Read(links) => Ok(links),
            Answer::Error(e) => Err(e),
            Answer::Host(_) => Err(self.broken("a host answer to a process request")),
        }
    }

    fn host_namespaces(&self) -> Result<Namespaces, ReadError> {
        match self.ask(HOST)? {
            Answer::Host(host) => Ok(host),
            Answer::Error(e) => Err(e),
            Answer::Read(_) => Err(self.broken("a process answer to the host request")),
        }
    }
}

/// The daemon's read of a process through the helper: `stat` and the pidfd here, the links
/// there.
impl ReadProcess for Helper {
    fn read(&self, pid: u32) -> Result<Entry, ReadError> {
        read_with(self, pid)
    }

    fn host(&self) -> Result<Namespaces, ReadError> {
        self.host_namespaces()
    }
}

impl Helper {
    /// An answer that doesn't fit its request: the helper isn't used again.
    fn broken(&self, what: &str) -> ReadError {
        let why = format!("the process reader can't be used any more ({what})");
        tracing::error!(error = %why, "every caller on a Unix socket is refused from now on");
        *self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = State::Ended(why.clone());
        ReadError::Unreadable(why)
    }
}
