//! A kqueue watching processes end (`EVFILT_PROC` with `NOTE_EXIT`), and a user event to
//! wake its waiting thread (`EVFILT_USER`).

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// The user event's identifier: the only one this kqueue has.
const WAKE: usize = 0;

/// What a wait returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The process with this pid ended.
    Exited(u32),
    /// [`Kqueue::wake`] was called.
    Woken,
}

/// A kqueue, closed when dropped.
#[derive(Debug)]
pub struct Kqueue(OwnedFd);

/// One change or event (`struct kevent`), all fields set.
fn kevent(ident: usize, filter: i16, flags: u16, fflags: u32) -> libc::kevent {
    libc::kevent {
        ident,
        filter,
        flags,
        fflags,
        data: 0,
        udata: std::ptr::null_mut(),
    }
}

impl Kqueue {
    /// A new kqueue, with its wake-up event registered.
    pub fn new() -> io::Result<Self> {
        // SAFETY: `kqueue` takes no argument; it returns a new descriptor or -1.
        let fd = unsafe { libc::kqueue() };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just returned by `kqueue` and is owned by nothing else.
        let queue = Self(unsafe { OwnedFd::from_raw_fd(fd) });
        queue.change(kevent(
            WAKE,
            libc::EVFILT_USER,
            libc::EV_ADD | libc::EV_CLEAR,
            0,
        ))?;
        Ok(queue)
    }

    /// Applies one change, with no event returned: an error about it (`ESRCH`: the process
    /// is gone) is the call's.
    fn change(&self, change: libc::kevent) -> io::Result<()> {
        // SAFETY: the changelist is one valid `kevent` that lives for the call; there is no
        // event list (null, 0), and no timeout (null) is needed when nothing is waited for.
        let result = unsafe {
            libc::kevent(
                self.0.as_raw_fd(),
                &raw const change,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Asks for one [`Event::Exited`] when `pid` ends. `ESRCH` (`NotFound`): it already has.
    /// Watching a pid already watched keeps one watch.
    pub fn watch_exit(&self, pid: u32) -> io::Result<()> {
        let ident = usize::try_from(pid).map_err(|_| io::Error::other("pid out of range"))?;
        self.change(kevent(
            ident,
            libc::EVFILT_PROC,
            libc::EV_ADD | libc::EV_ONESHOT,
            libc::NOTE_EXIT,
        ))
        .map_err(|e| match e.raw_os_error() {
            Some(libc::ESRCH) => io::Error::new(io::ErrorKind::NotFound, "no such process"),
            _ => e,
        })
    }

    /// Stops watching `pid` (nothing if it wasn't, or has ended).
    pub fn unwatch(&self, pid: u32) {
        if let Ok(ident) = usize::try_from(pid) {
            let _ = self.change(kevent(ident, libc::EVFILT_PROC, libc::EV_DELETE, 0));
        }
    }

    /// Wakes the thread waiting in [`Kqueue::wait`].
    pub fn wake(&self) -> io::Result<()> {
        self.change(kevent(WAKE, libc::EVFILT_USER, 0, libc::NOTE_TRIGGER))
    }

    /// Waits for the next events, as many as come together (at most 32).
    pub fn wait(&self) -> io::Result<Vec<Event>> {
        let mut events = [kevent(0, 0, 0, 0); 32];
        let capacity =
            libc::c_int::try_from(events.len()).map_err(|_| io::Error::other("event count"))?;
        // SAFETY: no changelist (null, 0); the event list is valid and writable for
        // `capacity` events; no timeout (null): it blocks until an event comes.
        let count = unsafe {
            libc::kevent(
                self.0.as_raw_fd(),
                std::ptr::null(),
                0,
                events.as_mut_ptr(),
                capacity,
                std::ptr::null(),
            )
        };
        let count = match usize::try_from(count) {
            Ok(count) => count,
            Err(_) => {
                let error = io::Error::last_os_error();
                // A signal: no event this time.
                return match error.kind() {
                    io::ErrorKind::Interrupted => Ok(Vec::new()),
                    _ => Err(error),
                };
            }
        };
        Ok(events
            .iter()
            .take(count)
            .filter_map(|event| match event.filter {
                libc::EVFILT_USER => Some(Event::Woken),
                libc::EVFILT_PROC if event.fflags & libc::NOTE_EXIT != 0 => {
                    u32::try_from(event.ident).ok().map(Event::Exited)
                }
                _ => None,
            })
            .collect())
    }
}
