//! `writd upstream-tunnel <socket> <host> <port>`: the `ProxyCommand` ssh runs for an `ssh://`
//! upstream behind a proxy of the policy (M7.2). It asks the operation's own SOCKS5 socket
//! ([`proxy`](crate::proxy), served by the daemon for this operation alone) for a tunnel to
//! `host` and `port`, by name, then relays ssh's stream through it: stdin to the tunnel, the
//! tunnel to stdout. The daemon's side checks the destination is the registry's upstream,
//! reaches it through the repo's proxy and counts what upstream sends; this program only
//! carries bytes. It runs in its own process, started by ssh (itself under the byte-capping
//! [`relay`](crate::relay)), its stderr in the daemon's captured output.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// How long the daemon's socket may take to open the tunnel: the longest `connect_timeout`
/// a proxy may have, and a margin.
pub const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(330);

/// Runs the tunnel with its arguments (after `upstream-tunnel`). Returns the exit code.
pub fn run(args: &[&str]) -> i32 {
    match tunnel(args) {
        Ok(()) => 0,
        Err(reason) => {
            eprintln!("writ: {reason}");
            1
        }
    }
}

/// The arguments, checked: an absolute socket path, a plain host, a port.
fn parse<'a>(args: &[&'a str]) -> Result<(&'a str, &'a str, u16), String> {
    let [socket, host, port] = args else {
        return Err("usage: writd upstream-tunnel <socket> <host> <port>".to_owned());
    };
    if !socket.starts_with('/') {
        return Err("the socket must be named by its absolute path".to_owned());
    }
    let plain = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_');
    if host.is_empty() || host.len() > 255 || host.starts_with('-') || !host.chars().all(plain) {
        return Err("invalid host".to_owned());
    }
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .ok_or("invalid port")?;
    Ok((socket, host, port))
}

fn tunnel(args: &[&str]) -> Result<(), String> {
    let (socket, host, port) = parse(args)?;
    let mut stream =
        UnixStream::connect(socket).map_err(|e| format!("cannot reach the daemon's proxy: {e}"))?;
    stream
        .set_read_timeout(Some(HANDSHAKE_DEADLINE))
        .map_err(|e| e.to_string())?;
    handshake(&mut stream, host, port)?;
    stream.set_read_timeout(None).map_err(|e| e.to_string())?;
    relay(stream)
}

/// SOCKS5 without authentication, `CONNECT` to `host` (as a name) on `port`.
fn handshake(stream: &mut UnixStream, host: &str, port: u16) -> Result<(), String> {
    let failed = |e: std::io::Error| format!("the daemon's proxy: {e}");
    stream.write_all(&[5, 1, 0]).map_err(failed)?;
    let mut chosen = [0u8; 2];
    stream.read_exact(&mut chosen).map_err(failed)?;
    if chosen != [5, 0] {
        return Err("the daemon's proxy took no method".to_owned());
    }
    let length = u8::try_from(host.len()).map_err(|_| "invalid host".to_owned())?;
    let mut request = vec![5, 1, 0, 3, length];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).map_err(failed)?;
    // The daemon's proxy always answers with an IPv4 address: 10 bytes.
    let mut answer = [0u8; 10];
    stream.read_exact(&mut answer).map_err(failed)?;
    match answer {
        [5, 0, ..] => Ok(()),
        [5, status, ..] => Err(format!(
            "the daemon's proxy refused the tunnel (status {status}): its reason is in the \
             daemon's error"
        )),
        _ => Err("the daemon's proxy answered something else than SOCKS5".to_owned()),
    }
}

/// ssh's stdin to the tunnel and the tunnel to ssh's stdout, until the tunnel ends.
fn relay(stream: UnixStream) -> Result<(), String> {
    let mut to_tunnel = stream.try_clone().map_err(|e| e.to_string())?;
    // stdin to the tunnel, on its own thread: when ssh closes it, the tunnel's write side is
    // shut, and upstream sees the end.
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut std::io::stdin().lock(), &mut to_tunnel);
        let _ = to_tunnel.shutdown(std::net::Shutdown::Write);
    });
    let mut from_tunnel = stream;
    let mut out = std::io::stdout().lock();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match from_tunnel.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("the tunnel failed: {e}")),
        };
        let chunk = buf.get(..n).unwrap_or_default();
        if out.write_all(chunk).and_then(|()| out.flush()).is_err() {
            // ssh hung up: nothing more to carry.
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;

    use super::*;

    #[test]
    fn the_arguments_are_checked() {
        assert!(parse(&[]).unwrap_err().starts_with("usage:"));
        assert_eq!(
            parse(&["sock", "h", "22"]).unwrap_err(),
            "the socket must be named by its absolute path"
        );
        for host in ["", "-oProxyCommand=x", "a b", "h;id", "h$x"] {
            assert_eq!(
                parse(&["/s", host, "22"]).unwrap_err(),
                "invalid host",
                "{host}"
            );
        }
        let long = "h".repeat(256);
        assert_eq!(parse(&["/s", &long, "22"]).unwrap_err(), "invalid host");
        assert!(parse(&["/s", &"h".repeat(255), "22"]).is_ok());
        for port in ["0", "65536", "x", ""] {
            assert_eq!(
                parse(&["/s", "h", port]).unwrap_err(),
                "invalid port",
                "{port}"
            );
        }
        assert_eq!(
            parse(&["/s", "abc.onion", "22"]),
            Ok(("/s", "abc.onion", 22))
        );
    }

    /// A daemon's socket answering `status` to the request, recording it.
    fn served(
        status: u8,
    ) -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::thread::JoinHandle<Vec<u8>>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.proxy");
        let listener = UnixListener::bind(&path).unwrap();
        let handle = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).unwrap();
            s.write_all(&[5, 0]).unwrap();
            let mut request = vec![0u8; 5 + 9 + 2];
            s.read_exact(&mut request).unwrap();
            s.write_all(&[5, status, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            [greeting.to_vec(), request].concat()
        });
        (dir, path, handle)
    }

    #[test]
    fn it_asks_the_daemon_s_socket_for_upstream_by_name() {
        let (_dir, path, handle) = served(0);
        let mut stream = UnixStream::connect(&path).unwrap();
        handshake(&mut stream, "abc.onion", 22).unwrap();
        let mut expected = vec![5, 1, 0, 5, 1, 0, 3, 9];
        expected.extend_from_slice(b"abc.onion");
        expected.extend_from_slice(&[0, 22]);
        assert_eq!(handle.join().unwrap(), expected);
    }

    #[test]
    fn a_refused_tunnel_says_so() {
        let (_dir, path, handle) = served(4);
        let mut stream = UnixStream::connect(&path).unwrap();
        let error = handshake(&mut stream, "abc.onion", 22).unwrap_err();
        assert!(error.contains("refused the tunnel (status 4)"), "{error}");
        handle.join().unwrap();
    }
}
