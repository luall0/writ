//! A fake Telegram Bot API on localhost: records the body of every `sendMessage`, and wakes
//! whoever waits for one.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Condvar, Mutex};

use crate::WAIT_LIMIT;

/// The bot token the fake accepts.
pub const TOKEN: &str = "123456:test-token-abcdefghijklmnopqrstuvwxyz";

/// The fake server; it runs until the test ends.
pub struct FakeTelegram {
    pub port: u16,
    received: Arc<(Mutex<Vec<String>>, Condvar)>,
}

impl FakeTelegram {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let received: Arc<(Mutex<Vec<String>>, Condvar)> = Arc::default();
        let sink = received.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                serve(stream, &sink);
            }
        });
        Self { port, received }
    }

    /// Waits for the `count`th message (woken by each one) and returns them all.
    pub fn wait_for(&self, count: usize) -> Vec<String> {
        let (messages, arrived) = &*self.received;
        let guard = messages.lock().unwrap();
        let (guard, timeout) = arrived
            .wait_timeout_while(guard, WAIT_LIMIT, |m| m.len() < count)
            .unwrap();
        assert!(
            !timeout.timed_out(),
            "{count} message(s) expected, got {}",
            guard.len()
        );
        guard.clone()
    }
}

fn serve(mut stream: std::net::TcpStream, sink: &(Mutex<Vec<String>>, Condvar)) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();
    reader.read_line(&mut request_line).unwrap();
    let mut length = 0;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).unwrap();
        if header.trim().is_empty() {
            break;
        }
        if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
            length = value.trim().parse().unwrap();
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    assert!(
        request_line.contains(&format!("/bot{TOKEN}/sendMessage")),
        "{request_line}"
    );
    let (messages, arrived) = sink;
    messages
        .lock()
        .unwrap()
        .push(String::from_utf8(body).unwrap());
    arrived.notify_all();
    let reply = r#"{"ok":true,"result":{}}"#;
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
        reply.len()
    );
}
