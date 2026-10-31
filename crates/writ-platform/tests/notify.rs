//! Every notifier, real and fake, through the notifier contract, and Telegram's own
//! guarantees (the token never leaks, the exact request, validation of every setting).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use writ_platform::contract;
use writ_platform::notify::{BotToken, Notifiers, TelegramNotifier};
use writ_platform::testing::RecordingNotifier;
use writ_platform::{Notification, Notifier, PlatformError, Priority};

const TOKEN: &str = "123456789:AAH-fake_token_for_tests_0123456789";
const OK_REPLY: &str = r#"{"ok":true,"result":{"message_id":1}}"#;

fn token() -> BotToken {
    BotToken::new(TOKEN.to_owned()).unwrap()
}

/// One HTTP request as the fake Bot API server read it.
#[derive(Debug, Clone)]
struct Request {
    method: String,
    path: String,
    /// Raw header lines, request line excluded.
    headers: Vec<String>,
    body: Vec<u8>,
}

impl Request {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

/// A tiny HTTP server on 127.0.0.1 that records every request and answers `status` with
/// `body`.
struct FakeBotApi {
    base: String,
    requests: Arc<Mutex<Vec<Request>>>,
}

impl FakeBotApi {
    fn start(status: &'static str, body: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let Some(request) = read_request(&mut stream) else {
                    continue;
                };
                recorded.lock().unwrap().push(request);
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        Self {
            base: format!("http://{addr}"),
            requests,
        }
    }

    fn ok() -> Self {
        Self::start("200 OK", OK_REPLY)
    }

    fn notifier(&self, chat_id: &str) -> TelegramNotifier {
        TelegramNotifier::with_api_base(token(), chat_id, &self.base).unwrap()
    }

    fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }

    /// The messages' texts decoded back into notifications (title, blank line, message).
    fn received(&self) -> Vec<Notification> {
        self.requests()
            .iter()
            .map(|request| {
                let json = request.json();
                let text = json["text"].as_str().unwrap();
                let (title, message) = text.split_once("\n\n").unwrap();
                Notification {
                    title: title.to_owned(),
                    message: message.to_owned(),
                    priority: if json["disable_notification"] == true {
                        Priority::Low
                    } else {
                        Priority::Default
                    },
                    tags: vec![],
                }
            })
            .collect()
    }
}

fn read_request(stream: &mut std::net::TcpStream) -> Option<Request> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();
    let mut headers = Vec::new();
    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        let header = header.trim_end_matches(['\r', '\n']).to_owned();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().ok()?;
        }
        headers.push(header);
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).ok()?;
    Some(Request {
        method,
        path,
        headers,
        body,
    })
}

/// A local base URL nothing listens on.
fn closed_port_base() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("http://{addr}")
}

fn notify_error(notifier: &TelegramNotifier) -> PlatformError {
    match notifier.notify(&Notification {
        title: "Writ".to_owned(),
        message: "test".to_owned(),
        ..Notification::default()
    }) {
        Ok(()) => panic!("must fail"),
        Err(e) => e,
    }
}

fn assert_no_token(text: &str) {
    let secret = TOKEN.split_once(':').unwrap().1;
    assert!(!text.contains(secret), "the token leaked: {text}");
    let path_start = format!("/bot{}", TOKEN.split_once(':').unwrap().0);
    assert!(
        !text.contains(&path_start),
        "the request URL leaked: {text}"
    );
}

// ----- Contract -----

#[test]
fn telegram_passes_the_contract() {
    let server = FakeBotApi::ok();
    let notifier = server.notifier("-1001234567890");
    contract::notifier(&notifier, || server.received());
}

#[test]
fn telegram_with_a_server_error_passes_the_unreachable_contract() {
    let server = FakeBotApi::start("500 Internal Server Error", "");
    contract::notifier_unreachable(&server.notifier("42"), Duration::from_secs(11));
    assert_eq!(server.requests().len(), 2, "the server was reached");
}

#[test]
fn telegram_refusing_the_message_passes_the_unreachable_contract() {
    let server = FakeBotApi::start(
        "200 OK",
        r#"{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}"#,
    );
    contract::notifier_unreachable(&server.notifier("42"), Duration::from_secs(11));
}

#[test]
fn telegram_with_a_closed_port_passes_the_unreachable_contract() {
    let notifier = TelegramNotifier::with_api_base(token(), "42", &closed_port_base()).unwrap();
    contract::notifier_unreachable(&notifier, Duration::from_secs(11));
}

#[test]
fn recording_notifier_passes_the_contract() {
    let notifier = RecordingNotifier::new();
    contract::notifier(&notifier, || notifier.notifications());
}

#[test]
fn failing_recording_notifier_passes_the_unreachable_contract() {
    let notifier = RecordingNotifier::failing();
    contract::notifier_unreachable(&notifier, Duration::from_secs(1));
    assert!(notifier.notifications().is_empty());
}

#[test]
fn notifiers_pass_the_contract() {
    let first = RecordingNotifier::new();
    let second = RecordingNotifier::new();
    let all = Notifiers(vec![Arc::new(first.clone()), Arc::new(second.clone())]);
    contract::notifier(&all, || second.notifications());
    assert_eq!(first.notifications(), second.notifications());
}

#[test]
fn notifiers_deliver_to_every_one_and_return_the_first_error() {
    let delivered = RecordingNotifier::new();
    let all = Notifiers(vec![
        Arc::new(RecordingNotifier::failing()),
        Arc::new(delivered.clone()),
        Arc::new(TelegramNotifier::with_api_base(token(), "42", &closed_port_base()).unwrap()),
    ]);
    let result = all.notify(&Notification {
        title: "t".to_owned(),
        ..Notification::default()
    });
    match result {
        Err(PlatformError::Notify(why)) => assert!(why.contains("recording"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(delivered.notifications().len(), 1);
}

#[test]
fn an_empty_notifier_list_succeeds() {
    assert!(
        Notifiers::default()
            .notify(&Notification::default())
            .is_ok()
    );
}

// ----- The request -----

#[test]
fn telegram_posts_send_message_with_the_exact_body() {
    let server = FakeBotApi::ok();
    server
        .notifier("-1001234567890")
        .notify(&Notification {
            title: "Ticket waiting".to_owned(),
            message: "wrt_01JD8X: fix the login bug\nrepo example/app".to_owned(),
            priority: Priority::High,
            tags: vec!["writ".to_owned()],
        })
        .unwrap();
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, format!("/bot{TOKEN}/sendMessage"));
    assert!(
        request
            .headers
            .iter()
            .any(|h| h.eq_ignore_ascii_case("content-type: application/json")),
        "{:?}",
        request.headers
    );
    assert_eq!(
        request.json(),
        serde_json::json!({
            "chat_id": -1001234567890_i64,
            "text": "Ticket waiting\n\nwrt_01JD8X: fix the login bug\nrepo example/app",
            "disable_web_page_preview": true,
            "disable_notification": false,
        })
    );
    assert!(
        request.json().get("parse_mode").is_none(),
        "plain text only"
    );
}

#[test]
fn channel_chat_ids_are_strings_and_low_priority_is_silent() {
    let server = FakeBotApi::ok();
    let notifier = server.notifier("@writ_alerts");
    for (priority, silent) in [
        (Priority::Low, true),
        (Priority::Default, false),
        (Priority::High, false),
    ] {
        notifier
            .notify(&Notification {
                title: "t".to_owned(),
                message: "m".to_owned(),
                priority,
                tags: vec![],
            })
            .unwrap();
        let json = server.requests().last().unwrap().json();
        assert_eq!(
            json,
            serde_json::json!({
                "chat_id": "@writ_alerts",
                "text": "t\n\nm",
                "disable_web_page_preview": true,
                "disable_notification": silent,
            })
        );
    }
}

#[test]
fn injected_characters_are_neutralized() {
    let server = FakeBotApi::ok();
    server
        .notifier("42")
        .notify(&Notification {
            title:
                "innocent\"\r\nX-Injected: 1\r\n\r\n\u{1b}[2J\u{1b}]0;pwned\u{7}\u{202E}lmth.exe"
                    .to_owned(),
            message: "body\r\nX-Injected: 2\u{1b}[31m\u{200B}*bold* <b>html</b>".to_owned(),
            priority: Priority::Default,
            tags: vec![],
        })
        .unwrap();
    let request = &server.requests()[0];
    assert!(
        !request.headers.iter().any(|h| {
            h.to_ascii_lowercase().starts_with("x-injected")
                || h.contains("innocent")
                || h.contains("pwned")
        }),
        "{:?}",
        request.headers
    );
    assert_eq!(
        request.json()["text"],
        "innocent\"X-Injected: 1[2J]0;pwnedlmth.exe\n\nbody\nX-Injected: 2[31m*bold* <b>html</b>"
    );
}

#[test]
fn text_is_capped_at_4096_utf16_units() {
    let server = FakeBotApi::ok();
    // Astral characters count twice in UTF-16: 200 + 2000 of them pass Telegram's limit.
    server
        .notifier("42")
        .notify(&Notification {
            title: "😀".repeat(300),
            message: "😀".repeat(3000),
            ..Notification::default()
        })
        .unwrap();
    let json = server.requests()[0].json();
    let text = json["text"].as_str().unwrap();
    let units: usize = text.chars().map(char::len_utf16).sum();
    assert!(units <= 4096, "{units}");
    assert!(units >= 4094, "{units}");
    assert!(text.starts_with(&"😀".repeat(200)));
    assert!(text.contains("\n\n"));
}

#[test]
fn bidi_and_zero_width_characters_are_removed() {
    let notification = Notification {
        title: "a\u{202E}b\u{2066}c\u{2069}d\u{200B}e\u{200F}f\u{2060}g\u{FEFF}h".to_owned(),
        message: "x\u{202A}y\n\u{200D}z".to_owned(),
        ..Notification::default()
    }
    .neutralized();
    assert_eq!(notification.title, "abcdefgh");
    assert_eq!(notification.message, "xy\nz");
}

#[test]
fn caps_count_characters_not_bytes() {
    let notification = Notification {
        title: "é".repeat(300),
        message: "✓".repeat(3000),
        ..Notification::default()
    }
    .neutralized();
    assert_eq!(notification.title.chars().count(), 200);
    assert_eq!(notification.message.chars().count(), 2000);
}

// ----- Errors and the token -----

#[test]
fn errors_and_debug_never_contain_the_token() {
    let unreachable = TelegramNotifier::with_api_base(token(), "42", &closed_port_base()).unwrap();
    let unauthorized = FakeBotApi::start(
        "401 Unauthorized",
        r#"{"ok":false,"error_code":401,"description":"Unauthorized"}"#,
    );
    // A server echoing the token back in its description.
    let refused = FakeBotApi::start(
        "200 OK",
        r#"{"ok":false,"error_code":400,"description":"Bad Request: bot123456789:AAH-fake_token_for_tests_0123456789 \u001b[31mcan't send"}"#,
    );

    let cases = [
        (unreachable, "cannot reach the Telegram Bot API"),
        (unauthorized.notifier("42"), "HTTP 401: Unauthorized"),
        (refused.notifier("42"), "refused the message: Bad Request"),
    ];
    for (notifier, expected) in &cases {
        let error = notify_error(notifier);
        assert!(matches!(error, PlatformError::Notify(_)), "{error:?}");
        let display = error.to_string();
        assert!(display.contains(expected), "{display}");
        assert_no_token(&display);
        assert_no_token(&format!("{error:?}"));
        assert!(!display.contains('\u{1b}'), "{display}");
        assert_no_token(&format!("{notifier:?}"));
    }
    assert_eq!(format!("{:?}", token()), "BotToken(<redacted>)");
}

#[test]
fn an_unreachable_server_is_described_in_short_words() {
    let base = closed_port_base();
    let notifier = TelegramNotifier::with_api_base(token(), "42", &base).unwrap();
    let error = notify_error(&notifier).to_string();
    assert_eq!(
        error,
        format!(
            "notification failed: cannot reach the Telegram Bot API at {base}: connection refused"
        )
    );
}

#[test]
fn an_unexpected_reply_fails() {
    let server = FakeBotApi::start("200 OK", "<html>not json</html>");
    let error = notify_error(&server.notifier("42")).to_string();
    assert!(error.contains("unexpected reply"), "{error}");
}

#[test]
fn redirects_are_not_followed() {
    let server = FakeBotApi::start("302 Found", "");
    let error = notify_error(&server.notifier("42"));
    assert!(error.to_string().contains("HTTP 302"), "{error}");
    assert_eq!(server.requests().len(), 1);
}

// ----- Validation -----

#[test]
fn bot_tokens_are_validated_without_echoing_them() {
    for good in [
        TOKEN,
        "1:abcdefghijklmnopqrst",
        "987654321:ABCDEFGHIJKLMNOPQRSTUVWXYZ_-0123456789",
    ] {
        assert!(BotToken::new(good.to_owned()).is_ok(), "{good}");
    }
    for bad in [
        "",
        ":abcdefghijklmnopqrstuvwxyz",
        "123456789",
        "123456789:",
        "123456789:short_secret_19char",
        "12a456789:abcdefghijklmnopqrstuvwxyz",
        "123456789:abcdefghijklmnopqrstuvwxyz!",
        "123456789:abcdefghij klmnopqrstuvwxyz",
        " 123456789:abcdefghijklmnopqrstuvwxyz",
        "123456789:abcdefghijklmnopqrstuvwxyz\n",
        "123:456:abcdefghijklmnopqrstuvwxyz",
    ] {
        match BotToken::new(bad.to_owned()) {
            Err(PlatformError::Config(why)) => {
                if !bad.is_empty() {
                    assert!(!why.contains(bad.trim()), "{why}");
                }
            }
            other => panic!("{bad:?} must be refused, got {other:?}"),
        }
    }
    let long = format!("1:{}", "a".repeat(300));
    assert!(BotToken::new(long).is_err());
}

#[cfg(unix)]
fn write_mode(path: &Path, contents: &str, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::remove_file(path);
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(unix)]
#[test]
fn bot_token_files_must_be_private() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("telegram-token");

    write_mode(&path, &format!("  {TOKEN}\n"), 0o600);
    let from_file = BotToken::from_file(&path).unwrap();
    let server = FakeBotApi::ok();
    TelegramNotifier::with_api_base(from_file, "42", &server.base)
        .unwrap()
        .notify(&Notification::default())
        .unwrap();
    assert_eq!(
        server.requests()[0].path,
        format!("/bot{TOKEN}/sendMessage")
    );

    write_mode(&path, TOKEN, 0o400);
    assert!(BotToken::from_file(&path).is_ok());

    for mode in [0o640, 0o604, 0o620, 0o602, 0o644, 0o660, 0o666] {
        write_mode(&path, TOKEN, mode);
        match BotToken::from_file(&path) {
            Err(PlatformError::Config(why)) => {
                assert!(why.contains(&path.display().to_string()), "{why}");
                assert_no_token(&why);
            }
            other => panic!("mode {mode:o} must be refused, got {other:?}"),
        }
    }
}

#[cfg(unix)]
#[test]
fn bad_bot_token_files_fail_without_echoing_them() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("telegram-token");
    for contents in [
        "",
        "not a token",
        "123456789:AAH-fake_token_for_tests_0123456789\nsecond line",
    ] {
        write_mode(&path, contents, 0o600);
        match BotToken::from_file(&path) {
            Err(PlatformError::Config(why)) => {
                assert!(why.contains(&path.display().to_string()), "{why}");
                assert_no_token(&why);
                assert!(!why.contains("not a token"), "{why}");
            }
            other => panic!("{contents:?} must be refused, got {other:?}"),
        }
    }
    write_mode(&path, &"a".repeat(10_000), 0o600);
    assert!(BotToken::from_file(&path).is_err());
    let missing = BotToken::from_file(&dir.path().join("absent"));
    assert!(
        matches!(missing, Err(PlatformError::Config(_))),
        "{missing:?}"
    );
}

#[test]
fn chat_ids_are_validated() {
    for good in [
        "42",
        "-42",
        "-1001234567890",
        "9223372036854775807",
        "@abcde",
        "@writ_alerts",
        "@ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
    ] {
        assert!(TelegramNotifier::new(token(), good).is_ok(), "{good}");
    }
    for bad in [
        "",
        "-",
        "+42",
        " 42",
        "42 ",
        "4 2",
        "1.5",
        "99999999999999999999",
        "@",
        "@abcd",
        "@ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456",
        "@writ-alerts",
        "@writ alerts",
        "writ_alerts",
        "@écrit",
    ] {
        let result = TelegramNotifier::new(token(), bad);
        assert!(
            matches!(result, Err(PlatformError::Config(_))),
            "{bad:?} must be refused, got {result:?}"
        );
    }
}

#[test]
fn api_bases_are_validated() {
    for good in [
        "https://api.telegram.org",
        "https://api.telegram.org/",
        "http://127.0.0.1:8081",
        "http://[::1]:8081",
        "https://bot-api.home:8443",
    ] {
        assert!(
            TelegramNotifier::with_api_base(token(), "42", good).is_ok(),
            "{good}"
        );
    }
    for bad in [
        "",
        "api.telegram.org",
        "ftp://api.telegram.org",
        "file:///tmp/api",
        "https://api.telegram.org/bot",
        "https://api.telegram.org//",
        "https://api.telegram.org?x=1",
        "https://api.telegram.org/?x=1",
        "https://api.telegram.org#frag",
        "https://user:secret@api.telegram.org",
        "https://",
        "not a url",
    ] {
        let result = TelegramNotifier::with_api_base(token(), "42", bad);
        assert!(
            matches!(result, Err(PlatformError::Config(_))),
            "{bad:?} must be refused, got {result:?}"
        );
    }
    let debug = format!(
        "{:?}",
        TelegramNotifier::with_api_base(token(), "@writ_alerts", "https://bot-api.home:8443/")
            .unwrap()
    );
    assert!(debug.contains("https://bot-api.home:8443\""), "{debug}");
    assert!(debug.contains("@writ_alerts"), "{debug}");
    assert_no_token(&debug);
}
