//! End to end against a real remote (`make e2e`: Forgejo in Docker, `tool/e2e.sh`): M4's
//! acceptance with the daemon's mirrors and upstream pushes, over Forgejo's own SSH server,
//! with a deploy key the daemon holds. Ignored by `make test` (it needs Docker); the script
//! starts Forgejo, makes a user and a token, and runs it with:
//!
//! - `WRIT_E2E_FORGEJO_HTTP`: Forgejo's base URL (`http://127.0.0.1:<port>`);
//! - `WRIT_E2E_FORGEJO_SSH_PORT`: its SSH port on `127.0.0.1`;
//! - `WRIT_E2E_FORGEJO_TOKEN`: an API token of the user `writ`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::process::Command;

use base64ct::{Base64, Encoding};
use writ_crypto::keys::{KeyKind, generate};
use writ_integration::gateway::{ExternalUpstream, GitGateway, Listen, POLICY};
use writ_integration::stderr;

struct Forgejo {
    http: String,
    ssh_port: u16,
    token: String,
}

impl Forgejo {
    fn from_env() -> Self {
        let var = |name: &str| {
            std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set: run `make e2e`"))
        };
        Self {
            http: var("WRIT_E2E_FORGEJO_HTTP"),
            ssh_port: var("WRIT_E2E_FORGEJO_SSH_PORT").parse().unwrap(),
            token: var("WRIT_E2E_FORGEJO_TOKEN"),
        }
    }

    /// A call to Forgejo's API: its status and its JSON (null when there is none).
    fn api(
        &self,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> (u16, serde_json::Value) {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into();
        let url = format!("{}/api/v1{path}", self.http);
        let auth = format!("token {}", self.token);
        let mut response = match (method, body) {
            ("GET", _) => agent.get(&url).header("Authorization", &auth).call(),
            (_, Some(body)) => agent
                .post(&url)
                .header("Authorization", &auth)
                .content_type("application/json")
                .send(body.to_string().as_bytes()),
            (_, None) => agent.post(&url).header("Authorization", &auth).send_empty(),
        }
        .unwrap();
        let status = response.status().as_u16();
        let text = response.body_mut().read_to_string().unwrap_or_default();
        (
            status,
            serde_json::from_str(&text).unwrap_or(serde_json::Value::Null),
        )
    }

    /// The commit a branch of `repo` points at, as Forgejo sees it.
    fn branch(&self, repo: &str, branch: &str) -> Option<String> {
        let path = format!("/repos/writ/{repo}/branches/{}", branch.replace('/', "%2F"));
        let (status, json) = self.api("GET", &path, None);
        (status == 200).then(|| json["commit"]["id"].as_str().unwrap().to_owned())
    }
}

#[test]
#[ignore = "needs Forgejo in Docker: make e2e"]
fn pushes_and_fetches_go_through_the_daemon_to_forgejo() {
    let forgejo = Forgejo::from_env();
    let repo = format!("demo-{}", std::process::id());
    let (status, json) = forgejo.api(
        "POST",
        "/user/repos",
        Some(serde_json::json!({"name": repo, "auto_init": true, "default_branch": "main"})),
    );
    assert_eq!(status, 201, "{json}");
    // The daemon's credential: a deploy key with write access on that one repository.
    let key = generate(KeyKind::Ed25519).unwrap();
    let (status, json) = forgejo.api(
        "POST",
        &format!("/repos/writ/{repo}/keys"),
        Some(serde_json::json!({
            "title": "writ",
            "key": key.public_key().to_openssh().unwrap(),
            "read_only": false,
        })),
    );
    assert_eq!(status, 201, "{json}");
    // Forgejo's host key, pinned (here from a scan of a container this script started).
    let scan = Command::new("ssh-keyscan")
        .args([
            "-p",
            &forgejo.ssh_port.to_string(),
            "-t",
            "ed25519",
            "127.0.0.1",
        ])
        .output()
        .unwrap();
    let known_hosts = String::from_utf8(scan.stdout).unwrap();
    assert!(known_hosts.contains("ssh-ed25519"), "{known_hosts}");
    let gateway = GitGateway::start_against(
        KeyKind::Ed25519,
        Listen::Tcp,
        POLICY,
        Some(ExternalUpstream {
            url: format!("ssh://git@127.0.0.1:{}/writ/{repo}.git", forgejo.ssh_port),
            known_hosts,
            key,
        }),
    );

    // A clone through the daemon: Forgejo's main (its initial commit).
    let work = gateway.clone("work");
    let main = forgejo.branch(&repo, "main").unwrap();
    assert_eq!(gateway.git_ok(&work, &["rev-parse", "HEAD"]).trim(), main);

    // A signed commit pushed: on Forgejo, as signed.
    let first = gateway.commit_signed(&work, "f", "1\n");
    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/x"]);
    assert_eq!(
        forgejo.branch(&repo, "agent/x").as_deref(),
        Some(first.as_str())
    );

    // A protected ref: refused, nothing on Forgejo.
    let out = gateway.git(&work, &["push", "origin", "HEAD:refs/heads/main"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(
        forgejo.branch(&repo, "main").as_deref(),
        Some(main.as_str())
    );

    // Upstream moves (someone commits on the branch on Forgejo): the agent's next push is
    // rejected, and nothing of it reaches the mirror or Forgejo.
    let (status, json) = forgejo.api(
        "POST",
        &format!("/repos/writ/{repo}/contents/theirs.txt"),
        Some(serde_json::json!({
            "branch": "agent/x",
            "message": "theirs",
            "content": Base64::encode_string(b"theirs\n"),
        })),
    );
    assert_eq!(status, 201, "{json}");
    let moved = forgejo.branch(&repo, "agent/x").unwrap();
    let second = gateway.commit_signed(&work, "g", "2\n");
    let out = gateway.git(&work, &["push", "origin", "HEAD:refs/heads/agent/x"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("rejected"), "{}", stderr(&out));
    assert_eq!(
        forgejo.branch(&repo, "agent/x").as_deref(),
        Some(moved.as_str())
    );
    assert_ne!(
        gateway.bare_ref("refs/heads/agent/x").as_deref(),
        Some(second.as_str())
    );

    // Fetch through the daemon, rebase, sign again, push again: on Forgejo.
    gateway.git_ok(&work, &["fetch", "-q", "origin"]);
    gateway.git_ok(&work, &["rebase", "-q", "origin/agent/x"]);
    let trailer = format!("Writ: {}", gateway.lease);
    gateway.git_ok(
        &work,
        &[
            "commit",
            "-q",
            "-S",
            "--amend",
            "--no-edit",
            "--trailer",
            &trailer,
        ],
    );
    let rebased = gateway
        .git_ok(&work, &["rev-parse", "HEAD"])
        .trim()
        .to_owned();
    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/x"]);
    assert_eq!(
        forgejo.branch(&repo, "agent/x").as_deref(),
        Some(rebased.as_str())
    );
    assert_eq!(
        gateway.bare_ref("refs/heads/agent/x").as_deref(),
        Some(rebased.as_str())
    );
}
