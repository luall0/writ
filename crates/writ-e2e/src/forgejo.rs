//! Forgejo, the remote of every scenario: its API (repositories, deploy keys, branch
//! protection, commits and their verification) with the admin user's token, and the web forms
//! it has no API for (proving an SSH signing key: a challenge signed in namespace `gitea`).
//! Changes made on the remote by someone else than the agents are a second account's, the
//! [`CONTRIBUTOR`], a collaborator with write access on every repository: through the API
//! ([`Forgejo::commit_file`]) and with plain git over HTTP ([`Forgejo::contributor_url`]).
//!
//! Its state is what a scenario checks besides what the agent reads: a branch on Forgejo is
//! where a push landed, or proof that a refused one didn't.

use std::collections::BTreeMap;
use std::time::Duration;

use base64ct::{Base64, Encoding};
use serde_json::{Value, json};

use crate::docker::{Container, eventually, stderr, stdout};

/// Forgejo on the project's network.
pub const BASE: &str = "http://forgejo:3000";

/// The account that owns the scenarios' repositories (an admin, made at setup).
pub const OWNER: &str = "writ";

/// The account's email: the committer email the templates allow, so a commit signed by a key
/// registered and proven on the account shows as verified.
pub const EMAIL: &str = "agent@writ.invalid";

/// Another person working on the same repositories, straight on Forgejo, without Writ.
pub const CONTRIBUTOR: &str = "contributor";

/// Forgejo's container, and the admin user's credentials.
pub struct Forgejo {
    pub container: Container,
    pub token: String,
    pub password: String,
    /// The [`CONTRIBUTOR`]'s token.
    pub contributor_token: String,
}

fn agent(redirects: bool) -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(if redirects { 10 } else { 0 })
        .timeout_global(Some(Duration::from_secs(60)));
    config.build().into()
}

/// Waits for Forgejo's API to answer (it gives no other signal), up to 3 minutes.
pub fn wait_ready() {
    eventually("Forgejo's API", Duration::from_secs(180), || {
        agent(true)
            .get(&format!("{BASE}/api/v1/version"))
            .call()
            .is_ok_and(|r| r.status() == 200)
    });
}

impl Forgejo {
    /// Makes the admin user (it owns the repositories) and the contributor, and their tokens
    /// (Forgejo's own CLI, in its container).
    pub fn create_accounts() -> Self {
        let container = Container::of("forgejo");
        wait_ready();
        let password = "writ-e2e-admin-password".to_owned();
        let token = user(&container, OWNER, EMAIL, &password, true);
        let contributor_token = user(
            &container,
            CONTRIBUTOR,
            "contributor@writ.invalid",
            "writ-e2e-contributor-password",
            false,
        );
        Self {
            container,
            token,
            password,
            contributor_token,
        }
    }

    /// A call to the API as the owner: its status and its JSON (null when there is none).
    pub fn api(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        api_as(&self.token, method, path, body)
    }

    /// The same, which must answer `expected`, as the contributor.
    pub fn contributor_api_ok(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        expected: u16,
    ) -> Value {
        let (status, json) = api_as(&self.contributor_token, method, path, body);
        assert_eq!(status, expected, "{CONTRIBUTOR}: {method} {path}: {json}");
        json
    }

    /// The URL the contributor's plain git pushes to over HTTP (its token in it).
    pub fn contributor_url(&self, repo: &str) -> String {
        format!(
            "{}/{OWNER}/{repo}.git",
            BASE.replace(
                "http://",
                &format!("http://{CONTRIBUTOR}:{}@", self.contributor_token)
            )
        )
    }
}

impl Forgejo {
    /// A new token of the owner's for repositories only (`write:repository`): what an
    /// operator makes for the daemon's HTTPS upstream.
    pub fn repository_token(&self, name: &str) -> String {
        let out = self.container.run_as(
            "git",
            &format!(
                "forgejo admin user generate-access-token --username {OWNER} --token-name {name} \
                 --scopes write:repository --raw"
            ),
        );
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let token = stdout(&out)
            .lines()
            .last()
            .unwrap_or_default()
            .trim()
            .to_owned();
        assert_eq!(token.len(), 40, "a token: {token:?}");
        token
    }
}

/// Makes a user and its token.
fn user(container: &Container, name: &str, email: &str, password: &str, admin: bool) -> String {
    let admin = if admin { "--admin " } else { "" };
    let out = container.run_as(
        "git",
        &format!(
            "forgejo admin user create {admin}--username {name} --password '{password}' \
             --email {email} --must-change-password=false"
        ),
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}{}",
        stdout(&out),
        stderr(&out)
    );
    let out = container.run_as(
        "git",
        &format!(
            "forgejo admin user generate-access-token --username {name} --token-name e2e \
             --scopes all --raw"
        ),
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let token = stdout(&out)
        .lines()
        .last()
        .unwrap_or_default()
        .trim()
        .to_owned();
    assert_eq!(token.len(), 40, "a token: {token:?}");
    token
}

/// A call to the API with `token`: its status and its JSON (null when there is none).
fn api_as(token: &str, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
    {
        let url = format!("{BASE}/api/v1{path}");
        let auth = format!("token {token}");
        let agent = agent(true);
        let response = match (method, body) {
            ("GET", _) => agent.get(&url).header("Authorization", &auth).call(),
            ("DELETE", _) => agent.delete(&url).header("Authorization", &auth).call(),
            ("POST", Some(body)) => agent
                .post(&url)
                .header("Authorization", &auth)
                .content_type("application/json")
                .send(body.to_string().as_bytes()),
            ("PUT", Some(body)) => agent
                .put(&url)
                .header("Authorization", &auth)
                .content_type("application/json")
                .send(body.to_string().as_bytes()),
            (method, _) => panic!("no {method} with this body"),
        };
        let mut response = response.unwrap_or_else(|e| panic!("{method} {path}: {e}"));
        let status = response.status().as_u16();
        let text = response.body_mut().read_to_string().unwrap_or_default();
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }
}

impl Forgejo {
    /// A call that must answer `expected`.
    pub fn api_ok(&self, method: &str, path: &str, body: Option<Value>, expected: u16) -> Value {
        let (status, json) = self.api(method, path, body);
        assert_eq!(status, expected, "{method} {path}: {json}");
        json
    }

    /// A repository with a README on `main`, owned by [`OWNER`].
    pub fn create_repo(&self, name: &str) {
        self.api_ok(
            "POST",
            "/user/repos",
            Some(json!({"name": name, "auto_init": true, "default_branch": "main"})),
            201,
        );
        self.api_ok(
            "PUT",
            &format!("/repos/{OWNER}/{name}/collaborators/{CONTRIBUTOR}"),
            Some(json!({"permission": "write"})),
            204,
        );
    }

    /// Adds `key` (OpenSSH text) to `repo` as a deploy key with write access; its id.
    pub fn add_deploy_key(&self, repo: &str, key: &str) -> u64 {
        let json = self.api_ok(
            "POST",
            &format!("/repos/{OWNER}/{repo}/keys"),
            Some(json!({"title": "writd", "key": key, "read_only": false})),
            201,
        );
        json["id"].as_u64().unwrap()
    }

    /// The deploy keys of `repo`: their ids.
    pub fn deploy_keys(&self, repo: &str) -> Vec<u64> {
        let json = self.api_ok("GET", &format!("/repos/{OWNER}/{repo}/keys"), None, 200);
        json.as_array()
            .unwrap()
            .iter()
            .map(|k| k["id"].as_u64().unwrap())
            .collect()
    }

    /// The commit a branch of `repo` points at, as Forgejo sees it.
    pub fn branch(&self, repo: &str, branch: &str) -> Option<String> {
        let path = format!(
            "/repos/{OWNER}/{repo}/branches/{}",
            branch.replace('/', "%2F")
        );
        let (status, json) = self.api("GET", &path, None);
        (status == 200).then(|| json["commit"]["id"].as_str().unwrap().to_owned())
    }

    /// Every branch of `repo` and the commit it points at, by name.
    pub fn branches(&self, repo: &str) -> std::collections::BTreeMap<String, String> {
        let mut all = std::collections::BTreeMap::new();
        for page in 1.. {
            let json = self.api_ok(
                "GET",
                &format!("/repos/{OWNER}/{repo}/branches?limit=50&page={page}"),
                None,
                200,
            );
            let branches = json.as_array().unwrap();
            if branches.is_empty() {
                break;
            }
            for b in branches {
                all.insert(
                    b["name"].as_str().unwrap().to_owned(),
                    b["commit"]["id"].as_str().unwrap().to_owned(),
                );
            }
        }
        all
    }

    /// The contributor makes a new branch `name` of `repo`, where `from` is.
    pub fn create_branch(&self, repo: &str, name: &str, from: &str) {
        self.contributor_api_ok(
            "POST",
            &format!("/repos/{OWNER}/{repo}/branches"),
            Some(json!({"new_branch_name": name, "old_branch_name": from})),
            201,
        );
    }

    /// The contributor writes `path` on `branch` through the API, straight on Forgejo: the
    /// new commit. A write Forgejo loses to a concurrent one on the same branch (its "cannot
    /// lock ref", a stale file version) is tried again, as a person would, a bounded number
    /// of times.
    pub fn commit_file(&self, repo: &str, branch: &str, path: &str, content: &str) -> String {
        let route = format!("/repos/{OWNER}/{repo}/contents/{path}");
        let encoded = Base64::encode_string(content.as_bytes());
        let token = &self.contributor_token;
        let mut last = (0, Value::Null);
        for _ in 0..10 {
            let (status, existing) = api_as(token, "GET", &format!("{route}?ref={branch}"), None);
            let message = format!("theirs: {path}");
            let (code, json) = if status == 200 {
                let sha = existing["sha"].as_str().unwrap();
                let body =
                    json!({"branch": branch, "message": message, "content": encoded, "sha": sha});
                api_as(token, "PUT", &route, Some(body))
            } else {
                let body = json!({"branch": branch, "message": message, "content": encoded});
                api_as(token, "POST", &route, Some(body))
            };
            if code == 200 || code == 201 {
                return json["commit"]["sha"].as_str().unwrap().to_owned();
            }
            // Lost to a concurrent write: a conflict, a stale version, or Forgejo's own
            // failure to lock the ref (a 500, sometimes with no message). Anything else (a
            // refused token, a missing branch) fails at once.
            assert!(
                matches!(code, 409 | 422 | 500),
                "{CONTRIBUTOR}: writing {path} on {branch}: {code} {json}"
            );
            last = (code, json);
        }
        let (code, json) = last;
        panic!("{CONTRIBUTOR}: writing {path} on {branch} lost every race: {code} {json}");
    }

    /// A branch protection rule on `repo` that refuses every push to `pattern`.
    pub fn protect(&self, repo: &str, pattern: &str) {
        self.api_ok(
            "POST",
            &format!("/repos/{OWNER}/{repo}/branch_protections"),
            Some(json!({"rule_name": pattern, "enable_push": false})),
            201,
        );
    }

    /// Whether Forgejo shows `sha` in `repo` as verified, and its whole verification.
    pub fn verification(&self, repo: &str, sha: &str) -> (bool, Value) {
        let json = self.api_ok(
            "GET",
            &format!("/repos/{OWNER}/{repo}/git/commits/{sha}"),
            None,
            200,
        );
        let verification = json["commit"]["verification"].clone();
        (verification["verified"] == true, verification)
    }

    /// Adds `key` (OpenSSH text) to the account (Forgejo has one kind of SSH key: it signs
    /// and authenticates). Its fingerprint, as Forgejo shows it.
    pub fn add_account_key(&self, key: &str) -> String {
        let json = self.api_ok(
            "POST",
            "/user/keys",
            Some(json!({"title": "writ agent signing key", "key": key})),
            201,
        );
        json["fingerprint"].as_str().unwrap().to_owned()
    }

    /// Logs in through the web form: the session's cookies.
    fn login(&self) -> Cookies {
        let mut cookies = Cookies::default();
        let page = cookies.get(&format!("{BASE}/user/login"));
        let status = cookies.post(
            &format!("{BASE}/user/login"),
            &[
                ("_csrf", &csrf(&page)),
                ("user_name", OWNER),
                ("password", &self.password),
            ],
        );
        assert_eq!(status, 303, "the login form answered {status}");
        cookies
    }

    /// Proves the account's key `fingerprint` (no API: the settings page, as a person would).
    /// The page shows a 64-hex challenge; `sign` signs it (namespace `gitea`) and returns the
    /// armored signature. Returns the challenge the page showed.
    pub fn prove_key(&self, fingerprint: &str, sign: impl FnOnce(&str) -> String) -> String {
        let mut cookies = self.login();
        // The fingerprint URL-escaped: a `+` left as is shows no challenge.
        let escaped: String = fingerprint
            .bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => {
                    char::from(b).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect();
        let page = cookies.get(&format!("{BASE}/user/settings/keys?verify_ssh={escaped}"));
        let token = page
            .split("echo -n &#39;")
            .nth(1)
            .or_else(|| page.split("echo -n '").nth(1))
            .and_then(|rest| rest.get(..64))
            .unwrap_or_else(|| panic!("no challenge on the page for {fingerprint}"))
            .to_owned();
        assert!(token.bytes().all(|b| b.is_ascii_hexdigit()), "{token:?}");
        let signature = sign(&token);
        let status = cookies.post(
            &format!("{BASE}/user/settings/keys"),
            &[
                ("_csrf", &csrf(&page)),
                ("title", "none"),
                ("content", "none"),
                ("type", "verify_ssh"),
                ("fingerprint", fingerprint),
                ("signature", &signature),
            ],
        );
        assert_eq!(status, 303, "the verify form answered {status}");
        token
    }

    /// Forgejo's own record of its SSH host key (what a remote publishes): the public key
    /// file in its container, as `<type> <base64>`.
    pub fn published_host_key(&self) -> String {
        let out = self
            .container
            .run_as("root", "cat /data/ssh/ssh_host_ed25519_key.pub");
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let text = stdout(&out);
        let mut words = text.split_whitespace();
        format!("{} {}", words.next().unwrap(), words.next().unwrap())
    }
}

/// The CSRF token of a Forgejo page's form.
fn csrf(page: &str) -> String {
    page.split("name=\"_csrf\" value=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_else(|| panic!("no CSRF token on the page"))
        .to_owned()
}

/// A browser's cookies, for the web forms (redirects not followed: a form answers 303).
#[derive(Default)]
struct Cookies(BTreeMap<String, String>);

impl Cookies {
    fn header(&self) -> String {
        self.0
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn keep(&mut self, response: &ureq::http::Response<ureq::Body>) {
        for value in response.headers().get_all("set-cookie") {
            let Ok(value) = value.to_str() else { continue };
            let pair = value.split(';').next().unwrap_or_default();
            if let Some((name, value)) = pair.split_once('=') {
                self.0
                    .insert(name.trim().to_owned(), value.trim().to_owned());
            }
        }
    }

    fn get(&mut self, url: &str) -> String {
        let mut response = agent(false)
            .get(url)
            .header("Cookie", &self.header())
            .call()
            .unwrap();
        self.keep(&response);
        assert_eq!(response.status(), 200, "GET {url}");
        response.body_mut().read_to_string().unwrap()
    }

    fn post(&mut self, url: &str, form: &[(&str, &str)]) -> u16 {
        let response = agent(false)
            .post(url)
            .header("Cookie", &self.header())
            .send_form(form.iter().copied())
            .unwrap();
        self.keep(&response);
        response.status().as_u16()
    }
}
