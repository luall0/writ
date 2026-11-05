//! A test remote standing in for GitHub, Codeberg or Forgejo: an SSH server on `127.0.0.1`,
//! port 0, serving `git-upload-pack` and `git-receive-pack` on bare repositories in a
//! directory, for one authorized key (the daemon's upstream credential). It can also
//! misbehave on demand ([`Mode`]): never answer, or send more than any fetch should take.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use russh::server::{Auth, ChannelOpenHandle, Msg, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId};
use tokio::io::AsyncWriteExt;
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::{PrivateKey, PublicKey};

/// The upstream every scenario's policy names; the harnesses rewrite it to their test remote.
pub const PLACEHOLDER_UPSTREAM: &str = "ssh://git@remote.invalid/demo.git";

/// The pin of [`PLACEHOLDER_UPSTREAM`]'s host every scenario's policy holds (a key nobody
/// has); the harnesses rewrite it to their test remote's ([`TestRemote::placed`]).
pub const PLACEHOLDER_PIN: &str = "  remote.invalid:\n    - \"ssh-ed25519 \
     AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\"";

/// An `ssh` upstream credential's declaration, as the scenarios' policies write it.
pub const SSH_CREDENTIAL: &str = "    kind: ssh\n    algorithm: ed25519";

/// How the remote answers a git command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// Runs git, like a real remote.
    Serve,
    /// Takes the command and never answers.
    Hang,
    /// Advertises refs (valid protocol lines, each a new branch) until it has sent this many
    /// bytes, then ends: git keeps reading, as from a remote with endless refs.
    Flood(usize),
    /// Says this on stderr and fails, as a hostile remote's message would.
    Say(Vec<u8>),
}

struct State {
    root: PathBuf,
    authorized: Mutex<Vec<PublicKey>>,
    mode: Mutex<Mode>,
    /// git commands run (or taken, in another mode), by name.
    upload_packs: AtomicUsize,
    receive_packs: AtomicUsize,
    /// git commands run in the repo before the next pushes are served, one per push, in
    /// order (upstream moving meanwhile).
    before_push: Mutex<std::collections::VecDeque<Vec<String>>>,
}

/// A running test remote.
pub struct TestRemote {
    pub port: u16,
    pub host_key: PrivateKey,
    state: Arc<State>,
}

impl TestRemote {
    /// Starts a remote on `runtime`, serving the bare repositories in `root`
    /// (`<root>/<name>.git`) to `authorized` only.
    pub fn start(runtime: &tokio::runtime::Runtime, root: &Path, authorized: PublicKey) -> Self {
        std::fs::create_dir_all(root).unwrap();
        let host_key = generate(KeyKind::Ed25519).unwrap();
        let state = Arc::new(State {
            root: root.to_owned(),
            authorized: Mutex::new(vec![authorized]),
            mode: Mutex::new(Mode::Serve),
            upload_packs: AtomicUsize::new(0),
            receive_packs: AtomicUsize::new(0),
            before_push: Mutex::new(std::collections::VecDeque::new()),
        });
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let config = Arc::new(russh::server::Config {
            methods: russh::MethodSet::from(&[russh::MethodKind::PublicKey][..]),
            keys: vec![host_key.clone()],
            auth_rejection_time: std::time::Duration::from_millis(10),
            auth_rejection_time_initial: Some(std::time::Duration::ZERO),
            ..Default::default()
        });
        let served = state.clone();
        runtime.spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let handler = Handler {
                    state: served.clone(),
                    channels: Vec::new(),
                    git_protocol: None,
                };
                let config = config.clone();
                tokio::spawn(async move {
                    if let Ok(session) = russh::server::run_stream(config, stream, handler).await {
                        let _ = session.await;
                    }
                });
            }
        });
        Self {
            port,
            host_key,
            state,
        }
    }

    /// The `ssh://` URL of the repository `name`.
    pub fn url(&self, name: &str) -> String {
        format!("ssh://git@127.0.0.1:{}/{name}.git", self.port)
    }

    /// `policy` (a scenario's, on the placeholder upstream) on this remote: the upstream
    /// replaced by `url`, the placeholder pin by this remote's host key.
    pub fn placed(&self, policy: &str, url: &str) -> String {
        let pin = format!(
            "  \"[127.0.0.1]:{}\":\n    - \"{}\"",
            self.port,
            self.host_key.public_key().to_openssh().unwrap()
        );
        policy
            .replace(PLACEHOLDER_UPSTREAM, url)
            .replace(PLACEHOLDER_PIN, &pin)
    }

    /// The line pinning this remote's host key in a `known_hosts` file.
    pub fn known_hosts_line(&self) -> String {
        format!(
            "[127.0.0.1]:{} {}",
            self.port,
            self.host_key.public_key().to_openssh().unwrap()
        )
    }

    /// The bare repository behind `name`.
    pub fn repo(&self, name: &str) -> PathBuf {
        self.state.root.join(format!("{name}.git"))
    }

    pub fn set_mode(&self, mode: Mode) {
        *self.state.mode.lock().unwrap() = mode;
    }

    /// Replaces the authorized key.
    pub fn authorize(&self, key: PublicKey) {
        *self.state.authorized.lock().unwrap() = vec![key];
    }

    /// Runs `git <args>` in the pushed repo right before the next push is served: upstream
    /// moving between the daemon's sync and its push. Called again before that push, it
    /// queues one more, for the push after.
    pub fn before_next_push(&self, args: &[&str]) {
        self.state
            .before_push
            .lock()
            .unwrap()
            .push_back(args.iter().map(|a| (*a).to_owned()).collect());
    }

    /// How many fetches (`git-upload-pack`) it took.
    pub fn upload_packs(&self) -> usize {
        self.state.upload_packs.load(Ordering::Acquire)
    }

    /// How many pushes (`git-receive-pack`) it took.
    pub fn receive_packs(&self) -> usize {
        self.state.receive_packs.load(Ordering::Acquire)
    }
}

struct Handler {
    state: Arc<State>,
    channels: Vec<Channel<Msg>>,
    git_protocol: Option<String>,
}

impl russh::server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        let known = self
            .state
            .authorized
            .lock()
            .unwrap()
            .iter()
            .any(|k| k.key_data() == key.public_key.key_data());
        Ok(if user == "git" && known {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.push(channel);
        reply.accept().await;
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name == "GIT_PROTOCOL" {
            self.git_protocol = Some(value.to_owned());
        }
        session.channel_success(channel)?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(index) = self.channels.iter().position(|c| c.id() == channel_id) else {
            session.channel_failure(channel_id)?;
            return Ok(());
        };
        let channel = self.channels.swap_remove(index);
        let line = String::from_utf8_lossy(data).into_owned();
        let Some((program, path)) = parse(&line) else {
            session.channel_failure(channel_id)?;
            return Ok(());
        };
        session.channel_success(channel_id)?;
        let counter = match program {
            "git-upload-pack" => &self.state.upload_packs,
            _ => &self.state.receive_packs,
        };
        counter.fetch_add(1, Ordering::AcqRel);
        let mode = self.state.mode.lock().unwrap().clone();
        let repo = self.state.root.join(path);
        if program == "git-receive-pack"
            && let Some(args) = self.state.before_push.lock().unwrap().pop_front()
        {
            let done = std::process::Command::new("git")
                .args(&args)
                .current_dir(&repo)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .status()
                .unwrap();
            assert!(done.success(), "before the push: git {args:?}");
        }
        let protocol = self.git_protocol.clone();
        let program = program.trim_start_matches("git-").to_owned();
        tokio::spawn(async move {
            match mode {
                Mode::Serve => run_git(&program, &repo, protocol, channel).await,
                Mode::Hang => {
                    // Holds the channel open and says nothing, until the client gives up.
                    let (mut rx, _tx) = channel.split();
                    while rx.wait().await.is_some() {}
                }
                Mode::Flood(bytes) => {
                    let (_rx, tx) = channel.split();
                    let mut sent = 0;
                    let mut n = 0u64;
                    while sent < bytes {
                        let mut chunk = Vec::new();
                        for _ in 0..1000 {
                            let line = format!("{} refs/heads/b{n:012}\n", "1".repeat(40));
                            chunk.extend_from_slice(format!("{:04x}", line.len() + 4).as_bytes());
                            chunk.extend_from_slice(line.as_bytes());
                            n += 1;
                        }
                        sent += chunk.len();
                        if tx.data_bytes(chunk).await.is_err() {
                            return;
                        }
                    }
                    let _ = tx.exit_status(0).await;
                    let _ = tx.eof().await;
                    let _ = tx.close().await;
                }
                Mode::Say(said) => {
                    let (_rx, tx) = channel.split();
                    let mut err = tx.make_writer_ext(Some(1));
                    let _ = tokio::io::AsyncWriteExt::write_all(&mut err, &said).await;
                    drop(err);
                    let _ = tx.exit_status(1).await;
                    let _ = tx.eof().await;
                    let _ = tx.close().await;
                }
            }
        });
        Ok(())
    }
}

/// `git-upload-pack '/demo.git'` → (`git-upload-pack`, `demo.git`).
fn parse(line: &str) -> Option<(&str, &str)> {
    let (program, arg) = line.split_once(' ')?;
    if !matches!(program, "git-upload-pack" | "git-receive-pack") {
        return None;
    }
    let path = arg.strip_prefix('\'')?.strip_suffix('\'')?;
    let path = path.trim_start_matches('/');
    (!path.contains("..") && !path.is_empty()).then_some((program, path))
}

async fn run_git(program: &str, repo: &Path, protocol: Option<String>, channel: Channel<Msg>) {
    let mut cmd = tokio::process::Command::new("git");
    cmd.arg(program)
        .arg(repo)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(protocol) = protocol {
        cmd.env("GIT_PROTOCOL", protocol);
    }
    let mut child = cmd.spawn().unwrap();
    let (mut rx, tx) = channel.split();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let input = tokio::spawn(async move {
        let mut reader = rx.make_reader();
        let _ = tokio::io::copy(&mut reader, &mut stdin).await;
        let _ = stdin.shutdown().await;
    });
    let mut out = tx.make_writer();
    let mut err = tx.make_writer_ext(Some(1));
    let _ = tokio::join!(
        tokio::io::copy(&mut stdout, &mut out),
        tokio::io::copy(&mut stderr, &mut err)
    );
    let _ = out.flush().await;
    let _ = err.flush().await;
    let code = child.wait().await.ok().and_then(|s| s.code()).unwrap_or(1);
    input.abort();
    let _ = tx.exit_status(u32::try_from(code).unwrap_or(1)).await;
    let _ = tx.eof().await;
    let _ = tx.close().await;
}
