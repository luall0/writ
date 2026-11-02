#!/bin/sh
# The GitHub manual check (docs/guides/manual-checks.md#a-throwaway-github-repo-m4), as one
# command: make github-check REPO=<owner>/<repo> [EMAIL=<a verified email of yours>].
#
#   sh tool/github-check.sh <owner>/<repo> [--email <address>] [--approver-key <file.pub>] [--keep]
#
# The repository must be a THROWAWAY one with a `main` (created with a README), never a real
# one. The script sets a daemon up from nothing in a temporary directory, as the operator guide
# does (its own writd.yaml, registry, keys, pins and reader), runs it, and drives the check's
# steps 4 to 8 with the check's own commands, then removes everything it made:
#
# - your approval key signs the ticket (Touch ID, once): its public half is
#   dev/data/client/approver.pub (step 1 of "Approving with Secretive"), or --approver-key;
#   Secretive's agent, or WRIT_APPROVAL_AGENT;
# - the daemon's deploy key is added to the repository with `gh` when it is installed and
#   logged in (and removed at the end), or by you when the script asks;
# - "upstream moves" is a commit pushed from a second clone with your own git access (your
#   GitHub SSH key: it may ask for a touch), in place of the web editor;
# - with --email (one of your account's verified emails, e.g. you+agent@example.org) the
#   lease's committer email is that address, and the script checks "Verified": unverified
#   before the lease's signing key is on your account, verified after (`gh` adds the key, or
#   you do when asked). Without it, that part is skipped: GitHub verifies an email by mail, so
#   the development policy's agent@writ.invalid can never be one of yours.
#
# Your own git and SSH are used only for what the operator does by hand in the check (clone,
# the other contributor's push, reading the repository's branches); Writ itself never sees
# them. Nothing in dev/ is changed. --keep leaves the temporary directory for a look.
set -eu
cd "$(dirname "$0")/.."
ROOT=$(pwd)

usage() {
    echo "usage: sh tool/github-check.sh <owner>/<repo> [--email <address>] [--approver-key <file.pub>] [--keep]" >&2
    exit 2
}

REPO="${1:-}"
[ -n "$REPO" ] || usage
shift
case "$REPO" in
    */*/* | /* | */ | *[!A-Za-z0-9._/-]*) echo "github-check: $REPO is not <owner>/<repo>" >&2; exit 2 ;;
    */*) ;;
    *) usage ;;
esac
EMAIL=""
APPROVER_KEY="$ROOT/dev/data/client/approver.pub"
KEEP=0
while [ $# -gt 0 ]; do
    case "$1" in
        --email) EMAIL="${2:-}"; [ -n "$EMAIL" ] || usage; shift 2 ;;
        --approver-key) APPROVER_KEY="${2:-}"; [ -n "$APPROVER_KEY" ] || usage; shift 2 ;;
        --keep) KEEP=1; shift ;;
        *) usage ;;
    esac
done
case "$EMAIL" in
    *[!A-Za-z0-9._+@-]*) echo "github-check: --email $EMAIL: printable address characters only" >&2; exit 2 ;;
esac
AGENT_SOCKET="${WRIT_APPROVAL_AGENT:-$HOME/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh}"
# GitHub's Ed25519 host key, checked below against its published fingerprint (GitHub's docs,
# "GitHub's SSH key fingerprints").
GITHUB_KEY="github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
GITHUB_FINGERPRINT="SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"

step() { printf '\n== %s\n' "$*"; }
FAILED=0
PASSED=0
check() { # check <what> <command…>: a line of the summary
    what=$1
    shift
    if "$@" >/dev/null 2>&1; then
        echo "  ok    $what"
        PASSED=$((PASSED + 1))
    else
        echo "  FAIL  $what"
        FAILED=$((FAILED + 1))
    fi
}
die() { echo "github-check: $*" >&2; exit 1; }
ask() { # ask <prompt>: waits for Enter on the terminal
    printf '%s [Enter] ' "$1" > /dev/tty
    read -r _ < /dev/tty
}
has_gh() { command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; }

# Prerequisites.
[ -f "$APPROVER_KEY" ] || die "no approval public key at $APPROVER_KEY: do step 1 of \"Approving with Secretive\" in docs/guides/manual-checks.md, or pass --approver-key"
[ -S "$AGENT_SOCKET" ] || die "no ssh-agent socket at $AGENT_SOCKET (Secretive's): set WRIT_APPROVAL_AGENT"
if nc -z 127.0.0.1 2222 2>/dev/null || nc -z 127.0.0.1 2223 2>/dev/null || nc -z 127.0.0.1 8443 2>/dev/null; then
    die "a daemon already listens on 2222, 2223 or 8443 (make run?): stop it first"
fi
printf '%s\n' "$GITHUB_KEY" > "${TMPDIR:-/tmp}/github-check-host.$$"
fingerprint=$(ssh-keygen -lf "${TMPDIR:-/tmp}/github-check-host.$$" | awk '{print $2}')
rm -f "${TMPDIR:-/tmp}/github-check-host.$$"
[ "$fingerprint" = "$GITHUB_FINGERPRINT" ] || die "GitHub's pinned key has fingerprint $fingerprint, not $GITHUB_FINGERPRINT"

# Your access to the repository, and its main, before anything is built or started.
if ! main=$(git ls-remote "git@github.com:$REPO.git" refs/heads/main 2>/dev/null); then
    die "cannot reach git@github.com:$REPO.git with your own git and SSH: check the name and your access"
fi
[ -n "$main" ] || die "$REPO has no main: create it with a README"

echo "This runs the GitHub manual check against $REPO."
echo "Use a THROWAWAY repository: the script pushes branches to it and adds keys."
ask "Continue?"

# Everything this run makes, removed on exit.
# Under /tmp, not $TMPDIR: macOS's is long enough that the daemon's sockets would pass the
# Unix socket path limit (104 bytes), which writd refuses.
DIR=$(mktemp -d /tmp/writ-gh.XXXXXX)
DIR=$(cd "$DIR" && pwd -P)
DAEMON_PID=""
DEPLOY_KEY_ID=""
SIGNING_KEY_ID=""
cleanup() {
    status=$?
    trap - EXIT INT TERM
    if [ -n "$DAEMON_PID" ]; then kill -INT "$DAEMON_PID" 2>/dev/null || true; wait "$DAEMON_PID" 2>/dev/null || true; fi
    if [ -n "$DEPLOY_KEY_ID" ]; then gh repo deploy-key delete "$DEPLOY_KEY_ID" --repo "$REPO" >/dev/null 2>&1 || true; fi
    if [ -n "$SIGNING_KEY_ID" ]; then gh api -X DELETE "user/ssh_signing_keys/$SIGNING_KEY_ID" >/dev/null 2>&1 || true; fi
    if [ "$KEEP" = 1 ]; then echo "kept: $DIR"; else rm -rf "$DIR"; fi
    if [ -z "$DEPLOY_KEY_ID" ] && [ -n "${DEPLOY_KEY_ADDED:-}" ]; then
        echo "Remove the deploy key you added (Settings > Deploy keys on $REPO)."
    fi
    if [ -z "$SIGNING_KEY_ID" ] && [ -n "${SIGNING_KEY_ADDED:-}" ]; then
        echo "Remove the signing key you added (GitHub > Settings > SSH and GPG keys)."
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

step "Building writd, writ and writ-sign"
cargo build -q --locked -p writd -p writ-cli -p writ-sign --features writd/dev-keystore
PATH="$ROOT/target/debug:$PATH"
export PATH

step "Setting the daemon up in $DIR (the operator guide's steps)"
mkdir -p "$DIR/daemon" "$DIR/client"
chmod 700 "$DIR/client"
COMMITTER="${EMAIL:-agent@writ.invalid}"
cat > "$DIR/daemon/writd.yaml" <<EOF
state_dir: data
policy: policy.yaml
approvers: approvers
readers: readers
decisions: signed
keystore: { dev: data/keys }
mirrors:
  known_hosts: upstream_known_hosts
transports:
  agents: [{ tcp: "127.0.0.1:2222", allow: [127.0.0.1] }]
  approvals:
    ssh: [{ tcp: "127.0.0.1:2223" }]
    https: [{ tcp: "127.0.0.1:8443" }]
attestor: network
session_watcher: none
notifiers: []
EOF
cat > "$DIR/daemon/policy.yaml" <<EOF
repos:
  demo:
    upstream: ssh://git@github.com/$REPO.git
    upstream_credential: upstream-github-check
    protected_refs: ["refs/heads/main", "refs/tags/*"]
templates:
  feature-branch:
    repos: [demo]
    operations: [fetch, commit_sign, push]
    branches: ["agent/*"]
    committer_emails: ["$COMMITTER"]
    signing_key: agent-github-check
    max_ttl: 4h
    max_signatures: 50
    max_pushes: 30
    max_ops_per_minute: 20
    max_push_size: 50MB
EOF
cp "$ROOT/dev/ticket.yaml" "$DIR/ticket.yaml"
printf '%s\n' "$GITHUB_KEY" > "$DIR/daemon/upstream_known_hosts"
printf 'me %s\n' "$(cat "$APPROVER_KEY")" > "$DIR/daemon/approvers"
chmod 644 "$DIR/daemon/"*
export WRIT_HOME="$DIR/client"
export WRIT_URL=ssh://127.0.0.1:2222
export WRIT_APPROVAL_URL=https://127.0.0.1:8443
export WRIT_APPROVAL_KEY="$APPROVER_KEY"
export WRIT_APPROVAL_AGENT="$AGENT_SOCKET"
cd "$DIR/daemon"
UPSTREAM_KEY=$(writd upstream-keys writd.yaml | awk '{print $2" "$3}')
SIGNING_KEY=$(writd signing-keys writd.yaml | awk '{print $2" "$3}')
HOST_KEY=$(writd host-key writd.yaml)
printf '[127.0.0.1]:2222 %s\n[127.0.0.1]:2223 %s\n' "$HOST_KEY" "$HOST_KEY" > "$DIR/client/known_hosts"
printf '[127.0.0.1]:8443 %s\n' "$(writd tls-fingerprint writd.yaml)" > "$DIR/client/tls_pins"
writ reader github-check > readers
chmod 644 readers

step "Step 3: the daemon's credential, as a deploy key with write access"
if has_gh; then
    printf '%s\n' "$UPSTREAM_KEY" > "$DIR/deploy.pub"
    gh repo deploy-key add "$DIR/deploy.pub" --repo "$REPO" --allow-write --title "writ github-check" >/dev/null
    DEPLOY_KEY_ID=$(gh repo deploy-key list --repo "$REPO" --json id,title --jq '.[] | select(.title == "writ github-check") | .id' | head -n 1)
    echo "added with gh (removed at the end)"
else
    echo "On GitHub: $REPO > Settings > Deploy keys > Add deploy key, with \"Allow write access\":"
    echo
    echo "  $UPSTREAM_KEY"
    echo
    DEPLOY_KEY_ADDED=1
    ask "Added?"
fi

step "Step 4: the daemon, and a lease (Touch ID once, for the ticket)"
writd run writd.yaml 2> "$DIR/writd.log" &
DAEMON_PID=$!
tries=0
until grep -q "role=Approvals" "$DIR/writd.log" 2>/dev/null && grep -q "approval API (HTTPS)" "$DIR/writd.log"; do
    kill -0 "$DAEMON_PID" 2>/dev/null || { cat "$DIR/writd.log" >&2; die "writd stopped"; }
    tries=$((tries + 1))
    [ "$tries" -le 120 ] || { cat "$DIR/writd.log" >&2; die "writd did not start"; }
    sleep 0.5
done
cd "$DIR"
LEASE=$(writ request --no-wait ticket.yaml | sed -n 's/^Ticket \(wrt_[0-9A-Z]*\) submitted.*/\1/p')
[ -n "$LEASE" ] || die "the ticket was not submitted"
echo "Review the ticket and answer y (Secretive asks for Touch ID):"
writ sign "$LEASE" < /dev/tty
writ wait "$LEASE"

step "Steps 5 to 7: the agent's clone, signed commits, upstream moving, refused pushes"
git clone -q "git@github.com:$REPO.git" "$DIR/w"
cd "$DIR/w"
MAIN=$(git ls-remote origin refs/heads/main | cut -f1)
remote_branch() { git ls-remote origin "refs/heads/$1" | cut -f1; }
mirror_branch() { git -C "$DIR/daemon/data/repos/demo.git" rev-parse --verify -q "refs/heads/$1" 2>/dev/null || true; }
# Step 5, the check's commands.
writ init demo
writ git fetch origin
git checkout -q -b agent/manual-check origin/main
echo hi > notes.txt && writ git add notes.txt
writ git commit -m "Manual check" --trailer "Writ: $LEASE"
writ git push origin HEAD:refs/heads/agent/manual-check
FIRST=$(git rev-parse HEAD)
check "the signed commit is on GitHub" test "$(remote_branch agent/manual-check)" = "$FIRST"
check "and in the daemon's mirror" test "$(mirror_branch agent/manual-check)" = "$FIRST"
printf '%s %s\n' "$COMMITTER" "$(cat "$DIR/client/sessions/current/signing_key.pub")" > "$DIR/allowed"
check "it verifies with the lease's key, through writ-sign" \
    writ git -c gpg.ssh.allowedSignersFile="$DIR/allowed" verify-commit HEAD
# Upstream moves: someone else commits another file on the branch (your git, another clone).
git clone -q --branch agent/manual-check "git@github.com:$REPO.git" "$DIR/other"
(cd "$DIR/other" && echo theirs > theirs.txt && git add theirs.txt \
    && git -c commit.gpgsign=false -c user.name="Someone else" -c user.email=someone@writ.invalid \
        commit -q -m "Someone else's change" && git push -q origin agent/manual-check)
THEIRS=$(remote_branch agent/manual-check)
# Step 6, the check's commands.
echo more >> notes.txt && writ git commit -qam "Second" --trailer "Writ: $LEASE"
if writ git push origin HEAD:refs/heads/agent/manual-check > "$DIR/rejected.txt" 2>&1; then
    check "the push behind upstream is rejected" false
else
    check "the push behind upstream is rejected" grep -q rejected "$DIR/rejected.txt"
fi
check "GitHub keeps the other contributor's commit" test "$(remote_branch agent/manual-check)" = "$THEIRS"
writ git fetch origin && writ git rebase origin/agent/manual-check
writ git push origin HEAD:refs/heads/agent/manual-check
REBASED=$(git rev-parse HEAD)
check "after fetch and rebase (signed again), the push lands" test "$(remote_branch agent/manual-check)" = "$REBASED"
check "on top of the other contributor's commit" test "$(git rev-parse HEAD~1)" = "$THEIRS"
check "the mirror follows" test "$(mirror_branch agent/manual-check)" = "$REBASED"
# Step 7, the check's commands.
if writ git push origin HEAD:refs/heads/main > "$DIR/main.txt" 2>&1; then
    check "a push to main is refused (protected)" false
else
    check "a push to main is refused (protected)" grep -q "refs/heads/main is protected" "$DIR/main.txt"
fi
git commit -q --allow-empty --no-gpg-sign -m "Unsigned"
if writ git push origin HEAD:refs/heads/agent/manual-check > "$DIR/unsigned.txt" 2>&1; then
    check "an unsigned commit is refused" false
else
    check "an unsigned commit is refused" grep -q "was not signed under this lease" "$DIR/unsigned.txt"
fi
git reset -q --hard HEAD~1
check "main on GitHub didn't move" test "$(remote_branch main)" = "$MAIN"
check "the branch on GitHub didn't move" test "$(remote_branch agent/manual-check)" = "$REBASED"

step "Step 8: what to check"
AUDIT="$DIR/daemon/data/audit.jsonl"
allowed=$(grep "\"lease\":\"$LEASE\"" "$AUDIT" | grep -c '"event":"push","result":"allowed"' || true)
denied=$(grep "\"lease\":\"$LEASE\"" "$AUDIT" | grep -c '"event":"push","result":"denied"' || true)
check "the audit log has the allowed pushes ($allowed)" test "$allowed" -ge 3
check "and the refused ones ($denied)" test "$denied" -ge 2
check "and no key material" sh -c "! grep -q 'PRIVATE KEY' '$AUDIT'"
others=$(ls "$DIR/client/sessions/$LEASE" | grep -vcE '^(key|key\.pub|key-cert\.pub|lease\.json|signing_key\.pub|ticket\.json|wrt_[0-9A-Z]+\.json)$' || true)
check "the session holds no GitHub credential (only its key, certificate, lease)" test "$others" -eq 0

if [ -n "$EMAIL" ]; then
    step "Verified on GitHub: the lease's signing key on your account, $EMAIL verified on it"
    verified() { # verified <sha>: GitHub's verification of a commit, true or false
        if has_gh; then
            gh api "repos/$REPO/commits/$1" --jq '.commit.verification.verified'
        else
            printf 'Does https://github.com/%s/commit/%s show "Verified"? [y/N] ' "$REPO" "$1" > /dev/tty
            read -r answer < /dev/tty
            case "$answer" in y | Y | yes) echo true ;; *) echo false ;; esac
        fi
    }
    check "before the key is on the account: unverified" test "$(verified "$REBASED")" = false
    if has_gh && SIGNING_KEY_ID=$(gh api -X POST user/ssh_signing_keys -f title="writ github-check" \
        -f key="$SIGNING_KEY" --jq .id 2>/dev/null); then
        echo "added with gh (removed at the end)"
    else
        SIGNING_KEY_ID=""
        echo "On GitHub: Settings > SSH and GPG keys > New SSH key, Key type \"Signing Key\":"
        echo
        echo "  $SIGNING_KEY"
        echo
        SIGNING_KEY_ADDED=1
        ask "Added?"
    fi
    echo again >> notes.txt && writ git commit -qam "Third" --trailer "Writ: $LEASE"
    writ git push -q origin HEAD:refs/heads/agent/manual-check
    check "after: the new commit is verified" test "$(verified "$(git rev-parse HEAD)")" = true
else
    step "Verified on GitHub: skipped (pass --email <one of your verified emails> to check it)"
fi

step "Summary"
echo "$PASSED passed, $FAILED failed (daemon log: $DIR/writd.log, kept with --keep)"
if [ "$FAILED" -eq 0 ]; then
    echo "Note it under the acceptance items of docs/history/m4-gateway-push-and-fetch.md"
    echo "(and of m4.1-real-end-to-end-scenarios.md for \"Verified\", if checked)."
fi
[ "$FAILED" -eq 0 ]
