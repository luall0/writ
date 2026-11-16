# shellcheck shell=sh
# shellcheck disable=SC2030,SC2031 # planned() sets DRY_RUN in a subshell of its own, by design
# The installer's frame (sourced by install.sh): what every setup shares.
#
# - Guided (docs/conventions.md#installers-are-guided): on a terminal every choice is asked,
#   each with what it means and its default; then the answers and every change are shown, and
#   nothing is done before one confirmation. Without a terminal (scripts, tests), the
#   variables answer the same questions: SETUP, APPROVER and each setup's own.
# - The setup: asked among the ones this OS has (each setups/<file>.sh says in its header
#   `# writ-setup: <name> <os> <manifest path>` and `# writ-setup-about: <one line>`).
# - The dry run: `DRY_RUN=1` lists every change and makes none (a terminal's summary shows
#   the same list before its confirmation).
# - Root only where needed: `as_root` runs one command through sudo, `as_user` as you,
#   `as_daemon <user>` as the daemon's user.
# - The manifest: each change is appended once made (root-owned), so a failed install stops
#   and says what was done, and the uninstall takes back exactly that, newest first, and only
#   paths the setup says are its own.
# - The upgrade: run again where a manifest is, the setup's upgrade runs instead.
#
# For the tests only: `WRIT_INSTALL_ROOT` puts every system path under a directory and runs
# every step as you (the system tools stubbed on PATH), `WRIT_INSTALL_OS` stands for
# `uname -s`, `WRIT_INSTALL_BINARIES` names the built binaries.

ROOT=${WRIT_INSTALL_ROOT:-}
DRY_RUN=${DRY_RUN:-0}
SETUP=${SETUP:-}
PURGE=${PURGE:-0}
REPOS=${REPOS:-}
OS=${WRIT_INSTALL_OS:-$(uname -s)}
# shellcheck disable=SC2034 # read by the setups it sources
BINARIES=${WRIT_INSTALL_BINARIES:-$DEPLOY/../target/release}
TAB=$(printf '\t')
CURRENT=
MANIFEST=
ACTION=

say() { printf '%s\n' "$*"; }
fail() {
    printf 'install: %s\n' "$*" >&2
    exit 1
}

# A system path, under the test root when there is one.
sys() { printf '%s%s' "$ROOT" "$1"; }

# Whether questions can be asked.
terminal() { [ -t 0 ]; }

# The writ that asks the questions on a terminal with its widgets (M7.9.5: arrow keys, typing
# filters): the one this install built (`writ prompt`), on stdout; none when it isn't there
# or stdin or stderr isn't a terminal, and the plain prompts below ask the same questions.
asker() {
    [ -t 0 ] && [ -t 2 ] && [ -x "$BINARIES/writ" ] || return 1
    printf '%s' "$BINARIES/writ"
}

# ask <label> <default>: one answer from the terminal (the default on Enter), on stdout; the
# prompt on stderr. Esc stops the install, nothing done.
ask() {
    if w=$(asker); then
        if [ -n "$2" ]; then
            answer=$("$w" prompt text --question "$1" --default "$2") || fail "stopped: nothing done"
        else
            answer=$("$w" prompt text --question "$1") || fail "stopped: nothing done"
        fi
        printf '%s' "${answer:-$2}"
        return 0
    fi
    if [ -n "$2" ]; then
        printf '%s [%s]: ' "$1" "$2" >&2
    else
        printf '%s: ' "$1" >&2
    fi
    read -r answer || answer=
    printf '%s' "${answer:-$2}"
}

# confirm <question>: yes on y or yes, asked on the terminal; no otherwise.
confirm() {
    if w=$(asker); then
        "$w" prompt confirm --question "$1" >&2
        return
    fi
    printf '%s [y/N] ' "$1" >&2
    read -r answer || answer=
    case $answer in
        y | Y | yes) return 0 ;;
        *) return 1 ;;
    esac
}

# choose_one <variable> <value> <label> <default> <allowed…>: the value of <variable> when it
# was given, else asked on a terminal (again until it is one of <allowed>), else <default>;
# one not allowed refused, naming the variable.
choose_one() {
    name=$1 value=$2 label=$3 default=$4
    shift 4
    if [ -z "$value" ] && terminal; then
        while :; do
            if w=$(asker); then
                # A select of the allowed values, the default first under the cursor.
                value=$("$w" prompt select --question "$label" --default "$default" -- "$@") ||
                    fail "stopped: nothing done"
            else
                value=$(ask "$label" "$default")
            fi
            for one in "$@"; do
                [ "$value" = "$one" ] && break 2
            done
            say "  $value: one of $*" >&2
        done
    fi
    value=${value:-$default}
    for one in "$@"; do
        if [ "$value" = "$one" ]; then
            printf '%s' "$value"
            return 0
        fi
    done
    fail "$name=$value: one of $*"
}

# A path with a leading ~/ made your home's.
expand_home() {
    # shellcheck disable=SC2088 # a literal ~/ typed at the prompt, made $HOME's here
    case $1 in
        "~/"*) printf '%s/%s' "$HOME" "${1#\~/}" ;;
        *) printf '%s' "$1" ;;
    esac
}

# Reads the approval key's public half at <path> once: APPROVER_KEY (its line, what the
# daemon's `approvers` and your approver.pub get) and APPROVER_FP (its fingerprint, what the
# summary shows) both come from that one read, so a file changed after you saw it changes
# nothing; or APPROVER_PROBLEM says what is wrong with it.
load_approver() {
    APPROVER_KEY='' APPROVER_FP='' APPROVER_PROBLEM=''
    if [ -z "$1" ]; then
        APPROVER_PROBLEM='no path given'
        return 0
    fi
    if [ ! -f "$1" ] || [ ! -r "$1" ]; then
        APPROVER_PROBLEM="$1: not a readable file"
        return 0
    fi
    approver_text=$(head -c 16384 "$1" 2>/dev/null) || approver_text=
    case $approver_text in
        *"PRIVATE KEY"*)
            APPROVER_PROBLEM="$1 is a private key: give its .pub"
            return 0
            ;;
    esac
    approver_line=$(printf '%s\n' "$approver_text" | head -n 1)
    case $approver_line in
        ssh-* | ecdsa-* | sk-*) ;;
        *)
            APPROVER_PROBLEM="$1 is not an SSH public key"
            return 0
            ;;
    esac
    approver_fp=$(printf '%s\n' "$approver_line" | ssh-keygen -l -f - 2>/dev/null) || {
        APPROVER_PROBLEM="$1 is not an SSH public key"
        return 0
    }
    APPROVER_KEY=$approver_line
    APPROVER_FP=$(printf '%s' "$approver_fp" | awk '{print $2}')
}

# APPROVER: asked on a terminal (again until it is an SSH public key), else the variable;
# read once (load_approver).
choose_approver() {
    if [ -z "${APPROVER:-}" ] && terminal; then
        say "Your approval key: the key whose signature turns an agent's ticket into a lease, held" >&2
        say "by your ssh-agent. Give the path to its public half, the .pub: the" >&2
        say "installer reads that file alone, and Writ never uses your other keys." >&2
        while :; do
            APPROVER=$(expand_home "$(ask "Approval key (.pub)" "")")
            load_approver "$APPROVER"
            [ -z "$APPROVER_PROBLEM" ] && break
            say "  $APPROVER_PROBLEM" >&2
        done
    fi
    [ -n "${APPROVER:-}" ] || fail "APPROVER=<your approval key's .pub> is needed without a terminal (its public half: who may sign)"
    load_approver "$APPROVER"
    [ -z "$APPROVER_PROBLEM" ] || fail "APPROVER=$APPROVER_PROBLEM"
}

# With the daemon's data kept from before, its `approvers` stands: no approval key is asked,
# and one given is not used.
approver_kept() {
    APPROVER_KEY=
    [ -z "${APPROVER:-}" ] ||
        say "  APPROVER is not used: the approvers of the data kept from before stand (writ admin changes them)."
}

# Your approver.pub (what writ sign and writ admin sign with), from the key read once; with
# the data kept from before, left to you when it isn't there.
put_approver_pub() {
    if [ -e "$WHOME/approver.pub" ]; then
        return 0
    fi
    if [ -z "${APPROVER_KEY:-}" ]; then
        say "  $WHOME/approver.pub is not there: copy your approval key's .pub to it (the data kept from before names that key)"
        return 0
    fi
    put_user "$WHOME/approver.pub" "$APPROVER_KEY"
    record "userfile $WHOME/approver.pub"
}

# What an upgrade that replaced writ says: the sessions bound under the old one are cut.
upgraded_writ() {
    say "writ changed: agents started with writ run before the upgrade are bound to the old writ,"
    say "and their leases are refused from now on. Start each again (writ run -- <agent>), then"
    say "request a new lease. writ skill update --all rewrites the agent skill in every"
    say "repository it wired."
}

# One command as root (through sudo), as you, or as the daemon's user.
as_root() {
    if [ "$DRY_RUN" = 1 ]; then
        printf '    (root)'
        printf ' %s' "$@"
        printf '\n'
        return 0
    fi
    if [ -n "$ROOT" ]; then "$@"; else sudo "$@"; fi
}
as_user() {
    if [ "$DRY_RUN" = 1 ]; then
        printf '    (you)'
        printf ' %s' "$@"
        printf '\n'
        return 0
    fi
    "$@"
}
as_daemon() {
    daemon_user=$1
    shift
    if [ "$DRY_RUN" = 1 ]; then
        printf '    (%s)' "$daemon_user"
        printf ' %s' "$@"
        printf '\n'
        return 0
    fi
    if [ -n "$ROOT" ]; then "$@"; else sudo -u "$daemon_user" "$@"; fi
}

# As as_root and as_daemon, run in a dry run too: for what changes nothing (the upgrade's check).
run_root() {
    if [ -n "$ROOT" ]; then "$@"; else sudo "$@"; fi
}
run_daemon() {
    daemon_user=$1
    shift
    if [ -n "$ROOT" ]; then "$@"; else sudo -u "$daemon_user" "$@"; fi
}

# The new writd's dry run on the installed daemon (M7.9.6), before anything changes, in a dry
# run too (it changes nothing): `writd check-upgrade` as the daemon's user, from a copy in a
# directory of root's (one you can write, an agent of yours could swap for a program that
# then runs as that user). It says what the start will migrate and what waits for a
# signature; a block stops the upgrade, nothing changed.
upgrade_check() {
    say "Checking what the new writd carries over (writd check-upgrade):"
    # /tmp on the machine; a fake root's tests (no other user, no sudo) use their own.
    base=/tmp
    [ -z "$ROOT" ] || base=${TMPDIR:-/tmp}
    check_dir=$(run_root mktemp -d "$base/writ-check-upgrade.XXXXXX") ||
        fail "no directory for the check"
    run_root chmod 0755 "$check_dir"
    run_root install -m 0755 "$BINARIES/writd" "$check_dir/writd"
    checked=0
    # shellcheck disable=SC2153 # DAEMON_USER and CONFIG are the setup's (sourced before)
    run_daemon "$DAEMON_USER" "$check_dir/writd" check-upgrade "$CONFIG" || checked=1
    run_root rm -rf "$check_dir"
    [ "$checked" = 0 ] || fail "the new writd can't carry this install over (said above): nothing was changed"
}

# The version a Writ binary says it is (M7.9.8): MAJOR.MINOR.PATCH, or nothing when it names
# none (a writd before 0.2.0 has no --version; a writ before 0.1.0 says 0.0.0).
version_of() {
    said=$("$1" --version 2>/dev/null) || return 0
    v=${said#* }
    case $v in
        "" | 0.0.0 | *[!0-9.]* | .* | *. | *..*) return 0 ;;
    esac
    printf '%s' "$v"
}

# -1, 0 or 1 as version <a> is below, the same as, or above <b>.
version_cmp() {
    awk -v a="$1" -v b="$2" 'BEGIN {
        split(a, x, "."); split(b, y, ".")
        for (i = 1; i <= 3; i++) {
            if (x[i] + 0 < y[i] + 0) { print -1; exit }
            if (x[i] + 0 > y[i] + 0) { print 1; exit }
        }
        print 0
    }'
}

# The changelog's Upgrading notes from <from> (empty: before any version) to <to>, newest
# first, and those of the changes not released yet.
upgrading_notes() {
    changelog=$DEPLOY/../CHANGELOG.md
    [ -f "$changelog" ] || return 0
    awk -v from="$1" -v to="$2" '
        function cmp(a, b,   x, y, i) {
            split(a, x, "."); split(b, y, ".")
            for (i = 1; i <= 3; i++) {
                if (x[i] + 0 < y[i] + 0) return -1
                if (x[i] + 0 > y[i] + 0) return 1
            }
            return 0
        }
        /^## / {
            section = ""
            if ($0 == "## Unreleased") { take = 1; release = "not released yet" }
            else { take = (from == "" || cmp($2, from) > 0) && cmp($2, to) <= 0; release = $2 }
            next
        }
        /^### / {
            section = substr($0, 5)
            if (take && section == "Upgrading") print "  " release ":"
            next
        }
        take && section == "Upgrading" && NF { print "    " $0 }
    ' "$changelog"
}

# Which version replaces which (M7.9.8), and what the changelog says the upgrade asks, before
# the check and the go: the installed writd's version (its writ's, for a writd before 0.2.0)
# and the new one's.
upgrade_versions() {
    to=$(version_of "$BINARIES/writd")
    [ -n "$to" ] || fail "the new writd names no version ($BINARIES/writd --version)"
    # shellcheck disable=SC2153 # BIN is the setup's (sourced before)
    from=$(version_of "$BIN/writd")
    [ -n "$from" ] || from=$(version_of "$BIN/writ")
    if [ -z "$from" ]; then
        say "Upgrading Writ: a version before 0.1.0 → $to."
    else
        case $(version_cmp "$from" "$to") in
            -1) say "Upgrading Writ: $from → $to." ;;
            0) say "Installing Writ $to again: the version installed." ;;
            1)
                say "Going back: Writ $from → $to, an older version. writd check-upgrade (below)"
                say "says whether it reads this install's state and policy."
                return 0
                ;;
        esac
    fi
    notes=$(upgrading_notes "$from" "$to")
    [ -z "$notes" ] || {
        say "What it asks (the changelog's Upgrading):"
        say "$notes"
    }
}

# Shell completion (M7.9.9). The directory a shell reads completions from, as the shell itself
# says, the first that exists; nothing when the shell isn't here or names none. fish: its
# vendor directories; zsh: a site-functions directory on its fpath; bash: bash-completion's
# completionsdir.
completion_dir() {
    case $1 in
        fish)
            command -v fish >/dev/null 2>&1 || return 0
            # shellcheck disable=SC2016 # the shell's own variable, expanded by it
            fish --no-config -c 'for d in $__fish_vendor_completionsdirs; echo $d; end' 2>/dev/null
            ;;
        zsh)
            command -v zsh >/dev/null 2>&1 || return 0
            # shellcheck disable=SC2016 # the shell's own variable, expanded by it
            zsh -f -c 'print -rl -- $fpath' 2>/dev/null | grep '/site-functions$'
            ;;
        bash)
            command -v pkg-config >/dev/null 2>&1 || return 0
            pkg-config --variable=completionsdir bash-completion 2>/dev/null
            ;;
    esac | while read -r dir; do
        if [ -d "$(sys "$dir")" ]; then
            printf '%s' "$dir"
            break
        fi
    done
}

# The file each shell loads for writ, in its completion directory.
completion_file() {
    case $1 in
        fish) printf 'writ.fish' ;;
        zsh) printf '_writ' ;;
        bash) printf 'writ' ;;
    esac
}

# Whether <path> is one the installer writes for completion: the uninstall takes back no other.
completion_owned() {
    case $1 in
        */vendor_completions.d/writ.fish | */site-functions/_writ | */completions/writ) return 0 ;;
    esac
    return 1
}

# writ's registration (`<writ> completions <shell>`) written for each shell installed here, in
# its completion directory, as root; a shell here that names none gets the line to add by
# hand. Written again by an upgrade: the registration runs the writ it names.
install_completions() {
    writ=$1
    for shell in fish zsh bash; do
        command -v "$shell" >/dev/null 2>&1 || continue
        dir=$(completion_dir "$shell")
        if [ -z "$dir" ]; then
            case $shell in
                fish) line="writ completions fish | source" ;;
                *) line="source <(writ completions $shell)" ;;
            esac
            say "- $shell completion: no completion directory found; add this line to its startup file: $line"
            continue
        fi
        path=$(sys "$dir")/$(completion_file "$shell")
        step "Shell completion for $shell ($path)"
        if [ "$DRY_RUN" = 1 ]; then
            printf '    (root) write %s: writ completions %s\n' "$path" "$shell"
            continue
        fi
        content=$("$writ" completions "$shell") || fail "writ completions $shell failed"
        new=no
        [ -e "$path" ] || new=yes
        put_root "$path" 0644 root:0 "$content"
        [ "$new" = no ] || record "completion $path"
    done
}

# After an upgrade's restart (M7.9.6): on a terminal, the daemon unsealed (unless it opened
# itself) and the policy's migration signed when one is owed, both as you, each its own
# approval; declined or failed, what to run. Without a terminal, what to run.
after_upgrade() {
    writ=$1
    [ "$DRY_RUN" = 1 ] && return 0
    if ! terminal; then
        say "Upgraded. writ unseal opens it again; then writ migrate, if it says the policy's"
        say "migration is owed (the daemon refuses every request until it is signed)."
        return 0
    fi
    # Once it listens, the daemon answers: sealed, a migration owed, or open.
    state=none
    tries=0
    while [ "$tries" -lt 60 ]; do
        if out=$("$writ" ls 2>&1); then
            state=open
            break
        fi
        case $out in
            *"daemon sealed"*) state=sealed && break ;;
            *"older format"*) state=owed && break ;;
        esac
        sleep 1
        tries=$((tries + 1))
    done
    case $state in
        none)
            say "Upgraded. The daemon didn't answer yet: writ unseal opens it, then writ migrate."
            return 0
            ;;
        open) say "Upgraded: the daemon is open, nothing is owed." && return 0 ;;
    esac
    if [ "$state" = sealed ]; then
        say "Upgraded. Unsealing it now (writ unseal):"
        "$writ" unseal || {
            say "Not unsealed: run writ unseal, then writ migrate."
            return 0
        }
    fi
    say "Signing the policy's migration if one is owed (writ migrate):"
    "$writ" migrate || say "Not migrated: the daemon refuses every request until you run writ migrate."
}

# Runs <command…> as a dry run, in a subshell: the changes listed, none made, and DRY_RUN
# that subshell's alone.
planned() {
    (
        DRY_RUN=1
        "$@"
    )
}

# A step: said, and named if it fails.
step() {
    CURRENT=$*
    say "- $*"
}

# Appends a line to the manifest, once its change is made.
record() {
    [ "$DRY_RUN" = 1 ] && return 0
    printf '%s\n' "$*" | as_root tee -a "$MANIFEST" >/dev/null
}

# put_root <path> <mode> <owner> <content>: a file written whole as root. The content goes
# to sudo on its standard input, never through a file of yours (an agent running as you could
# change one while sudo asks for your password): written beside its place in root's
# directory, given its mode and owner, then renamed over it.
put_root() {
    if [ "$DRY_RUN" = 1 ]; then
        printf '    (root) write %s (%s, %s):\n' "$1" "$2" "$3"
        printf '%s\n' "$4" | sed 's/^/        /'
        return 0
    fi
    put_new=$1.writ-install
    as_root rm -f "$put_new"
    printf '%s\n' "$4" | as_root tee "$put_new" >/dev/null
    as_root chmod "$2" "$put_new"
    as_root chown "$3" "$put_new"
    as_root mv -f "$put_new" "$1"
}

# A file of yours written whole, only you reading it.
put_user() {
    if [ "$DRY_RUN" = 1 ]; then
        printf '    (you) write %s:\n' "$1"
        printf '%s\n' "$2" | sed 's/^/        /'
        return 0
    fi
    (umask 077 && printf '%s\n' "$2" >"$1.writ-install" && mv "$1.writ-install" "$1")
}

# The setups this OS has: "<name> <file>" a line.
setups_here() {
    for file in "$DEPLOY"/setups/*.sh; do
        header=$(sed -n 's/^# writ-setup: //p' "$file" | head -n 1)
        name=${header%% *}
        rest=${header#* }
        os=${rest%% *}
        [ "$os" = "$OS" ] && printf '%s %s\n' "$name" "$file"
    done
    return 0
}

# The manifest path a setup file declares.
manifest_of() {
    header=$(sed -n 's/^# writ-setup: //p' "$1" | head -n 1)
    rest=${header#* }
    printf '%s' "$(sys "${rest#* }")"
}

# A setup file's name (its header's first word).
name_of() {
    header=$(sed -n 's/^# writ-setup: //p' "$1" | head -n 1)
    printf '%s' "${header%% *}"
}

# What a setup file says it is, in one line.
about_of() {
    sed -n 's/^# writ-setup-about: //p' "$1" | head -n 1
}

# Picks the setup: SETUP, or asked on a terminal (each offered one said with what it is, the
# first one on Enter); one this OS doesn't have is refused with the list.
choose_setup() {
    offered=$(setups_here | cut -d' ' -f1 | tr '\n' ' ')
    [ -n "$offered" ] || fail "no setup for $OS in this build"
    if [ -z "$SETUP" ]; then
        terminal || fail "SETUP=<name> is needed without a terminal (offered on $OS: $offered)"
        # On stderr: what this function prints on stdout is the setup's file.
        say "Which setup? Offered on $OS: $offered" >&2
        setups_here | while read -r name file; do
            say "  $name: $(about_of "$file")" >&2
        done
        if w=$(asker); then
            # shellcheck disable=SC2086 # one option per setup name (names have no space)
            SETUP=$("$w" prompt select --question "Setup" --default "${offered%% *}" -- $offered) ||
                fail "stopped: nothing done"
        else
            SETUP=$(ask "Setup" "${offered%% *}")
        fi
    fi
    chosen=$(setups_here | while read -r name file; do
        if [ "$name" = "$SETUP" ]; then printf '%s' "$file"; fi
    done)
    [ -n "$chosen" ] || fail "setup $SETUP is not offered on $OS (offered: $offered)"
    printf '%s' "$chosen"
}

# The manifest already here, if any, and the setup that wrote it.
installed() {
    setups_here | while read -r _name file; do
        manifest=$(manifest_of "$file")
        if [ -f "$manifest" ]; then
            printf '%s\n%s' "$file" "$manifest"
            return 0
        fi
    done
    return 0
}

on_exit() {
    status=$?
    if [ "$status" != 0 ] && [ "$ACTION" = install ] && [ -n "$CURRENT" ] && [ "$DRY_RUN" != 1 ]; then
        printf 'install: stopped at: %s.\n' "$CURRENT" >&2
        # shellcheck disable=SC2016 # the backticks are the message's, not a command
        printf 'What was done so far is in %s: `make uninstall` takes it back.\n' "$MANIFEST" >&2
    fi
}

do_install() {
    ACTION=install
    trap on_exit EXIT
    found=$(installed)
    if [ -n "$found" ]; then
        file=$(printf '%s' "$found" | sed -n 1p)
        MANIFEST=$(printf '%s' "$found" | sed -n 2p)
        # shellcheck source=/dev/null
        . "$file"
        upgrade_versions
        upgrade_check
        if [ "$DRY_RUN" != 1 ] && terminal; then
            say "Installed already ($MANIFEST): an upgrade replaces the binaries and restarts the"
            say "daemon, its keys, state and configuration kept. The changes, in order:"
            planned setup_upgrade
            confirm "Upgrade?" || {
                say "Nothing changed."
                return 0
            }
        fi
        say "Upgrading the installed setup ($MANIFEST):"
        setup_upgrade
        return 0
    fi
    [ "$DRY_RUN" != 1 ] && terminal &&
        say "Writ's installer: a few questions, then every change it will make, then your go."
    file=$(choose_setup)
    MANIFEST=$(manifest_of "$file")
    # shellcheck source=/dev/null
    . "$file"
    to=$(version_of "$BINARIES/writd")
    [ -n "$to" ] || fail "the new writd names no version ($BINARIES/writd --version)"
    say "Installing Writ $to."
    setup_questions
    if [ "$DRY_RUN" = 1 ]; then
        say "Dry run: these are the changes; none is made."
        setup_install
        return 0
    fi
    if terminal; then
        say ""
        say "Your answers:"
        say "  Setup: $(name_of "$file") ($(about_of "$file"))"
        [ -z "${APPROVER_KEY:-}" ] || say "  Approval key: $APPROVER_FP ($APPROVER)"
        setup_answers
        say "The changes, in order (none is made yet):"
        planned setup_install
        confirm "Install?" || {
            say "Nothing changed."
            return 0
        }
    fi
    setup_install
}

# The manifest, if it can be trusted: a regular file nobody but root (you, under a test
# root) can write.
trusted_manifest() {
    if [ ! -f "$1" ] || [ -L "$1" ]; then
        fail "$1 is not a regular file: nothing done"
    fi
    # ls, not stat: stat's options differ between macOS and Linux; the path is the manifest's.
    # shellcheck disable=SC2012
    owner=$(ls -ldn "$1" | awk '{print $3}')
    # shellcheck disable=SC2012
    perms=$(ls -ld "$1" | cut -c1-10)
    expected=0
    [ -z "$ROOT" ] || expected=$(id -u)
    [ "$owner" = "$expected" ] || fail "$1 is owned by uid $owner, not root: nothing done"
    case $perms in
        ?????w???? | ????????w?) fail "$1 can be written by group or others ($perms): nothing done" ;;
    esac
}

do_uninstall() {
    ACTION=uninstall
    found=$(installed)
    [ -n "$found" ] || fail "nothing installed here (no manifest of a setup for $OS)"
    file=$(printf '%s' "$found" | sed -n 1p)
    MANIFEST=$(printf '%s' "$found" | sed -n 2p)
    # shellcheck source=/dev/null
    . "$file"
    trusted_manifest "$MANIFEST"

    # Every question first: nothing changes before they are answered.
    repos_answer=$(repos_question)
    purge_answer=no
    if terminal || [ "$PURGE" = 1 ]; then
        say "The daemon's data (keystore, state, ledger, audit log): kept, a later install uses"
        say "it again; or deleted for good:"
        grep "^data \|^userdata " "$MANIFEST" | cut -d' ' -f2- | sed 's/^/  /'
        # Deleting it needs a person: PURGE=1 alone, without a terminal, deletes nothing.
        terminal || fail "PURGE=1 needs a terminal to confirm: nothing done"
        typed=$(ask "Type delete to delete it, Enter keeps it" "")
        case $typed in
            delete) purge_answer=yes ;;
            "") [ "$PURGE" != 1 ] || fail "not confirmed: nothing done" ;;
            *) fail "not confirmed: nothing done" ;;
        esac
    fi
    if [ "$DRY_RUN" != 1 ] && terminal; then
        say "What the uninstall takes back, newest first (nothing is done yet):"
        planned undo_all "$purge_answer"
        confirm "Uninstall?" || {
            say "Nothing changed."
            return 0
        }
    fi

    if [ "$repos_answer" = undo ]; then
        step "Writ taken out of the repositories it wired (as you)"
        as_user "$(setup_writ)" init --undo --all || say "  (some could not be taken back: named above)"
        # writ's own list, empty once every repository is taken back.
        repos_list=${WRIT_HOME:-$HOME/.writ}/repos
        if [ "$DRY_RUN" != 1 ] && [ -f "$repos_list" ] && [ ! -s "$repos_list" ]; then
            rm -f "$repos_list"
        fi
    fi
    step "Taking back what the install made, newest first"
    undo_all "$purge_answer"
    as_root rm -f "$MANIFEST"
    setup_finish_uninstall
    say "Uninstalled."
}

# What the uninstall does with the repositories writ init wired here: undo, keep, or none
# (no list). Asked on a terminal; without one, REPOS answers or nothing is done.
repos_question() {
    writ=$(setup_writ)
    if [ ! -f "${WRIT_HOME:-$HOME/.writ}/repos" ] || [ ! -x "$writ" ]; then
        printf none
        return 0
    fi
    listed=$("$writ" init --list 2>&1) || listed=
    [ -n "$listed" ] || {
        printf none
        return 0
    }
    {
        say "The repositories writ init wired here:"
        printf '%s\n' "$listed" | sed 's/^/  /'
        say "Once writ is gone, only a new install can take them back."
    } >&2
    case $REPOS in
        undo | keep)
            printf '%s' "$REPOS"
            return 0
            ;;
        "") ;;
        *) fail "REPOS=$REPOS: undo or keep" ;;
    esac
    terminal || fail "REPOS=undo or REPOS=keep is needed without a terminal: nothing done"
    if confirm "Take Writ out of them too?"; then
        printf undo
    else
        say "Kept wired." >&2
        printf keep
    fi
}

# Takes back every manifest line, newest first (<purge>: yes deletes the daemon's data).
undo_all() {
    lines=$(sed '1!G;h;$!d' "$MANIFEST")
    printf '%s\n' "$lines" | while IFS= read -r line; do
        undo_line "$line" "$1"
    done
}

# Takes back one manifest line: its kind, then its path (and for a line in a file, a tab
# and the line).
undo_line() {
    kind=${1%% *}
    rest=${1#* }
    case $kind in
        # A setup's name, an answer an upgrade reads again (`choice <what> <answer>`):
        # nothing to take back.
        setup | choice) return 0 ;;
        userline)
            path=${rest%%"$TAB"*}
            text=${rest#*"$TAB"}
            ;;
        *) path=$rest ;;
    esac
    case $kind in
        user | group | member | daemon | agent) ;;
        completion)
            completion_owned "$path" || {
                say "  left as it is (not one of this installer's paths): $path"
                return 0
            }
            ;;
        *)
            setup_owns "$path" || {
                say "  left as it is (not one of this installer's paths): $path"
                return 0
            }
            ;;
    esac
    case $kind in
        file | completion) as_root rm -f "$path" ;;
        dir) [ ! -d "$path" ] || as_root rmdir "$path" || say "  kept (not empty): $path" ;;
        tree) as_root rm -rf "$path" ;;
        # The daemon's data being made: a `data` line follows once `writd init` made it.
        # Without one (the install stopped before), it is half made and goes whole.
        newdata) grep -qxF -- "data $path" "$MANIFEST" || as_root rm -rf "$path" ;;
        data)
            if [ "$2" = yes ]; then
                as_root rm -rf "$path"
            else
                say "  kept (the daemon's data; the uninstall deletes it once you type delete): $path"
            fi
            ;;
        userfile) as_user rm -f "$path" ;;
        userdata)
            if [ "$2" = yes ]; then
                as_user rm -f "$path"
            else
                say "  kept (it goes with the daemon's data): $path"
            fi
            ;;
        userdir) [ ! -d "$path" ] || as_user rmdir "$path" 2>/dev/null || say "  kept (not empty): $path" ;;
        userline)
            if [ "$DRY_RUN" = 1 ]; then
                say "    (you) remove from $path: $text"
            elif [ -f "$path" ]; then
                grep -vxF -- "$text" "$path" >"$path.writ-install" || true
                mv "$path.writ-install" "$path"
            fi
            ;;
        *) setup_undo "$kind" "$rest" ;;
    esac
}

main() {
    case ${1:-} in
        install) do_install ;;
        uninstall) do_uninstall ;;
        *) fail "usage: deploy/install.sh install|uninstall (make install, make uninstall)" ;;
    esac
}
