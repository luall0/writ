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

# ask <label> <default>: one answer from the terminal (the default on Enter), on stdout; the
# prompt on stderr.
ask() {
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
            value=$(ask "$label" "$default")
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

# What is wrong with <path> as an approval key's public half, or nothing.
approver_problem() {
    if [ -z "$1" ]; then
        printf 'no path given'
    elif [ ! -r "$1" ]; then
        printf '%s: not a readable file' "$1"
    elif grep -q 'PRIVATE KEY' "$1"; then
        printf '%s is a private key: give its .pub' "$1"
    else
        case $(head -n 1 "$1") in
            ssh-* | ecdsa-* | sk-*) ;;
            *) printf '%s is not an SSH public key' "$1" ;;
        esac
    fi
}

# APPROVER: asked on a terminal (again until it is an SSH public key), else the variable.
choose_approver() {
    if [ -z "${APPROVER:-}" ] && terminal; then
        say "Your approval key: the key whose signature turns an agent's ticket into a lease (a" >&2
        say "Secretive key on a Mac, say). Give the path to its public half, the .pub: the" >&2
        say "installer reads that file alone, and Writ never uses your other keys." >&2
        while :; do
            APPROVER=$(expand_home "$(ask "Approval key (.pub)" "")")
            problem=$(approver_problem "$APPROVER")
            [ -z "$problem" ] && break
            say "  $problem" >&2
        done
    fi
    [ -n "${APPROVER:-}" ] || fail "APPROVER=<your approval key's .pub> is needed without a terminal (its public half: who may sign)"
    problem=$(approver_problem "$APPROVER")
    [ -z "$problem" ] || fail "APPROVER=$problem"
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

# put_root <path> <mode> <owner> <content>: a file written whole as root (through a
# temporary file of yours), with its mode and owner.
put_root() {
    if [ "$DRY_RUN" = 1 ]; then
        printf '    (root) write %s (%s, %s):\n' "$1" "$2" "$3"
        printf '%s\n' "$4" | sed 's/^/        /'
        return 0
    fi
    put_tmp=$(mktemp)
    printf '%s\n' "$4" >"$put_tmp"
    as_root install -m "$2" "$put_tmp" "$1"
    as_root chown "$3" "$1"
    rm -f "$put_tmp"
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
        SETUP=$(ask "Setup" "${offered%% *}")
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
        say "  Approval key: $APPROVER"
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
    [ -f "$1" ] && [ ! -L "$1" ] || fail "$1 is not a regular file: nothing done"
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
        printf 'Type delete to delete it, Enter keeps it: '
        read -r typed || typed=
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
    [ -f "${WRIT_HOME:-$HOME/.writ}/repos" ] && [ -x "$writ" ] || {
        printf none
        return 0
    }
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
    printf 'Take Writ out of them too? [y/N] ' >&2
    read -r answer || answer=
    case $answer in
        y | Y | yes) printf undo ;;
        *)
            say "Kept wired." >&2
            printf keep
            ;;
    esac
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
        setup) return 0 ;;
        userline)
            path=${rest%%"$TAB"*}
            text=${rest#*"$TAB"}
            ;;
        *) path=$rest ;;
    esac
    case $kind in
        setup | user | group | member | daemon) ;;
        *)
            setup_owns "$path" || {
                say "  left as it is (not one of this installer's paths): $path"
                return 0
            }
            ;;
    esac
    case $kind in
        file) as_root rm -f "$path" ;;
        dir) [ ! -d "$path" ] || as_root rmdir "$path" || say "  kept (not empty): $path" ;;
        tree) as_root rm -rf "$path" ;;
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
