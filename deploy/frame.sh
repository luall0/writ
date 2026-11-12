# shellcheck shell=sh
# The installer's frame (sourced by install.sh): what every setup shares.
#
# - The setup: `SETUP=<name>`, or asked on a terminal, among the ones this OS has (each
#   setups/<file>.sh says in its header `# writ-setup: <name> <os> <manifest path>`).
# - The dry run: `DRY_RUN=1` lists every change and makes none.
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

# Picks the setup: SETUP, or asked on a terminal; one this OS doesn't have is refused with
# the list.
choose_setup() {
    offered=$(setups_here | cut -d' ' -f1 | tr '\n' ' ')
    [ -n "$offered" ] || fail "no setup for $OS in this build"
    if [ -z "$SETUP" ]; then
        terminal || fail "SETUP=<name> is needed without a terminal (offered on $OS: $offered)"
        # On stderr: what this function prints on stdout is the setup's file.
        say "Which setup? Offered on $OS: $offered" >&2
        printf 'Setup: ' >&2
        read -r SETUP || fail "no setup given"
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
        say "Upgrading the installed setup ($MANIFEST):"
        setup_upgrade
        return 0
    fi
    file=$(choose_setup)
    MANIFEST=$(manifest_of "$file")
    # shellcheck source=/dev/null
    . "$file"
    [ "$DRY_RUN" = 1 ] && say "Dry run: these are the changes; none is made."
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
    if [ "$PURGE" = 1 ]; then
        say "PURGE=1 deletes the daemon's data (keystore, state, ledger, audit log):"
        grep "^data \|^userdata " "$MANIFEST" | cut -d' ' -f2- | sed 's/^/  /'
        terminal || fail "PURGE=1 needs a terminal to confirm: nothing done"
        printf 'Type delete to delete it: '
        read -r typed || typed=
        [ "$typed" = delete ] || fail "not confirmed: nothing done"
        purge_answer=yes
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
    lines=$(sed '1!G;h;$!d' "$MANIFEST")
    printf '%s\n' "$lines" | while IFS= read -r line; do
        undo_line "$line" "$purge_answer"
    done
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
                say "  kept (the daemon's data; PURGE=1 deletes it): $path"
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
