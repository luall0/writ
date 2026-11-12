# writ-setup: local Darwin /Library/Application Support/Writ/install.manifest
# shellcheck shell=sh
# shellcheck disable=SC2034 # CURRENT is the frame's (the step a failure names)
#
# The `local` setup on the Mac (docs/architecture/deployment.md#local-mac): the daemon as a
# LaunchDaemon under its own role user `_writd`, isolated from yours; the agents' sockets
# reachable through the `_writ` group you join; the binaries root-owned in /opt/writ/bin;
# your ~/.writ pointed at it. Sourced by frame.sh, which gives `as_root`, `record`, `step`…

LABEL=dev.writ.writd
DAEMON_USER=_writd
SOCKETS_GROUP=_writ
PREFIX=$(sys /opt/writ)
BIN=$PREFIX/bin
PATHS_D=$(sys /etc/paths.d/writ)
DATA=$(sys /var/db/writ)
CONFIG=$DATA/writd.yaml
APP=$(sys "/Library/Application Support/Writ")
RUN=$APP/run
LOGS=$(sys /Library/Logs/Writ)
LOG=$LOGS/writd.log
PLIST=$(sys /Library/LaunchDaemons/$LABEL.plist)
WHOME=${WRIT_HOME:-$HOME/.writ}
ME=$(id -un)
BINARIES_SHIPPED="writd writ writ-sign writ-se"
# The ids the role user and the sockets' group take: the hidden system range.
ID_FIRST=450
ID_LAST=499

setup_writ() { printf '%s' "$BIN/writ"; }

setup_owns() {
    case $1 in
        "$(sys /opt)" | "$PREFIX" | "$PREFIX"/* | "$PATHS_D" | "$PLIST" | "$DATA" | "$APP"/* | "$LOGS" | "$LOGS"/*) return 0 ;;
        "$WHOME" | "$WHOME"/*) return 0 ;;
    esac
    return 1
}

setup_undo() {
    case $1 in
        user) as_root dscl . -delete "/Users/$2" ;;
        group) as_root dscl . -delete "/Groups/$2" ;;
        member) as_root dseditgroup -o edit -d "${2#* }" -t user "${2%% *}" ;;
        daemon) as_root launchctl bootout "system/$2" || say "  (the daemon was not running)" ;;
    esac
}

setup_finish_uninstall() {
    [ ! -d "$APP" ] || as_root rmdir "$APP" || say "  kept (not empty): $APP"
}

# Whether an id is free as a user id and as a group id.
id_free() {
    ! dscl . -list /Users UniqueID 2>/dev/null | awk '{print $2}' | grep -qx "$1" &&
        ! dscl . -list /Groups PrimaryGroupID 2>/dev/null | awk '{print $2}' | grep -qx "$1"
}

# The first free id in the hidden range, past $1 (none: from the start).
free_id() {
    candidate=$ID_FIRST
    while [ "$candidate" -le "$ID_LAST" ]; do
        if [ "$candidate" != "${1:-}" ] && id_free "$candidate"; then
            printf '%s' "$candidate"
            return 0
        fi
        candidate=$((candidate + 1))
    done
    fail "no free id from $ID_FIRST to $ID_LAST for $DAEMON_USER and $SOCKETS_GROUP"
}

exists() { dscl . -read "$1" >/dev/null 2>&1; }

# A directory of root's on the way to /opt/writ/bin that you could write would let an
# agent swap writd, which then runs as _writd at its next start: refused.
check_prefix() {
    [ -n "$ROOT" ] && return 0
    dir=/opt
    for part in writ bin; do
        if [ -e "$dir" ]; then
            [ -w "$dir" ] && fail "$dir can be written by you: a binary under it could be swapped (fix its owner and mode first)"
            # shellcheck disable=SC2012 # ls, not stat (its options differ by OS)
            owner=$(ls -ldn "$dir" | awk '{print $3}')
            [ "$owner" = 0 ] || fail "$dir is not root's (uid $owner): fix it first"
        fi
        dir=$dir/$part
    done
}

check_approver() {
    [ -n "${APPROVER:-}" ] || fail "APPROVER=<your approval key's .pub> is needed (its public half: who may sign)"
    [ -r "$APPROVER" ] || fail "APPROVER=$APPROVER: not a readable file"
    grep -q 'PRIVATE KEY' "$APPROVER" && fail "APPROVER=$APPROVER is a private key: give its .pub"
    case $(head -n 1 "$APPROVER") in
        ssh-* | ecdsa-* | sk-*) ;;
        *) fail "APPROVER=$APPROVER is not an SSH public key" ;;
    esac
}

# Where the HTTPS approval API's TLS key is made (M7.5): TLS_BACKEND, or asked on a
# terminal; software unless you choose this Mac's Secure Enclave. Checked before any change.
choose_tls_backend() {
    if [ -z "${TLS_BACKEND:-}" ] && terminal; then
        say "The HTTPS approval API's TLS key (HTTPS is off in this setup; the key serves it if you"
        say "turn it on later): software, or se-cryptokit (this Mac's Secure Enclave: the key never"
        say "leaves it; writ admin tls rotate --backend moves it later either way)."
        printf '%s' "TLS key backend [software]: "
        read -r TLS_BACKEND || TLS_BACKEND=
    fi
    TLS_BACKEND=${TLS_BACKEND:-software}
    case $TLS_BACKEND in
        software | se-cryptokit) ;;
        *) fail "TLS_BACKEND=$TLS_BACKEND: software or se-cryptokit" ;;
    esac
}

preflight() {
    step "Checks"
    [ -n "$ROOT" ] || [ "$(id -u)" != 0 ] || fail "run as yourself, not root: the installer asks sudo for the steps that need it"
    for b in $BINARIES_SHIPPED; do
        [ -x "$BINARIES/$b" ] || fail "$BINARIES/$b is not built (make install builds it)"
    done
    check_prefix
}

# The binaries, root-owned, signed ad hoc with the hardened runtime and a stable identifier.
install_binaries() {
    step "The binaries in $BIN (root-owned, signed with the hardened runtime)"
    for dir in "$(sys /opt)" "$PREFIX" "$BIN"; do
        if [ ! -d "$dir" ]; then
            as_root install -d -m 0755 "$dir"
            record "dir $dir"
            as_root chown root:wheel "$dir"
        fi
    done
    for b in $BINARIES_SHIPPED; do
        new=no
        [ -e "$BIN/$b" ] || new=yes
        as_root install -m 0755 "$BINARIES/$b" "$BIN/$b"
        [ "$new" = no ] || record "file $BIN/$b"
        as_root chown root:wheel "$BIN/$b"
        as_root codesign --force --sign - --options runtime --identifier "dev.writ.$b" "$BIN/$b"
    done
}

writd_yaml() {
    cat <<EOF
# writd.yaml, local mode on this Mac (written by make install; docs/operators/writd-yaml.md).
state_dir: state
policy: policy.yaml
approvers: approvers
readers: readers
keystore: { sealed: { dir: keys, boot: boot } }
transports:
  agents: [{ unix: "$RUN/agents.sock" }]
  approvals:
    ssh: [{ unix: "$RUN/approvals.sock" }]
    https: []
attestor: macos_process_chain
session_watcher: macos
notifiers: []
EOF
}

policy_yaml() {
    cat <<'EOF'
# The starting policy: no repository yet. Add keys, hosts, repos and templates with
# `writ admin` (docs/operators/policy-yaml.md).
keys: {}
upstream_hosts: {}
repos: {}
templates: {}
EOF
}

plist() {
    cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>$LABEL</string>
	<key>ProgramArguments</key>
	<array><string>$BIN/writd</string><string>run</string><string>$CONFIG</string></array>
	<key>UserName</key><string>$DAEMON_USER</string>
	<key>GroupName</key><string>$DAEMON_USER</string>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
	<key>ExitTimeOut</key><integer>330</integer>
	<key>Umask</key><integer>63</integer>
	<key>EnvironmentVariables</key><dict><key>WRIT_LOG</key><string>info</string></dict>
	<key>StandardOutPath</key><string>$LOG</string>
	<key>StandardErrorPath</key><string>$LOG</string>
</dict>
</plist>
EOF
}

setup_install() {
    check_approver
    preflight
    [ -d "$DATA" ] || choose_tls_backend

    step "The installer's own directory and manifest ($MANIFEST)"
    as_root install -d -m 0755 "$APP"
    as_root chown root:wheel "$APP"
    if [ "$DRY_RUN" != 1 ]; then
        as_root install -m 0644 /dev/null "$MANIFEST"
        as_root chown root:wheel "$MANIFEST"
    fi
    record "setup local-macos"

    # Kept data (an uninstall without PURGE): the role user made again with its uid.
    kept_uid=
    if [ -d "$DATA" ]; then
        # shellcheck disable=SC2012 # ls, not stat (its options differ by OS)
        kept_uid=$(ls -ldn "$DATA" | awk '{print $3}')
        say "  The daemon's data from before is kept: $DATA (uid $kept_uid)"
    fi
    step "The role user $DAEMON_USER and the sockets' group $SOCKETS_GROUP (you in it)"
    exists "/Users/$DAEMON_USER" && fail "$DAEMON_USER exists already and isn't this install's (an earlier install? make uninstall first)"
    exists "/Groups/$SOCKETS_GROUP" && fail "$SOCKETS_GROUP exists already and isn't this install's"
    if [ -n "$kept_uid" ]; then
        id_free "$kept_uid" || fail "uid $kept_uid (the kept data's) is taken"
        daemon_id=$kept_uid
    else
        daemon_id=$(free_id)
    fi
    group_id=$(free_id "$daemon_id")
    as_root dscl . -create "/Groups/$DAEMON_USER"
    record "group $DAEMON_USER"
    as_root dscl . -create "/Groups/$DAEMON_USER" PrimaryGroupID "$daemon_id"
    as_root dscl . -create "/Groups/$DAEMON_USER" RealName "Writ daemon"
    as_root dscl . -create "/Groups/$DAEMON_USER" Password '*'
    as_root dscl . -create "/Users/$DAEMON_USER"
    record "user $DAEMON_USER"
    as_root dscl . -create "/Users/$DAEMON_USER" UniqueID "$daemon_id"
    as_root dscl . -create "/Users/$DAEMON_USER" PrimaryGroupID "$daemon_id"
    as_root dscl . -create "/Users/$DAEMON_USER" UserShell /usr/bin/false
    as_root dscl . -create "/Users/$DAEMON_USER" NFSHomeDirectory /var/db/writ
    as_root dscl . -create "/Users/$DAEMON_USER" RealName "Writ daemon"
    as_root dscl . -create "/Users/$DAEMON_USER" Password '*'
    as_root dscl . -create "/Users/$DAEMON_USER" IsHidden 1
    as_root dscl . -create "/Groups/$SOCKETS_GROUP"
    record "group $SOCKETS_GROUP"
    as_root dscl . -create "/Groups/$SOCKETS_GROUP" PrimaryGroupID "$group_id"
    as_root dscl . -create "/Groups/$SOCKETS_GROUP" RealName "Writ agents' sockets"
    as_root dscl . -create "/Groups/$SOCKETS_GROUP" Password '*'
    as_root dseditgroup -o edit -a "$ME" -t user "$SOCKETS_GROUP"
    record "member $SOCKETS_GROUP $ME"

    install_binaries
    step "On your PATH: $PATHS_D"
    put_root "$PATHS_D" 0644 root:wheel "/opt/writ/bin"
    record "file $PATHS_D"

    step "The sockets' directory $RUN (${DAEMON_USER}:$SOCKETS_GROUP 0750) and the log $LOG"
    as_root install -d -m 0750 "$RUN"
    record "tree $RUN"
    as_root chown "$DAEMON_USER:$SOCKETS_GROUP" "$RUN"
    as_root install -d -m 0750 "$LOGS"
    record "tree $LOGS"
    as_root chown "$DAEMON_USER:$SOCKETS_GROUP" "$LOGS"
    as_root install -m 0640 /dev/null "$LOG"
    as_root chown "$DAEMON_USER:$SOCKETS_GROUP" "$LOG"

    step "Your Writ home $WHOME"
    if [ ! -d "$WHOME" ]; then
        as_user mkdir -m 0700 "$WHOME"
        record "userdir $WHOME"
    elif [ -n "$kept_uid" ]; then
        # Kept by an earlier uninstall with the reader key: that install's (removed empty only).
        record "userdir $WHOME"
    fi
    reader_new=no
    [ -e "$WHOME/reader" ] || reader_new=yes
    reader_line="(the line writ reader prints)"
    if [ "$DRY_RUN" = 1 ]; then
        as_user "$BIN/writ" reader "writ-local-$ME"
    else
        reader_line=$(WRIT_HOME=$WHOME "$BIN/writ" reader "writ-local-$ME")
    fi
    # Kept with the daemon's data: its public half is in the kept `readers` (a reader key
    # kept by an earlier uninstall is that install's).
    if [ "$reader_new" = yes ] || [ -n "$kept_uid" ]; then
        record "userdata $WHOME/reader"
    fi

    if [ -n "$kept_uid" ]; then
        # This install's again: an uninstall keeps it, PURGE=1 deletes it.
        record "data $DATA"
    else
        step "The daemon's directory $DATA (${DAEMON_USER}, 0700): its configuration and the starting policy"
        as_root install -d -m 0700 "$DATA"
        record "data $DATA"
        as_root chown "$DAEMON_USER:$DAEMON_USER" "$DATA"
        put_root "$CONFIG" 0644 root:wheel "$(writd_yaml)"
        put_root "$DATA/policy.yaml" 0644 "$DAEMON_USER:$DAEMON_USER" "$(policy_yaml)"
        put_root "$DATA/approvers" 0644 "$DAEMON_USER:$DAEMON_USER" "approver $(head -n 1 "$APPROVER")"
        put_root "$DATA/readers" 0644 "$DAEMON_USER:$DAEMON_USER" "$reader_line"
        step "The keystore (writd init, as $DAEMON_USER): choose its passphrase"
        as_daemon "$DAEMON_USER" "$BIN/writd" init "$CONFIG" --tls-backend "$TLS_BACKEND"
    fi

    step "The LaunchDaemon $LABEL ($PLIST), started"
    put_root "$PLIST" 0644 root:wheel "$(plist)"
    record "file $PLIST"
    as_root launchctl bootstrap system "$PLIST"
    record "daemon $LABEL"

    step "Your client pointed at it: the host key pinned, the endpoints set"
    host_key="(the daemon's host key)"
    if [ "$DRY_RUN" != 1 ]; then
        host_key=$(as_daemon "$DAEMON_USER" "$BIN/writd" host-key "$CONFIG")
    else
        as_daemon "$DAEMON_USER" "$BIN/writd" host-key "$CONFIG"
    fi
    pin="writ-local $host_key"
    if [ -e "$WHOME/known_hosts" ]; then
        if [ "$DRY_RUN" = 1 ]; then
            say "    (you) add to $WHOME/known_hosts: $pin"
        elif ! grep -qxF -- "$pin" "$WHOME/known_hosts"; then
            printf '%s\n' "$pin" >>"$WHOME/known_hosts"
            record "userline $WHOME/known_hosts$TAB$pin"
        fi
    else
        put_user "$WHOME/known_hosts" "$pin"
        record "userfile $WHOME/known_hosts"
    fi
    if [ -e "$WHOME/config" ]; then
        say "  $WHOME/config is kept as it is: check url and approval_url point at $RUN"
    else
        put_user "$WHOME/config" "# Written by make install: the local daemon.
url = unix:$RUN/agents.sock
approval_url = unix:$RUN/approvals.sock"
        record "userfile $WHOME/config"
    fi
    if [ ! -e "$WHOME/approver.pub" ]; then
        if [ "$DRY_RUN" = 1 ]; then
            say "    (you) copy $APPROVER to $WHOME/approver.pub"
        else
            cp "$APPROVER" "$WHOME/approver.pub"
        fi
        record "userfile $WHOME/approver.pub"
    fi
    CURRENT=
    [ "$DRY_RUN" = 1 ] && return 0
    say ""
    say "Installed. What is left:"
    say "  1. Open a new terminal (for /opt/writ/bin on your PATH)."
    say "  2. writ unseal (the passphrase you chose, then Touch ID)."
    say "  3. writ admin key/host/repo/template add, then writ init <repo> in a clone."
    say "  4. Start each agent with writ run -- <agent>."
}

setup_upgrade() {
    preflight
    old=$(cksum <"$BIN/writ" 2>/dev/null || printf none)
    step "The daemon stopped in order (SIGTERM: what is in flight finishes)"
    as_root launchctl bootout "system/$LABEL" || say "  (it was not running)"
    install_binaries
    step "The daemon started again: the keystore, state, configuration and pins kept"
    as_root launchctl bootstrap system "$PLIST"
    CURRENT=
    [ "$DRY_RUN" = 1 ] && return 0
    say "Upgraded. writ unseal opens it again."
    new=$(cksum <"$BIN/writ")
    [ "$old" = "$new" ] || say "writ changed: writ skill update --all rewrites the agent skill in every repository it wired."
}
