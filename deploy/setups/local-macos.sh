# writ-setup: local Darwin /Library/Application Support/Writ/install.manifest
# writ-setup-about: the daemon on this Mac, under its own user, out of your reach; your agents run here
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
BINARIES_SHIPPED="writd writ writ-sign writ-se writ-popup"
# The approval popup (M7.8): writ-popup in your session, started at login.
POPUP_LABEL=dev.writ.popup
POPUP_PLIST=$HOME/Library/LaunchAgents/$POPUP_LABEL.plist
SECRETIVE_SOCKET=$HOME/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh
# The agent the popup signs through when none is given: the one your terminal uses
# (SSH_AUTH_SOCK, as writ sign does), else Secretive's on this Mac.
DEFAULT_AGENT=${SSH_AUTH_SOCK:-$SECRETIVE_SOCKET}
# The ids the role user and the sockets' group take: the hidden system range.
ID_FIRST=450
ID_LAST=499

setup_writ() { printf '%s' "$BIN/writ"; }

setup_owns() {
    case $1 in
        "$(sys /opt)" | "$PREFIX" | "$PREFIX"/* | "$PATHS_D" | "$PLIST" | "$DATA" | "$APP"/* | "$LOGS" | "$LOGS"/*) return 0 ;;
        "$WHOME" | "$WHOME"/*) return 0 ;;
        "$HOME/Library" | "$HOME/Library/LaunchAgents" | "$POPUP_PLIST") return 0 ;;
    esac
    return 1
}

setup_undo() {
    case $1 in
        user) as_root dscl . -delete "/Users/$2" ;;
        group) as_root dscl . -delete "/Groups/$2" ;;
        member) as_root dseditgroup -o edit -d "${2#* }" -t user "${2%% *}" ;;
        daemon) as_root launchctl bootout "system/$2" || say "  (the daemon was not running)" ;;
        agent) as_user launchctl bootout "gui/$(id -u)/$2" || say "  (the popup was not running)" ;;
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

# The setup's own questions, after the frame's (the setup, the approval key): where the TLS
# key, the SSH CA's key and the first agent signing key live; what opens the keystore (a
# passphrase, or the Secure Enclave with an offline recovery key); and, with everything on the
# Secure Enclave, whether the daemon starts without you (auto-unseal). With the daemon's data kept from before, its
# keystore and policy are kept: nothing more to ask.
setup_questions() {
    TLS_BACKEND=${TLS_BACKEND:-}
    CA_BACKEND=${CA_BACKEND:-}
    AGENT_BACKEND=${AGENT_BACKEND:-}
    UNSEAL=${UNSEAL:-}
    RECOVERY=${RECOVERY:-}
    AUTO_UNSEAL=${AUTO_UNSEAL:-}
    if [ -d "$DATA" ]; then
        approver_kept
        popup_questions
        return 0
    fi
    choose_approver
    if [ -z "$TLS_BACKEND" ] && terminal; then
        say ""
        say "The HTTPS approval API's key. This setup approves over a local socket, so HTTPS is"
        say "off; the key is made anyway and serves it if you turn it on later."
        say "  software: in the daemon's sealed keystore"
        say "  se-cryptokit: in this Mac's Secure Enclave, which makes it and never lets it out"
        say "writ admin tls rotate --backend moves it later either way."
    fi
    TLS_BACKEND=$(choose_one TLS_BACKEND "$TLS_BACKEND" "TLS key" software software se-cryptokit)
    if [ -z "$CA_BACKEND" ] && terminal; then
        say ""
        say "The daemon's SSH certificate authority: it signs each lease's certificate, the one"
        say "your agents connect with."
        say "  software: an Ed25519 key in the daemon's sealed keystore"
        say "  se-cryptokit: a P-256 key in this Mac's Secure Enclave, never out of it (needed to"
        say "  start the daemon without you, auto-unseal)"
    fi
    CA_BACKEND=$(choose_one CA_BACKEND "$CA_BACKEND" "SSH CA key" software software se-cryptokit)
    if [ -z "$AGENT_BACKEND" ] && terminal; then
        say ""
        say "Your agents' first commit signing key, agent-01: it signs every commit they make"
        say "(you register its public half on your remote)."
        say "  software: an Ed25519 key in the daemon's sealed keystore"
        say "  se-cryptokit: a P-256 key in this Mac's Secure Enclave, never out of it"
        say "writ admin key rotate --backend moves it later; writ admin key add makes more."
    fi
    AGENT_BACKEND=$(choose_one AGENT_BACKEND "$AGENT_BACKEND" "Agent signing key" software software se-cryptokit)
    keystore_questions
    popup_questions
}

# The approval popup (M7.8): whether it starts at login, and the agent socket it signs
# through (your approval key's: DEFAULT_AGENT unless given).
popup_questions() {
    POPUP=${POPUP:-}
    APPROVAL_AGENT=${APPROVAL_AGENT:-}
    if [ -z "$POPUP" ] && terminal; then
        say ""
        say "The approval popup: a window in front of every app, full-screen ones too, when a"
        say "ticket waits for your signature, with the whole ticket, Sign and Decline. It signs"
        say "as writ sign does (your approval key, through its agent). Started at login in your"
        say "session."
    fi
    POPUP=$(choose_one POPUP "$POPUP" "Approval popup" yes yes no)
    if [ "$POPUP" = no ]; then
        [ -z "$APPROVAL_AGENT" ] || fail "APPROVAL_AGENT is for POPUP=yes (writ sign reads WRIT_APPROVAL_AGENT)"
        return 0
    fi
    if [ -z "$APPROVAL_AGENT" ] && terminal; then
        say ""
        say "The socket of the ssh-agent holding your approval key, which the popup signs through"
        say "(Enter: the one this terminal uses)."
        APPROVAL_AGENT=$(expand_home "$(ask "Approval key's agent socket" "$DEFAULT_AGENT")")
    fi
    APPROVAL_AGENT=${APPROVAL_AGENT:-$DEFAULT_AGENT}
    check_approval_agent
}

# APPROVAL_AGENT, checked: an absolute path, and none of what the LaunchAgent's XML would
# read otherwise.
check_approval_agent() {
    case $APPROVAL_AGENT in
        /*) ;;
        *) fail "APPROVAL_AGENT=$APPROVAL_AGENT: an absolute path (the approval key's agent socket)" ;;
    esac
    case $APPROVAL_AGENT in
        *[\<\>\&\"\']* | *"$TAB"*) fail "APPROVAL_AGENT=$APPROVAL_AGENT: no < > & \" ' or tab in the path" ;;
    esac
}

popup_said() {
    case $POPUP in
        yes) say "  Approval popup: at login, signing through $APPROVAL_AGENT" ;;
        *) say "  Approval popup: not started (writ-popup is installed; writ sign in a terminal)" ;;
    esac
}

# What opens the keystore, the recovery key, and auto-unseal (M7.6).
keystore_questions() {
    if [ -z "$UNSEAL" ] && terminal; then
        say ""
        say "What opens the daemon's keystore, which holds every secret, after each start:"
        say "  passphrase: one you choose now, typed at writ unseal with your approval"
        say "  se-cryptokit: this Mac's Secure Enclave: writ unseal is your approval alone. It needs a"
        say "  recovery key, kept offline, that opens everything if this Mac is lost"
    fi
    UNSEAL=$(choose_one UNSEAL "$UNSEAL" "Keystore opened by" passphrase passphrase se-cryptokit)
    if [ "$UNSEAL" = se-cryptokit ]; then
        if [ -z "$RECOVERY" ] && terminal; then
            say ""
            say "The recovery key: paste the age1... line writ recovery new printed (best run on a"
            say "machine that isn't online), or press Enter to make one now, shown once."
            RECOVERY=$(ask "Recovery key's recipient (age1...)" "")
            if [ -z "$RECOVERY" ]; then
                made=$("$BINARIES/writ" recovery new) || fail "writ recovery new failed"
                say "$made"
                RECOVERY=$(printf '%s\n' "$made" | sed -n 's/^ *writ admin recipient add recovery recipient=//p')
                confirm "Is the recovery key written down, somewhere safe and offline?" ||
                    fail "write the recovery key down first (nothing was changed): run the install again"
            fi
        fi
        case $RECOVERY in
            age1*) ;;
            *) fail "RECOVERY=$RECOVERY: the recovery key's age1... recipient (writ recovery new)" ;;
        esac
    else
        [ -z "$RECOVERY" ] || fail "RECOVERY is for UNSEAL=se-cryptokit (a passphrase keystore adds one later: writ admin recipient add)"
    fi
    if [ "$UNSEAL" = se-cryptokit ] && [ "$CA_BACKEND" = se-cryptokit ] && [ "$AGENT_BACKEND" = se-cryptokit ]; then
        if [ -z "$AUTO_UNSEAL" ] && terminal; then
            say ""
            say "Auto-unseal: the daemon opens itself after every start, with no one. Anyone who can"
            say "restart it, or takes this Mac, gets it running. Leases still need your signature,"
            say "and every automatic start is logged and notified. writ admin auto-unseal off undoes it."
        fi
        AUTO_UNSEAL=$(choose_one AUTO_UNSEAL "$AUTO_UNSEAL" "Start without you (auto-unseal)" no no yes)
    else
        [ "${AUTO_UNSEAL:-no}" = no ] ||
            fail "AUTO_UNSEAL=yes needs CA_BACKEND, AGENT_BACKEND and UNSEAL all se-cryptokit"
        AUTO_UNSEAL=no
        if terminal; then
            say ""
            say "Auto-unseal (the daemon starting without you) needs the SSH CA, agent-01 and the"
            say "keystore on the Secure Enclave: not offered with these answers. Later, writ admin"
            say "auto-unseal status says what is missing."
        fi
    fi
}

# The setup's answers, for the summary before the go.
setup_answers() {
    if [ -d "$DATA" ]; then
        say "  The daemon's data kept from before: its keystore and policy are used again"
        popup_said
        return 0
    fi
    say "  TLS key: $TLS_BACKEND"
    say "  SSH CA key: $CA_BACKEND"
    case $UNSEAL in
        se-cryptokit) say "  Keystore opened by: the Secure Enclave, no passphrase; recovery key $RECOVERY" ;;
        *) say "  Keystore opened by: a passphrase" ;;
    esac
    say "  Auto-unseal: $AUTO_UNSEAL"
    say "  Agent signing key agent-01: $(agent_key_said)"
    popup_said
}

# agent-01 as the starting policy declares it, and as the summary says it.
agent_key_yaml() {
    case $AGENT_BACKEND in
        se-cryptokit) printf '%s' "{ use: signing, format: ssh, algorithm: p256, backend: se-cryptokit }" ;;
        *) printf '%s' "{ use: signing, format: ssh, algorithm: ed25519 }" ;;
    esac
}
agent_key_said() {
    case $AGENT_BACKEND in
        se-cryptokit) printf '%s' "P-256, in the Secure Enclave" ;;
        *) printf '%s' "Ed25519, in software" ;;
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
    cat <<EOF
# The starting policy: your agents' first signing key, no repository yet. Add keys, hosts,
# repos and templates with \`writ admin\` (docs/operators/policy-yaml.md).
format: 2
keys:
  agent-01: $(agent_key_yaml)
upstream_hosts: {}
$(recipients_yaml)
repos: {}
templates: {}
$(unseal_yaml)
EOF
}

# The keystore's recipients in the starting policy, for UNSEAL=se-cryptokit.
recipients_yaml() {
    [ "$UNSEAL" = se-cryptokit ] || return 0
    printf 'recipients:\n  recovery: { recipient: %s }\n  se-01: { backend: se-cryptokit }\n' "$RECOVERY"
}

# Auto-unseal in the starting policy, for AUTO_UNSEAL=yes.
unseal_yaml() {
    [ "$AUTO_UNSEAL" = yes ] || return 0
    printf 'unseal: auto\n'
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

# The popup's LaunchAgent: writ-popup in your GUI session, its writ given your Writ home and
# the approval key's agent.
popup_plist() {
    cat <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>$POPUP_LABEL</string>
	<key>ProgramArguments</key>
	<array><string>$BIN/writ-popup</string></array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>WRIT_HOME</key><string>$WHOME</string>
		<key>WRIT_APPROVAL_AGENT</key><string>$APPROVAL_AGENT</string>
	</dict>
	<key>LimitLoadToSessionType</key><string>Aqua</string>
	<key>ProcessType</key><string>Interactive</string>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
</dict>
</plist>
PLIST
}

# The approval popup started at login: its LaunchAgent written and started in your session.
install_popup() {
    step "The approval popup ($POPUP_PLIST), started in your session"
    for dir in "$HOME/Library" "$HOME/Library/LaunchAgents"; do
        if [ ! -d "$dir" ]; then
            as_user mkdir -m 0755 "$dir"
            record "userdir $dir"
        fi
    done
    put_user "$POPUP_PLIST" "$(popup_plist)"
    record "userfile $POPUP_PLIST"
    as_user launchctl bootstrap "gui/$(id -u)" "$POPUP_PLIST"
    record "agent $POPUP_LABEL"
}

# Whether this install started the popup (its manifest line).
popup_installed() {
    [ -f "$MANIFEST" ] && grep -qxF -- "agent $POPUP_LABEL" "$MANIFEST"
}

setup_install() {
    preflight

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
    install_completions "$BIN/writ"
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
        # Half made until writd init has made the keystore: an uninstall takes it back whole.
        record "newdata $DATA"
        as_root chown "$DAEMON_USER:$DAEMON_USER" "$DATA"
        put_root "$CONFIG" 0644 root:wheel "$(writd_yaml)"
        put_root "$DATA/policy.yaml" 0644 "$DAEMON_USER:$DAEMON_USER" "$(policy_yaml)"
        put_root "$DATA/approvers" 0644 "$DAEMON_USER:$DAEMON_USER" "approver $APPROVER_KEY"
        put_root "$DATA/readers" 0644 "$DAEMON_USER:$DAEMON_USER" "$reader_line"
        case $UNSEAL in
            se-cryptokit) step "The keystore (writd init, as $DAEMON_USER): opened by the Secure Enclave, no passphrase" ;;
            *) step "The keystore (writd init, as $DAEMON_USER): choose its passphrase" ;;
        esac
        as_daemon "$DAEMON_USER" "$BIN/writd" init "$CONFIG" --tls-backend "$TLS_BACKEND" --ca-backend "$CA_BACKEND"
        # Made: an uninstall keeps it from now on (PURGE=1 deletes it).
        record "data $DATA"
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
    put_approver_pub
    if [ "$POPUP" = no ]; then
        # Remembered: an upgrade doesn't start the popup you declined.
        record "choice popup no"
    else
        install_popup
    fi
    CURRENT=
    [ "$DRY_RUN" = 1 ] && return 0
    say ""
    say "Installed. What is left:"
    say "  1. Open a new terminal (for /opt/writ/bin on your PATH)."
    case $AUTO_UNSEAL:$UNSEAL in
        yes:*) say "  2. Nothing to unseal: the daemon opened itself (auto-unseal), and will at each start." ;;
        *:se-cryptokit) say "  2. writ unseal (your approval: the Secure Enclave opens the keystore)." ;;
        *) say "  2. writ unseal (the passphrase you chose, then your approval)." ;;
    esac
    say "  3. writ admin key/host/repo/template add, then writ init <repo> in a clone."
    say "  4. Start each agent with writ run -- <agent>."
    [ "$POPUP" = no ] || say "  A ticket waiting for you comes up in the approval popup (writ sign in a terminal too)."
}

setup_upgrade() {
    preflight
    old=$(cksum <"$BIN/writ" 2>/dev/null || printf none)
    step "The daemon stopped in order (SIGTERM: what is in flight finishes)"
    as_root launchctl bootout "system/$LABEL" || say "  (it was not running)"
    if popup_installed; then
        step "The approval popup stopped"
        as_user launchctl bootout "gui/$(id -u)/$POPUP_LABEL" || say "  (it was not running)"
    fi
    install_binaries
    install_completions "$BIN/writ"
    step "The LaunchDaemon's plist written again ($PLIST): this version's settings"
    put_root "$PLIST" 0644 root:wheel "$(plist)"
    step "The daemon started again: the keystore, state, configuration and pins kept"
    as_root launchctl bootstrap system "$PLIST"
    if popup_installed; then
        step "The approval popup started again ($POPUP_PLIST kept: your answers)"
        as_user launchctl bootstrap "gui/$(id -u)" "$POPUP_PLIST"
    elif [ "${POPUP:-yes}" != no ] && ! grep -qxF -- "choice popup no" "$MANIFEST"; then
        # An install from before M7.8: the popup added, through DEFAULT_AGENT unless
        # APPROVAL_AGENT says otherwise (POPUP=no, or the install's no, leaves it out).
        POPUP=yes
        APPROVAL_AGENT=${APPROVAL_AGENT:-$DEFAULT_AGENT}
        check_approval_agent
        install_popup
    fi
    CURRENT=
    [ "$DRY_RUN" = 1 ] && return 0
    after_upgrade "$BIN/writ"
    new=$(cksum <"$BIN/writ")
    [ "$old" = "$new" ] || upgraded_writ
}
