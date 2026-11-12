# writ-setup: local Linux /etc/writ/install.manifest
# shellcheck shell=sh
# shellcheck disable=SC2034 # CURRENT is the frame's (the step a failure names)
#
# The `local` setup on a Linux workstation (docs/architecture/deployment.md#local-linux): the
# daemon as a systemd service under its own system user `writd`, isolated from yours, with
# CAP_SYS_PTRACE for its process reader alone; the agents' sockets reachable through the
# `writ` group you join; the binaries root-owned in /usr/local/bin; your ~/.writ pointed at
# it. Sourced by frame.sh, which gives `as_root`, `record`, `step`…

UNIT=writd
DAEMON_USER=writd
SOCKETS_GROUP=writ
BIN=$(sys /usr/local/bin)
ETC=$(sys /etc/writ)
CONFIG=$ETC/writd.yaml
DATA=$(sys /var/lib/writ)
# The sockets' directory, made by systemd at each start (RuntimeDirectory): not the
# installer's, never in the manifest.
RUN=/run/writ
UNIT_FILE=$(sys /etc/systemd/system/$UNIT.service)
WHOME=${WRIT_HOME:-$HOME/.writ}
ME=$(id -un)
BINARIES_SHIPPED="writd writ writ-sign"

setup_writ() { printf '%s' "$BIN/writ"; }

setup_owns() {
    case $1 in
        "$BIN/writd" | "$BIN/writ" | "$BIN/writ-sign" | "$ETC" | "$ETC"/* | "$DATA" | "$UNIT_FILE") return 0 ;;
        "$WHOME" | "$WHOME"/*) return 0 ;;
    esac
    return 1
}

setup_undo() {
    case $1 in
        # userdel takes the user's own group (useradd --user-group made it) with it.
        user) as_root userdel "$2" ;;
        group) as_root groupdel "$2" ;;
        member) as_root gpasswd -d "${2#* }" "${2%% *}" ;;
        daemon) as_root systemctl disable --now "$2.service" || say "  (the daemon was not running)" ;;
    esac
}

setup_finish_uninstall() {
    as_root systemctl daemon-reload
    [ ! -d "$ETC" ] || as_root rmdir "$ETC" || say "  kept (not empty): $ETC"
}

exists_user() { getent passwd "$1" >/dev/null 2>&1; }
exists_group() { getent group "$1" >/dev/null 2>&1; }

# A directory of root's on the way to /usr/local/bin that you could write would let an
# agent swap writd, which then runs as writd (with CAP_SYS_PTRACE) at its next start: refused.
check_prefix() {
    [ -n "$ROOT" ] && return 0
    for dir in /usr /usr/local /usr/local/bin /etc /etc/systemd/system; do
        [ -e "$dir" ] || continue
        [ -w "$dir" ] && fail "$dir can be written by you: a file under it could be swapped (fix its owner and mode first)"
        # shellcheck disable=SC2012 # ls, not stat (its options differ by OS)
        owner=$(ls -ldn "$dir" | awk '{print $3}')
        [ "$owner" = 0 ] || fail "$dir is not root's (uid $owner): fix it first"
    done
    return 0
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

preflight() {
    step "Checks"
    [ -n "$ROOT" ] || [ "$(id -u)" != 0 ] || fail "run as yourself, not root: the installer asks sudo for the steps that need it"
    for b in $BINARIES_SHIPPED; do
        [ -x "$BINARIES/$b" ] || fail "$BINARIES/$b is not built (make install builds it)"
    done
    for tool in systemctl useradd groupadd gpasswd getent; do
        command -v "$tool" >/dev/null 2>&1 || fail "$tool is needed (a systemd system with the shadow tools)"
    done
    check_prefix
}

# The binaries, root-owned.
install_binaries() {
    step "The binaries in $BIN (root-owned)"
    for b in $BINARIES_SHIPPED; do
        new=no
        [ -e "$BIN/$b" ] || new=yes
        as_root install -m 0755 "$BINARIES/$b" "$BIN/$b"
        [ "$new" = no ] || record "file $BIN/$b"
        as_root chown root:root "$BIN/$b"
    done
}

writd_yaml() {
    cat <<EOF
# writd.yaml, local mode on this machine (written by make install; docs/operators/writd-yaml.md).
state_dir: $DATA/state
policy: $DATA/policy.yaml
approvers: $DATA/approvers
readers: $DATA/readers
keystore: { sealed: { dir: $DATA/keys, boot: $DATA/boot } }
transports:
  agents: [{ unix: $RUN/agents.sock }]
  approvals:
    ssh: [{ unix: $RUN/approvals.sock }]
    https: []
attestor: linux_process_chain
session_watcher: linux
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

# The systemd unit (docs/architecture/deployment.md#local-linux). CAP_SYS_PTRACE is the only
# capability the service can have, and only its process reader keeps it: writd drops it
# before it reads a secret. ptrace itself and process_vm_* are refused by the system call
# filter; the agents' processes stay visible (no ProtectProc=invisible, no PrivatePIDs).
unit() {
    cat <<EOF
# Written by make install (docs/architecture/deployment.md#local-linux).
[Unit]
Description=Writ daemon (local mode)
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=$DAEMON_USER
Group=$SOCKETS_GROUP
ExecStart=/usr/local/bin/writd run /etc/writ/writd.yaml
Environment=WRIT_LOG=info
Restart=on-failure
# The orderly stop's waits (mirrors.timeout and its margin); the process reader outlives them.
TimeoutStopSec=330
KillMode=mixed
UMask=0077
RuntimeDirectory=writ
RuntimeDirectoryMode=0750
ReadWritePaths=/var/lib/writ
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_SYS_PTRACE
AmbientCapabilities=CAP_SYS_PTRACE
SystemCallFilter=@system-service
SystemCallFilter=~ptrace process_vm_readv process_vm_writev
SystemCallArchitectures=native
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LimitMEMLOCK=infinity
LimitCORE=0

[Install]
WantedBy=multi-user.target
EOF
}

setup_install() {
    check_approver
    preflight

    step "The installer's own directory and manifest ($MANIFEST)"
    if [ ! -d "$ETC" ]; then
        as_root install -d -m 0755 "$ETC"
        as_root chown root:root "$ETC"
    fi
    if [ "$DRY_RUN" != 1 ]; then
        as_root install -m 0644 /dev/null "$MANIFEST"
        as_root chown root:root "$MANIFEST"
    fi
    # $ETC holds the manifest: taken back after it, by setup_finish_uninstall.
    record "setup local-linux"

    # Kept data (an uninstall without PURGE): the system user made again with its uid.
    kept_uid=
    if [ -d "$DATA" ]; then
        # shellcheck disable=SC2012 # ls, not stat (its options differ by OS)
        kept_uid=$(ls -ldn "$DATA" | awk '{print $3}')
        say "  The daemon's data from before is kept: $DATA (uid $kept_uid)"
    fi
    step "The system user $DAEMON_USER and the sockets' group $SOCKETS_GROUP (you in it)"
    exists_user "$DAEMON_USER" && fail "$DAEMON_USER exists already and isn't this install's (an earlier install? make uninstall first)"
    exists_group "$SOCKETS_GROUP" && fail "$SOCKETS_GROUP exists already and isn't this install's"
    uid_option=
    if [ -n "$kept_uid" ]; then
        getent passwd "$kept_uid" >/dev/null 2>&1 && fail "uid $kept_uid (the kept data's) is taken"
        uid_option="--uid $kept_uid"
    fi
    # shellcheck disable=SC2086 # the uid option is one word or none
    as_root useradd --system --user-group $uid_option --no-create-home --home-dir /var/lib/writ \
        --shell /usr/sbin/nologin --comment "Writ daemon" "$DAEMON_USER"
    record "user $DAEMON_USER"
    as_root groupadd --system "$SOCKETS_GROUP"
    record "group $SOCKETS_GROUP"
    as_root gpasswd -a "$ME" "$SOCKETS_GROUP"
    record "member $SOCKETS_GROUP $ME"

    install_binaries

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

    step "The daemon's configuration $CONFIG (root's)"
    put_root "$CONFIG" 0644 root:root "$(writd_yaml)"
    record "file $CONFIG"
    if [ -n "$kept_uid" ]; then
        # This install's again: an uninstall keeps it, PURGE=1 deletes it.
        record "data $DATA"
    else
        step "The daemon's directory $DATA (${DAEMON_USER}, 0700): the starting policy"
        as_root install -d -m 0700 "$DATA"
        record "data $DATA"
        as_root chown "$DAEMON_USER:$DAEMON_USER" "$DATA"
        put_root "$DATA/policy.yaml" 0644 "$DAEMON_USER:$DAEMON_USER" "$(policy_yaml)"
        put_root "$DATA/approvers" 0644 "$DAEMON_USER:$DAEMON_USER" "approver $(head -n 1 "$APPROVER")"
        put_root "$DATA/readers" 0644 "$DAEMON_USER:$DAEMON_USER" "$reader_line"
        step "The keystore (writd init, as $DAEMON_USER): choose its passphrase"
        as_daemon "$DAEMON_USER" "$BIN/writd" init "$CONFIG"
    fi

    step "The systemd unit $UNIT ($UNIT_FILE), enabled and started"
    put_root "$UNIT_FILE" 0644 root:root "$(unit)"
    record "file $UNIT_FILE"
    as_root systemctl daemon-reload
    as_root systemctl enable --now "$UNIT.service"
    record "daemon $UNIT"

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
    say "  1. Log in again (or run newgrp $SOCKETS_GROUP): your membership of $SOCKETS_GROUP, which"
    say "     opens the daemon's sockets, applies to new logins only."
    say "  2. writ unseal (the passphrase you chose, then your approval key)."
    say "  3. writ admin key/host/repo/template add, then writ init <repo> in a clone."
    say "  4. Start each agent with writ run -- <agent>."
    say "The daemon's log: journalctl -u $UNIT."
}

setup_upgrade() {
    preflight
    old=$(cksum <"$BIN/writ" 2>/dev/null || printf none)
    step "The daemon stopped in order (SIGTERM: what is in flight finishes)"
    as_root systemctl stop "$UNIT.service" || say "  (it was not running)"
    install_binaries
    step "The daemon started again: the keystore, state, configuration and pins kept"
    as_root systemctl start "$UNIT.service"
    CURRENT=
    [ "$DRY_RUN" = 1 ] && return 0
    say "Upgraded. writ unseal opens it again."
    new=$(cksum <"$BIN/writ")
    [ "$old" = "$new" ] || say "writ changed: writ skill update --all rewrites the agent skill in every repository it wired."
}
