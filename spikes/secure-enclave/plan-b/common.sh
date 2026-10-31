# Shared by install.sh and uninstall.sh: what Plan B puts on the machine.
USER_NAME=_writd
LABEL=dev.writ.spike
BIN_DIR=/usr/local/libexec/writ-spike
BIN="$BIN_DIR/se-cryptokit"
HOME_DIR=/var/db/writ-spike
LOG=/Library/Logs/writ-spike.log
PLIST=/Library/LaunchDaemons/$LABEL.plist

DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

run() {
    echo "+ $*"
    [ "$DRY" = 1 ] || "$@"
}

need_root() {
    if [ "$DRY" = 0 ] && [ "$(id -u)" != 0 ]; then
        echo "run with sudo (or --dry-run to only list the steps)" >&2
        exit 1
    fi
}
