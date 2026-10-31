#!/bin/sh
# Removes everything install.sh added, including the key (deleting the blob deletes the key).
# Usage: sudo ./uninstall.sh      (./uninstall.sh --dry-run lists the steps)
set -u
cd "$(dirname "$0")"
. ./common.sh
need_root

run launchctl bootout "system/$LABEL"
run rm -f "$PLIST"
run rm -rf "$BIN_DIR" "$HOME_DIR"
run rm -f "$LOG"
run dscl . -delete "/Users/$USER_NAME"
run dscl . -delete "/Groups/$USER_NAME"
echo "# done"
