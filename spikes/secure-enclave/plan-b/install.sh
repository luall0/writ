#!/bin/sh
# Plan B spike: a dedicated role user `_writd` running se-cryptokit as a LaunchDaemon, its
# Secure Enclave key blob in a directory only that user can read.
# Usage: sudo ./install.sh        (./install.sh --dry-run lists the steps without doing them)
# Undo:  sudo ./uninstall.sh
set -eu
cd "$(dirname "$0")"
. ./common.sh
need_root

built=../cryptokit/.build/release/se-cryptokit
[ -x "$built" ] || { echo "build it first: (cd ../cryptokit && swift build -c release)" >&2; exit 1; }
if dscl . -read "/Users/$USER_NAME" >/dev/null 2>&1; then
    echo "$USER_NAME already exists: run uninstall.sh first" >&2
    exit 1
fi

# A free id below 500 (hidden system range), unused as a user id and as a group id.
ID=
for candidate in $(seq 450 499); do
    if ! dscl . -list /Users UniqueID | awk '{print $2}' | grep -qx "$candidate" &&
       ! dscl . -list /Groups PrimaryGroupID | awk '{print $2}' | grep -qx "$candidate"; then
        ID=$candidate
        break
    fi
done
[ -n "$ID" ] || { echo "no free id in 450-499" >&2; exit 1; }
echo "# role user and group $USER_NAME, id $ID"

run dscl . -create "/Groups/$USER_NAME"
run dscl . -create "/Groups/$USER_NAME" PrimaryGroupID "$ID"
run dscl . -create "/Groups/$USER_NAME" RealName "Writ spike daemon"
run dscl . -create "/Groups/$USER_NAME" Password "*"
run dscl . -create "/Users/$USER_NAME"
run dscl . -create "/Users/$USER_NAME" UniqueID "$ID"
run dscl . -create "/Users/$USER_NAME" PrimaryGroupID "$ID"
run dscl . -create "/Users/$USER_NAME" UserShell /usr/bin/false
run dscl . -create "/Users/$USER_NAME" NFSHomeDirectory "$HOME_DIR"
run dscl . -create "/Users/$USER_NAME" RealName "Writ spike daemon"
run dscl . -create "/Users/$USER_NAME" Password "*"
run dscl . -create "/Users/$USER_NAME" IsHidden 1

echo "# the binary, owned by root so no other user can replace it"
run install -d -o root -g wheel -m 0755 "$BIN_DIR"
run install -o root -g wheel -m 0755 "$built" "$BIN"

echo "# the key's directory: only $USER_NAME can read it"
run install -d -o "$USER_NAME" -g "$USER_NAME" -m 0700 "$HOME_DIR"

echo "# the log, readable by everyone (it holds results, never the key)"
run touch "$LOG"
run chown "$USER_NAME:$USER_NAME" "$LOG"
run chmod 0644 "$LOG"

echo "# the LaunchDaemon: starts at boot, before anyone logs in"
plist_content="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
	<key>Label</key><string>$LABEL</string>
	<key>ProgramArguments</key>
	<array><string>$BIN</string><string>daemon</string><string>$HOME_DIR</string><string>10</string></array>
	<key>UserName</key><string>$USER_NAME</string>
	<key>GroupName</key><string>$USER_NAME</string>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>StandardOutPath</key><string>$LOG</string>
	<key>StandardErrorPath</key><string>$LOG</string>
</dict>
</plist>"
echo "+ write $PLIST"
if [ "$DRY" = 1 ]; then
    echo "$plist_content" | sed 's/^/    /'
else
    echo "$plist_content" > "$PLIST"
    chown root:wheel "$PLIST"
    chmod 0644 "$PLIST"
fi
run launchctl bootstrap system "$PLIST"

echo "# done; results: tail -f $LOG"
