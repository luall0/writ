# Secure Enclave spike (M0)

Throwaway code to answer the ⚠️ points of
[macOS Secure Enclave](../../docs/architecture/macos-secure-enclave.md), in the order of its
plans. Not part of the Cargo workspace; results go into the roadmap's M0 section.

| Folder | Plan | What it is |
|---|---|---|
| `keychain-app/` | A | `main.swift` for a macOS app with the Keychain Sharing capability (Xcode project made by hand, below) |
| `cryptokit/` | B, C | `se-cryptokit`, a Swift package: CryptoKit Secure Enclave key kept as a blob file |

## Plan A: the Xcode part

`keychain-app/WritSESpike.xcodeproj` is ready (Keychain Sharing group `dev.writ.daemon`, no
App Sandbox, `main.swift`). You need Xcode and an Apple ID, no paid membership.

1. Xcode → **Settings…** (⌘,) → **Accounts** → **+** → **Apple ID** → sign in: a team
   *"Your Name (Personal Team)"* appears.
2. In `project.pbxproj`, replace `dev.writ.spike.CHANGE-ME` with a bundle identifier of your
   own (they are global across Apple developers; Xcode registers it in your account).
3. Open the project → blue **WritSESpike** icon → target **WritSESpike** → **Signing &
   Capabilities** → **Team:** your Personal Team. Xcode creates the certificate and profile.
4. Build and run from the command line:
   ```bash
   xcodebuild -project keychain-app/WritSESpike.xcodeproj -target WritSESpike \
     -configuration Release -allowProvisioningUpdates SYMROOT=/tmp/writ-se build
   /tmp/writ-se/Release/WritSESpike.app/Contents/MacOS/WritSESpike info|create|sign|delete
   ```
   `delete` removes the test key from the keychain afterwards.

## Plans B and C: `se-cryptokit`

```bash
cd cryptokit && swift build -c release
.build/release/se-cryptokit create <blob>      # new key, blob 0600
.build/release/se-cryptokit sign <blob>
.build/release/se-cryptokit watch <blob> <log> 10
```

### Plan B: dedicated `_writd` user (by hand, needs `sudo`)

```bash
cd plan-b
./install.sh --dry-run     # every step it will take, nothing done
sudo ./install.sh          # role user _writd (id 450–499), binary in /usr/local/libexec/writ-spike,
                           # key directory /var/db/writ-spike (0700), LaunchDaemon dev.writ.spike
tail -f /Library/Logs/writ-spike.log   # one line every 10 s: console user, sign result
sudo ./uninstall.sh        # removes all of it, the key included
```

## Results

2026-10-31, M1 Pro, macOS 27.2, Xcode 27.1, FileVault on.

The only manual step for Plan A was picking the Personal Team in Signing & Capabilities;
builds then ran from the command line.

### Plan A

| Check | Result |
|---|---|
| Capability accepted for a Personal Team on macOS | ✅ The profile grants `keychain-access-groups = TEAMID.*` |
| App launches with the profile embedded | ✅ (Gatekeeper's `spctl` says "rejected": only matters for distribution) |
| Key creation and signing, no prompt | ✅ 6–7 ms per signature |
| Profile expiry | ⚠️ **7 days** (created 2026-10-31, expires 2026-11-07), this Mac only |
| A binary without the entitlement can't use the key | ✅ `-34018` |
| An ad-hoc binary claiming the entitlement | ✅ killed at launch (exit 137) |
| **Other code, same profile, signed with my Apple Development identity** | ❌ **can use the key**, no prompt |
| Reboot, screen locked, LaunchAgent, renewed profile | not run yet |

The access group binds the key to *my team's* signature, not to the daemon. Anything running
as my user can sign with my team: the Apple Development identity's private key is in my login
keychain and `codesign` used it without a prompt, and Xcode's account session lets
`xcodebuild -allowProvisioningUpdates` make profiles without one. Development builds also get
`com.apple.security.get-task-allow`, so a debugger running as my user may attach to the
daemon. Against agents running as my user, Plan A alone fails requirement 3.

### Plan C (CryptoKit blob, my user)

| Check | Result |
|---|---|
| Key creation and signing with no entitlement, no prompt | ✅ ad-hoc signed binary, 8 ms |
| Another binary (other code identity) uses the same blob | ✅ works: the blob is bound to the Mac, not the app (as expected) |
| A corrupted blob | ⚠️ **crashes the process** inside CryptoKit (`try!` → `invalidParameter`) instead of throwing |

### Plan B (CryptoKit blob, dedicated `_writd` user)

| Check | Result |
|---|---|
| Key creation as `_writd` from a LaunchDaemon | ✅ role account (uid 450, no shell, hidden), no prompt |
| Signing as `_writd` while I'm logged in | ✅ 8–22 ms |
| My user can't read the blob | ✅ `Permission denied` (directory and file) |
| My user can't use the blob with the same binary | ✅ `Permission denied` |
| My user can't attach to the daemon | ✅ `lldb`: "process is running as user '_writd'" |
| My user can't signal, replace the binary or the LaunchDaemon | ✅ `operation not permitted` / root-owned |
| Signing with my screen locked | ✅ locked 3 min (13:49:52–13:52:51Z), Mac awake: signed every 10 s, 14–44 ms. With the lid closed the Mac sleeps (`Clamshell Sleep`) and the daemon simply pauses, then carries on at wake |
| Signing after a reboot | ✅ With FileVault on, nothing runs before the first login unlocks the disk (no "before login" state on this Mac). Booted 13:54:59Z; the daemon started at the login (13:56:14Z) and signed at once (console user still `none`), then every 10 s; first signatures 170–420 ms, then 17–30 ms |
| Signing while nobody is logged in (after logging out) | ✅ logged out 13:59–14:02Z: 15 signatures, all ok (16–71 ms), console user `none` |
| Copying the blob to another Mac fails | not run (no second Mac) |

**Plan B is the local-mode signer.** Plan D wasn't needed.
