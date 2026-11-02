# Keychain Secure Enclave signer with a paid Apple account

**Status:** parked (2026-11-02). **Area:** Signers. **Kind:** feature.

This page explains why we are not building it, and what would make us reconsider. The signer
that local mode uses is `se-cryptokit` under the dedicated `_writd` user (Plan B in
[macOS Secure Enclave](../../architecture/macos-secure-enclave.md), built in
[M7.5](../../roadmap.md#m75--secure-enclave-signer-on-the-mac)). Paying for the Apple
Developer Program only for clean code signatures, without this backend, is a separate idea:
[Developer ID signed binaries](../README.md#developer-id-signed-binaries).

## The idea

`se-keychain`: a Secure Enclave key stored in the data protection keychain under a keychain
access group (`<TEAMID>.dev.writ.daemon`). Only code signed by the team, carrying the
`keychain-access-groups` entitlement and an Apple-issued provisioning profile, can use the
key. A paid account was meant to fix the two problems the free Personal Team showed: a
profile that expires after 7 days, and a signing identity sitting in my user's login keychain.

## What the M0 spike found

The M0 spike built it with a free Personal Team. The Xcode project is archived in commit
`3485f40`, under `spikes/secure-enclave/keychain-app/`. Details are in
[the M0 spike's results](../../history/m0-protocol-spike.md#secure-enclave-results).

- **What worked:** the capability was accepted, the app launched with the profile, and the
  key was created and signed with no prompt (6–7 ms). Code without the entitlement was
  refused (`-34018`), and an ad-hoc binary claiming the entitlement was killed at launch.
- **Isolation is by team, not by daemon:** other code that reused the profile and was signed
  with my Apple Development identity used the key with no prompt. Anything running as my user
  can sign with my team (the identity is in the login keychain, and so is Xcode's account
  session).
- A Personal Team profile lasts 7 days; a paid account's lasts years.
- The paid team ID is probably different from the Personal Team's. That changes the access
  group, so the keys would have to be created again.
- Everything ran **inside my own login session**, never as `_writd` from a LaunchDaemon.

## Why it is a no-go for now

1. **Plan B already meets all three goals.** The goals were: non-exportable, usable with no
   prompt, usable only by the daemon. In M0, a CryptoKit key under the role user `_writd`
   signed with no prompt, with the screen locked, after a reboot and with nobody logged in. My
   user couldn't read the blob, use it, attach to the daemon, signal it, or replace its
   binary or LaunchDaemon. The isolation comes from the Unix user, and an access group would
   add nothing to it.
2. **A daemon probably can't use the data protection keychain.** Apple's
   [TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)
   says the data protection keychain is only available in a user login context, and that a
   launchd daemon can't use it. Apple's developer support repeats this on the forums ("the
   only keychain available to your daemon is the System keychain", which is file-based and
   can't hold Secure Enclave keys). Apple has said it intends to lift the limit, with no date.
   We have not tested it ourselves, but it is Apple's documented behavior, and paying doesn't
   change it: the limit is about where the code runs, not who signed it.
3. **The workarounds bring back what Plan B avoids:**
   - Running the daemon as a LaunchAgent in my session makes the keychain work, but the
     daemon runs as my user again, with the isolation M0 showed is missing.
   - Giving `_writd` a real login session (a hidden standard user kept logged in through
     fast user switching) is fragile. After a reboot nothing starts until that user logs in,
     and it is untested.
4. **The free Personal Team would isolate just as well under `_writd`.** If the daemon
   could use the keychain as `_writd`, my user couldn't reach `_writd`'s keychain whatever
   signs my code. That would make the signing-identity problem moot, and a paid account would
   bring only a longer-lived profile.

## What a paid account would still add on top of Plan B

Only if Apple lets a daemon use the data protection keychain:

- **The key is bound to the daemon's code signature, not only to a file.** Root, or code
  running as `_writd`, would need a binary signed by the team to use it, instead of reading
  the blob. Root is out of scope in the [threat model](../../threat-model.md), and code
  running as `_writd` already means the daemon is compromised, with its credentials. This
  changes no guarantee.
- **There is no blob file.** A corrupted blob can't crash the process inside CryptoKit, and
  no key file sits on disk or in a backup. M7.5 already guards against the crash.

Against: 99 €/yr, the daemon built as an app bundle with Xcode, keys created again if the team
changes, and point 2 above.

## What would reopen it

- Apple lets a launchd daemon running as its own user use the data protection keychain, and
  a test under `_writd` confirms it (create, sign with no prompt, screen locked, after a
  reboot, nobody logged in, another team's code refused).
- Writ is distributed to other Macs as a notarized app, and a daemon running in a user
  session becomes acceptable there. The keys would then be bound to the Writ developer's
  team, not the user's, so that question would be part of packaging rather than of this
  signer alone.

## Sources

- [TN3137: On Mac keychain APIs and implementations](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)
- [System Keychain not available from a Daemon](https://developer.apple.com/forums/thread/759976) (Apple Developer Forums)
- [How to write entries to the system keychain in macOS 12+](https://developer.apple.com/forums/thread/704034) (Apple Developer Forums)
