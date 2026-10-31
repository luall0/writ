# Deployment

## Detached (Docker)

```yaml
services:
  writd:
    image: writ/writd
    ports:
      - "2222:2222"   # gateway (SSH, agents)
      - "2223:2223"   # approval API over SSH (optional; firewall it to the approver)
      - "8443:8443"   # approval API over HTTPS (optional; firewall it to the approver)
    volumes:
      - writ-data:/var/lib/writ        # mirrors, leases, ledger, audit
      - writ-keys:/var/lib/writ/keys   # software signer only
    # devices:
    #   - /dev/bus/usb                   # YubiKey backend, later
```

Files: `deploy/Dockerfile`, `deploy/compose.yaml`.

Network exposure: **LAN + VPN only** ([Q21](../decisions.md)). Nothing is published to the
internet.

## Daemon host hardening

The daemon host is the crown jewel: it holds agent keys, upstream credentials and mirrors
([threat model, boundary 5](../threat-model.md#5-daemon-host-the-crown-jewel)).

- Dedicated host or VM
- Container running as non-root
- Minimal exposed ports: the gateway, and only the approval transports in use (SSH, HTTPS, or both)
- Backups of the ledger and the audit log
- YubiKey backend as soon as practical
- The `writ-keys` volume only ever holds the encrypted keystore; the daemon starts sealed
  ([Signer and sealing](signer.md#startup-and-sealing))

## Local (Mac)

The same `writd`, built natively, listening on a Unix socket (with
[process chain checks](identity.md#local-mode-process-chain-checks)) and started by launchd,
isolated from my user: a LaunchDaemon running as the dedicated role user `_writd`, as the M0
spike decided ([macOS Secure Enclave](macos-secure-enclave.md#m0-results)). The Mac must stay
awake for agents to work while I'm away (lid open, or on power with a display); with FileVault
the daemon starts at the first login after a boot. It is
the local [configuration preset](platform.md#configuration-presets), with the macOS
implementations plugged in. Built in [M7](../roadmap.md#m7--local-mode-on-the-mac).
