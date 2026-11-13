# The images of the end-to-end pipeline (docs/end-to-end.md), built by `make e2e`:
#
# - `writd`: the daemon's host. The real Linux `writd`, git and OpenSSH, a user `writ`; the
#   operator sets it up and starts it (crates/writ-e2e/src/setup.rs).
# - `agent`: an agent's host (another host, as in detached mode): `writ`, `writ-sign`, git and
#   OpenSSH, a user `agent` (the agents, and the operator's own git) and a user `approver`
#   (the approver's machine: `writ` and a throwaway ssh-agent holding the approval key).
# - `local`: local mode on Linux, one machine: the daemon as `writd` on Unix sockets, the agent
#   and the approver as `dev` (scenario 24).
# - `runner`: the scenarios (crates/writ-e2e/tests/scenarios), driving the others through
#   the Docker socket and Forgejo's API.
# - `socks-proxy`, `http-proxy`: microsocks (SOCKS5) and tinyproxy (HTTP CONNECT), each with a user
#   and a password, the only way to `forgejo-behind` and `forgejo-https-behind` (scenario 25).
# - `tls-front`: Forgejo over HTTPS (`https://forgejo-https:3443`), for the daemon's HTTPS
#   upstream: socat terminating TLS with a throwaway self-signed certificate made at build
#   time, in front of Forgejo's plain HTTP. Built twice, each with its own certificate: for
#   `forgejo-https` (in the daemon's `mirrors.ca_certs`) and for `forgejo-https-system` (in
#   the daemon container's system store only, `TLS_NAME`).
#
# A test image (decided with the user in M4.1): debug builds, on the sealed keystore as an
# operator runs it (M5), without the development keystore. M8's deploy image (non-root,
# minimal, read-only, compose) builds on it. Base images are pinned by digest (multi-arch
# indexes: the same pin on arm64 and amd64); every cargo build is --locked.

ARG RUST_IMAGE=rust:1.99.1-slim-trixie@sha256:b8e062b1c3a80183df83d9ba187cadd2b5ab84bc78d453dbfeb2fccd5f982247
ARG DEBIAN_IMAGE=debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
# The apt packages, pinned too: every stage installs from Debian's archive as it was on this
# date (snapshot.debian.org), never from whatever the mirrors hold the day the image builds.
# Moved with the base images (docs/guides/dependency-upgrades.md).
ARG DEBIAN_SNAPSHOT=20261101T000000Z

FROM ${RUST_IMAGE} AS build
ARG DEBIAN_SNAPSHOT
RUN printf 'Types: deb\nURIs: http://snapshot.debian.org/archive/debian/%s\nSuites: trixie trixie-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n\nTypes: deb\nURIs: http://snapshot.debian.org/archive/debian-security/%s\nSuites: trixie-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n' \
        "$DEBIAN_SNAPSHOT" "$DEBIAN_SNAPSHOT" > /etc/apt/sources.list.d/debian.sources \
    && rm -f /etc/apt/sources.list \
    && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99writ-snapshot
# The toolchain the image ships (the one rust-toolchain.toml pins), without its extra
# components: nothing is downloaded here.
ENV RUSTUP_TOOLCHAIN=1.99.1 CARGO_TERM_COLOR=never
# Python, for tool/target-cache.py: the target cache below keeps the last build only.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# The binaries as they ship (built on their own, so no test-only feature reaches them, nor the
# development keystore), then the scenarios' test binary. The caches only make a
# second build faster: what is built is the copied tree and Cargo.lock. Each build is
# recorded, then the target cache pruned to them (docs/testing.md#how-make-test-runs): it
# would otherwise keep every build it ever held.
RUN --mount=type=cache,id=writ-e2e-cargo,target=/usr/local/cargo/registry \
    --mount=type=cache,id=writ-e2e-target,target=/src/target \
    set -eu; \
    python3 -I tool/target-cache.py record e2e-binaries build --locked -p writd -p writ-cli -p writ-sign; \
    mkdir -p /out; \
    cp target/debug/writd target/debug/writ target/debug/writ-sign /out/; \
    python3 -I tool/target-cache.py record e2e-scenarios test --locked -p writ-e2e --test scenarios --no-run; \
    cargo test --locked -p writ-e2e --test scenarios --no-run --message-format=json \
        | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' > /tmp/scenarios; \
    test "$(wc -l < /tmp/scenarios)" -eq 1; \
    cp "$(cat /tmp/scenarios)" /out/scenarios; \
    python3 -I tool/target-cache.py prune

FROM ${DEBIAN_IMAGE} AS runtime
ARG DEBIAN_SNAPSHOT
RUN printf 'Types: deb\nURIs: http://snapshot.debian.org/archive/debian/%s\nSuites: trixie trixie-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n\nTypes: deb\nURIs: http://snapshot.debian.org/archive/debian-security/%s\nSuites: trixie-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n' \
        "$DEBIAN_SNAPSHOT" "$DEBIAN_SNAPSHOT" > /etc/apt/sources.list.d/debian.sources \
    && rm -f /etc/apt/sources.list \
    && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99writ-snapshot
# git ≥ 2.45 (the daemon's mirrors; Debian 13 has 2.47) and OpenSSH (Debian 13: 10.0).
RUN apt-get update \
    && apt-get install -y --no-install-recommends git openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/*

FROM runtime AS writd
RUN useradd --create-home --shell /bin/sh writ
COPY --from=build /out/writd /usr/local/bin/writd
COPY e2e/writd-start.sh /usr/local/bin/writd-start
USER writ
WORKDIR /home/writ
ENTRYPOINT ["/usr/local/bin/writd-start"]

FROM runtime AS agent
# GnuPG, for the agent's `git verify-commit` of OpenPGP commits (`writ-sign --verify` hands it
# to gpg), with its agent: gpg starts one even to import a public key, and exits 2 without it.
# The daemon's image has none: it never runs gpg.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gpg gpg-agent \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --shell /bin/sh agent \
    && useradd --create-home --shell /bin/sh approver
COPY --from=build /out/writ /out/writ-sign /usr/local/bin/
USER agent
WORKDIR /home/agent
CMD ["sleep", "infinity"]

FROM runtime AS local
# Local mode on Linux (M7.1, scenario 24): one machine, the daemon as the system user `writd`
# (started as its systemd unit starts it: `setpriv` with the ambient CAP_SYS_PTRACE its
# process reader keeps), the agent and the approver as `dev`, in the `writ` group that opens
# the sockets. nc (OpenBSD's, for `nc -U`: git over the socket), and strace and gdb to show
# `dev` can't attach to the daemon.
RUN apt-get update \
    && apt-get install -y --no-install-recommends netcat-openbsd procps strace gdb \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --user-group --no-create-home --home-dir /var/lib/writ \
        --shell /usr/sbin/nologin writd \
    && groupadd --system writ \
    && useradd --create-home --shell /bin/sh --groups writ dev \
    && install -d -m 0755 /etc/writ \
    && install -d -m 0700 -o writd -g writd /var/lib/writ
COPY --from=build /out/writd /out/writ /out/writ-sign /usr/local/bin/
CMD ["sleep", "infinity"]

FROM runtime AS runner
# The Docker client only: the scenarios reach the other containers through the socket.
RUN apt-get update \
    && apt-get install -y --no-install-recommends docker-cli \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/scenarios /usr/local/bin/scenarios
ENTRYPOINT ["/usr/local/bin/scenarios", "--ignored"]

FROM ${DEBIAN_IMAGE} AS socks-proxy
ARG DEBIAN_SNAPSHOT
RUN printf 'Types: deb\nURIs: http://snapshot.debian.org/archive/debian/%s\nSuites: trixie trixie-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n\nTypes: deb\nURIs: http://snapshot.debian.org/archive/debian-security/%s\nSuites: trixie-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n' \
        "$DEBIAN_SNAPSHOT" "$DEBIAN_SNAPSHOT" > /etc/apt/sources.list.d/debian.sources \
    && rm -f /etc/apt/sources.list \
    && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99writ-snapshot
# microsocks: SOCKS5 with a user and a password (RFC 1929), CONNECT only, names resolved by
# it. The password is a throwaway stack's, the one the setup adds with `writ admin token`
# (crates/writ-e2e/src/setup.rs).
RUN apt-get update \
    && apt-get install -y --no-install-recommends microsocks \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --no-create-home --shell /usr/sbin/nologin socks
USER socks
CMD ["microsocks", "-i", "0.0.0.0", "-p", "1080", "-u", "writ", "-P", "e2e-socks-proxy-password"]

FROM ${DEBIAN_IMAGE} AS http-proxy
ARG DEBIAN_SNAPSHOT
RUN printf 'Types: deb\nURIs: http://snapshot.debian.org/archive/debian/%s\nSuites: trixie trixie-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n\nTypes: deb\nURIs: http://snapshot.debian.org/archive/debian-security/%s\nSuites: trixie-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n' \
        "$DEBIAN_SNAPSHOT" "$DEBIAN_SNAPSHOT" > /etc/apt/sources.list.d/debian.sources \
    && rm -f /etc/apt/sources.list \
    && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99writ-snapshot
RUN apt-get update \
    && apt-get install -y --no-install-recommends tinyproxy \
    && rm -rf /var/lib/apt/lists/*
COPY e2e/proxy/tinyproxy.conf /etc/tinyproxy/tinyproxy.conf
USER tinyproxy
CMD ["tinyproxy", "-d", "-c", "/etc/tinyproxy/tinyproxy.conf"]

FROM ${DEBIAN_IMAGE} AS tls-front
ARG DEBIAN_SNAPSHOT
RUN printf 'Types: deb\nURIs: http://snapshot.debian.org/archive/debian/%s\nSuites: trixie trixie-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n\nTypes: deb\nURIs: http://snapshot.debian.org/archive/debian-security/%s\nSuites: trixie-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n' \
        "$DEBIAN_SNAPSHOT" "$DEBIAN_SNAPSHOT" > /etc/apt/sources.list.d/debian.sources \
    && rm -f /etc/apt/sources.list \
    && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99writ-snapshot
# The name the certificate is made for (and the compose service's), and every name it holds.
ARG TLS_NAME=forgejo-https
ARG TLS_SAN=DNS:${TLS_NAME}
RUN apt-get update \
    && apt-get install -y --no-install-recommends socat openssl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --no-create-home --shell /bin/sh front \
    && mkdir /tls && chown front /tls
USER front
WORKDIR /tls
# A throwaway certificate for the front's name, made here (never stored in the repository).
# `forgejo-https`'s: the operator setup copies it to the daemon as its `mirrors.ca_certs`;
# `forgejo-https-system`'s: scenario 13 adds it to the daemon container's system store.
RUN openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
        -subj "/CN=${TLS_NAME}" -addext "subjectAltName=${TLS_SAN}" \
        -keyout key.pem -out cert.pem 2>/dev/null
CMD ["socat", "OPENSSL-LISTEN:3443,reuseaddr,fork,cert=/tls/cert.pem,key=/tls/key.pem,verify=0", "TCP:forgejo:3000"]
