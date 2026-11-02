# The images of the end-to-end pipeline (docs/end-to-end.md), built by `make e2e`:
#
# - `writd`: the daemon's host. The real Linux `writd`, git and OpenSSH, a user `writ`; the
#   operator sets it up and starts it (crates/writ-e2e/src/setup.rs).
# - `agent`: an agent's host (another host, as in detached mode): `writ`, `writ-sign`, git and
#   OpenSSH, a user `agent` (the agents, and the operator's own git) and a user `approver`
#   (the approver's machine: `writ` and a throwaway ssh-agent holding the approval key).
# - `runner`: the scenarios (crates/writ-e2e/tests/scenarios), driving the others through
#   the Docker socket and Forgejo's API.
# - `tls-front`: Forgejo over HTTPS (`https://forgejo-https:3443`), for the daemon's HTTPS
#   upstream: socat terminating TLS with a throwaway self-signed certificate made at build
#   time, in front of Forgejo's plain HTTP. Built twice, each with its own certificate: for
#   `forgejo-https` (in the daemon's `mirrors.ca_certs`) and for `forgejo-https-system` (in
#   the daemon container's system store only, `TLS_NAME`).
#
# A test image (decided with the user in M4.1): debug builds, because only they take the
# development keystore until the sealed keystore exists (M5). M8's deploy image (non-root,
# minimal, read-only, compose) builds on it. Base images are pinned by digest (multi-arch
# indexes: the same pin on arm64 and amd64); every cargo build is --locked.

ARG RUST_IMAGE=rust:1.99.1-slim-trixie@sha256:b8e062b1c3a80183df83d9ba187cadd2b5ab84bc78d453dbfeb2fccd5f982247
ARG DEBIAN_IMAGE=debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4

FROM ${RUST_IMAGE} AS build
# The toolchain the image ships (the one rust-toolchain.toml pins), without its extra
# components: nothing is downloaded here.
ENV RUSTUP_TOOLCHAIN=1.99.1 CARGO_TERM_COLOR=never
WORKDIR /src
COPY . .
# The binaries as they ship (built on their own, so no test-only feature reaches them; writd
# with the development keystore), then the scenarios' test binary. The caches only make a
# second build faster: what is built is the copied tree and Cargo.lock.
RUN --mount=type=cache,id=writ-e2e-cargo,target=/usr/local/cargo/registry \
    --mount=type=cache,id=writ-e2e-target,target=/src/target \
    set -eu; \
    cargo build --locked -p writd -p writ-cli -p writ-sign --features writd/dev-keystore; \
    mkdir -p /out; \
    cp target/debug/writd target/debug/writ target/debug/writ-sign /out/; \
    cargo test --locked -p writ-e2e --test scenarios --no-run --message-format=json \
        | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' > /tmp/scenarios; \
    test "$(wc -l < /tmp/scenarios)" -eq 1; \
    cp "$(cat /tmp/scenarios)" /out/scenarios

FROM ${DEBIAN_IMAGE} AS runtime
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
RUN useradd --create-home --shell /bin/sh agent \
    && useradd --create-home --shell /bin/sh approver
COPY --from=build /out/writ /out/writ-sign /usr/local/bin/
USER agent
WORKDIR /home/agent
CMD ["sleep", "infinity"]

FROM runtime AS runner
# The Docker client only: the scenarios reach the other containers through the socket.
RUN apt-get update \
    && apt-get install -y --no-install-recommends docker-cli \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/scenarios /usr/local/bin/scenarios
ENTRYPOINT ["/usr/local/bin/scenarios", "--ignored"]

FROM ${DEBIAN_IMAGE} AS tls-front
# The name the certificate is made for (and the compose service's).
ARG TLS_NAME=forgejo-https
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
        -subj "/CN=${TLS_NAME}" -addext "subjectAltName=DNS:${TLS_NAME}" \
        -keyout key.pem -out cert.pem 2>/dev/null
CMD ["socat", "OPENSSL-LISTEN:3443,reuseaddr,fork,cert=/tls/cert.pem,key=/tls/key.pem,verify=0", "TCP:forgejo:3000"]
