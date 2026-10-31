.PHONY: check test test-props test-agent fmt run dev-client

# Lint, format check, dependency directions, source rules, doc links.
# Each library is also linted alone: the workspace build turns on the `testing` features the
# tests ask for, which could hide code that only compiles with them.
LIBRARIES := writ-core writ-proto writ-crypto writ-platform writ-store writ-approval writ-gateway

check:
	cargo fmt --all --check
	cargo clippy --workspace --all-targets -- -D warnings
	for crate in $(LIBRARIES); do cargo clippy -q -p $$crate --lib -- -D warnings || exit 1; done
	python3 -I tool/check-deps.py
	python3 -I tool/check-rules.py
	python3 -I tool/check-links.py

# The integration tests run the workspace binaries (writd, writ, writ-sign), so build them
# first. The property tests run twice: with the fixed seed (the same inputs every run), then
# with a new random seed, printed so a failure can be replayed with `make test-props SEED=…`.
test:
	cargo build --workspace --bins
	cargo test --workspace
	WRIT_PROPTEST_SEED=random cargo test -q -p writ-core --test properties -- --nocapture

# The property tests with one seed (a number from a failed run, or `random`).
test-props:
	@test -n "$(SEED)" || { echo "usage: make test-props SEED=<number|random>"; exit 2; }
	WRIT_PROPTEST_SEED="$(SEED)" cargo test -p writ-core --test properties -- --nocapture

# Opt-in: an approval signed by a key in your own ssh-agent (may ask for Touch ID or a touch).
# make test-agent KEY=<public key .pub> [AGENT=<agent socket, default $$SSH_AUTH_SOCK>]
test-agent:
	@test -n "$(KEY)" || { echo "usage: make test-agent KEY=<public key .pub> [AGENT=<socket>]"; exit 2; }
	WRIT_TEST_AGENT_KEY="$(KEY)" SSH_AUTH_SOCK="$(or $(AGENT),$(SSH_AUTH_SOCK))" \
		cargo test -p writ-integration --test interop -- --ignored --exact your_agent_key_signs_approvals_rust_verifies

fmt:
	cargo fmt --all

# The development daemon on dev/writd.yaml (test keys in dev/data, approver key in
# dev/approvers, both gitignored).
run:
	cargo run -p writd -- run dev/writd.yaml

# Pins the development daemon's host key and TLS certificate for the client
# (dev/data/client/known_hosts and tls_pins; see docs/guides/manual-checks.md).
dev-client:
	@mkdir -p dev/data/client
	@host=$$(cargo run -q -p writd -- host-key dev/writd.yaml) && \
		printf '[127.0.0.1]:2222 %s\n[127.0.0.1]:2223 %s\n' "$$host" "$$host" > dev/data/client/known_hosts
	@echo "[127.0.0.1]:8443 $$(cargo run -q -p writd -- tls-fingerprint dev/writd.yaml)" > dev/data/client/tls_pins
	@echo "pinned in dev/data/client/known_hosts and dev/data/client/tls_pins"
