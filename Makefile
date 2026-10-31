.PHONY: ci check test test-props test-agent fmt run dev-client hooks

# Lint, format check, dependency directions, source rules, doc links.
# Each library is also linted alone: the workspace build turns on the `testing` features the
# tests ask for, which could hide code that only compiles with them.
LIBRARIES := writ-core writ-proto writ-crypto writ-platform writ-store writ-approval writ-gateway

# The shipped binaries, built on their own: a workspace build would turn on the `testing`
# features the integration crate asks for.
BINARIES := -p writd -p writ-cli -p writ-sign

# What CI runs (GitHub Actions on Linux, the pre-push hook on the Mac): the one definition of
# green. Everything is --locked: Cargo.lock is what gets built, never a fresh resolution.
ci: check test

check:
	cargo fmt --all --check
	cargo clippy --locked --workspace --all-targets -- -D warnings
	for crate in $(LIBRARIES); do cargo clippy --locked -q -p $$crate --lib -- -D warnings || exit 1; done
	python3 -I tool/check-deps.py
	python3 -I tool/check-rules.py
	python3 -I tool/check-links.py
	python3 -I tool/check-features.py
	cargo deny --locked check

# The integration tests run the binaries (writd, writ, writ-sign) as they ship, built first on
# their own in target/bins (writd with the dev keystore the tests use). The property tests
# run twice: with the fixed seed (the same inputs every run), then with a new random seed,
# printed so a failure can be replayed with `make test-props SEED=…`.
test:
	CARGO_TARGET_DIR=target/bins cargo build --locked $(BINARIES) --features writd/dev-keystore
	WRIT_BIN_DIR=$(CURDIR)/target/bins/debug cargo test --locked --workspace
	WRIT_PROPTEST_SEED=random cargo test --locked -q -p writ-core --test properties -- --nocapture

# The property tests with one seed (a number from a failed run, or `random`).
test-props:
	@test -n "$(SEED)" || { echo "usage: make test-props SEED=<number|random>"; exit 2; }
	WRIT_PROPTEST_SEED="$(SEED)" cargo test --locked -p writ-core --test properties -- --nocapture

# Opt-in: an approval signed by a key in your own ssh-agent (may ask for Touch ID or a touch).
# make test-agent KEY=<public key .pub> [AGENT=<agent socket, default $$SSH_AUTH_SOCK>]
test-agent:
	@test -n "$(KEY)" || { echo "usage: make test-agent KEY=<public key .pub> [AGENT=<socket>]"; exit 2; }
	WRIT_TEST_AGENT_KEY="$(KEY)" SSH_AUTH_SOCK="$(or $(AGENT),$(SSH_AUTH_SOCK))" \
		WRIT_BIN_DIR=$(CURDIR)/target/bins/debug cargo test --locked -p writ-integration --test interop -- --ignored --exact your_agent_key_signs_approvals_rust_verifies

fmt:
	cargo fmt --all

# The development daemon on dev/writd.yaml (test keys in dev/data, approver key in
# dev/approvers, both gitignored).
run:
	cargo run --locked -p writd --features dev-keystore -- run dev/writd.yaml

# Pins the development daemon's host key and TLS certificate for the client
# (dev/data/client/known_hosts and tls_pins), and lists the client's reader key in
# dev/readers (see docs/guides/manual-checks.md).
dev-client:
	@mkdir -p dev/data/client
	@WRIT_HOME=dev/data/client cargo run --locked -q -p writ-cli -- reader dev > dev/readers
	@host=$$(cargo run --locked -q -p writd --features dev-keystore -- host-key dev/writd.yaml) && \
		printf '[127.0.0.1]:2222 %s\n[127.0.0.1]:2223 %s\n' "$$host" "$$host" > dev/data/client/known_hosts
	@echo "[127.0.0.1]:8443 $$(cargo run --locked -q -p writd --features dev-keystore -- tls-fingerprint dev/writd.yaml)" > dev/data/client/tls_pins
	@echo "pinned in dev/data/client/known_hosts and dev/data/client/tls_pins; reader key in dev/readers"

# Installs the git hooks (tool/git-hooks): `make ci` before every push.
hooks:
	git config core.hooksPath tool/git-hooks
	@echo "pre-push runs make ci"
