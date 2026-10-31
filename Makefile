.PHONY: check test test-agent fmt run

# Lint, format check, dependency directions.
check:
	cargo fmt --all --check
	cargo clippy --workspace --all-targets -- -D warnings
	python3 -I tool/check-deps.py
	python3 -I tool/check-links.py

# The end-to-end tests run the workspace binaries (writd, writ-sign), so build them first.
test:
	cargo build --workspace --bins
	cargo test --workspace

# Opt-in: an approval signed by a key in your own ssh-agent (may ask for Touch ID or a touch).
# make test-agent KEY=<public key .pub> [AGENT=<agent socket, default $$SSH_AUTH_SOCK>]
test-agent:
	@test -n "$(KEY)" || { echo "usage: make test-agent KEY=<public key .pub> [AGENT=<socket>]"; exit 2; }
	WRIT_TEST_AGENT_KEY="$(KEY)" SSH_AUTH_SOCK="$(or $(AGENT),$(SSH_AUTH_SOCK))" \
		cargo test -p writ-crypto --test interop -- --ignored --exact your_agent_key_signs_approvals_rust_verifies

fmt:
	cargo fmt --all

# M0 spike: the gateway with test keys in dev/data (gitignored).
run:
	cargo run -p writd -- spike dev/data 127.0.0.1:2222
