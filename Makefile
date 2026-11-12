.PHONY: ci push check test test-props test-agent e2e bench-alloc github-check fmt run dev-client hooks install uninstall

# Lint, format check, dependency directions, source rules, doc links, the guarantee,
# end-to-end and configuration registries.
# Each library is also linted alone: the workspace build turns on the `testing` features the
# tests ask for, which could hide code that only compiles with them.
LIBRARIES := writ-alloc writ-core writ-proto writ-crypto writ-git writ-mirror writ-signer writ-platform writ-store writ-approval writ-gateway

# The shipped binaries, built on their own: a workspace build would turn on the `testing`
# features the integration crate asks for.
BINARIES := -p writd -p writ-cli -p writ-sign

# Every cargo build here records what it built or reused, so `make test` can prune target/ to
# the last builds at its end: `$(RECORD) <record name> <cargo subcommand> [arguments]`
# (tool/target-cache.py, docs/testing.md#how-make-test-runs).
RECORD := python3 -I tool/target-cache.py record

# The property tests, selected from the workspace's test build (no build of their own).
PROPERTIES := binary_id(writ-core::properties) | binary_id(writ-approval::sign_phases)

# What CI runs (GitHub Actions on Linux, by hand or `make push` on the Mac): the one definition
# of green. Everything is --locked: Cargo.lock is what gets built, never a fresh resolution.
# On a clean working tree, a pass stamps the tree (tool/ci-stamp.sh): the pre-push hook allows
# a push of a stamped tree only, without running CI while git holds the connection open.
ci:
	@tree=$$(sh tool/ci-stamp.sh tree) && \
		$(MAKE) --no-print-directory check test && \
		sh tool/ci-stamp.sh record "$$tree"

# `make ci` (skipped if it already passed on this tree), then `git push`, on a clean working
# tree only. Arguments for git: make push ARGS="origin main".
push:
	@sh tool/ci-stamp.sh require-clean
	@sh tool/ci-stamp.sh verified || $(MAKE) --no-print-directory ci
	git push $(ARGS)

check:
	cargo fmt --all --check
	$(RECORD) clippy clippy --locked --workspace --all-targets -- -D warnings
	for crate in $(LIBRARIES); do $(RECORD) clippy-$$crate clippy --locked -q -p $$crate --lib -- -D warnings || exit 1; done
	python3 -I tool/check-deps.py
	python3 -I tool/check-rules.py
	python3 -I tool/check-links.py
	python3 -I tool/check-features.py
	python3 -I tool/check-guarantees.py
	python3 -I tool/check-e2e.py
	python3 -I tool/check-config.py
	sh tool/shellcheck.sh deploy/install.sh deploy/frame.sh deploy/setups/*.sh
	cargo deny --locked check

# The integration tests run the binaries (writd, writ, writ-sign, and on the Mac writ-se, the
# Secure Enclave helper: tool/build-writ-se.sh) as they ship, built first on their own in
# target/bins (writd with the dev keystore the tests use). Every test runs under
# cargo-nextest, in a process of its own (.config/nextest.toml), without backtraces (a
# deliberate panic would cost seconds); the property tests with the fixed seed only (CI adds
# a random one). Then target/ is pruned to the last builds (docs/testing.md#how-make-test-runs).
test:
	CARGO_TARGET_DIR=target/bins $(RECORD) bins build --locked $(BINARIES) --features writd/dev-keystore
	sh tool/build-writ-se.sh target/bins/debug
	$(RECORD) test test --locked --workspace --no-run
	WRIT_BIN_DIR=$(CURDIR)/target/bins/debug RUST_BACKTRACE=0 cargo nextest run --locked --workspace
	python3 -I tool/target-cache.py prune

# The property tests with one seed: a number from a failed run, or `random` (CI's pass), drawn
# here and printed, so every property gets the same one.
test-props:
	@test -n "$(SEED)" || { echo "usage: make test-props SEED=<number|random>"; exit 2; }
	@seed="$(SEED)"; \
		if [ "$$seed" = random ]; then seed=$$(python3 -I -c 'import secrets; print(secrets.randbits(64))'); fi; \
		echo "proptest seed: $$seed (replay with make test-props SEED=$$seed)"; \
		WRIT_PROPTEST_SEED="$$seed" RUST_BACKTRACE=0 cargo nextest run --locked --workspace -E '$(PROPERTIES)'

# Opt-in: an approval signed by a key in your own ssh-agent (may ask for Touch ID or a touch).
# make test-agent KEY=<public key .pub> [AGENT=<agent socket, default $$SSH_AUTH_SOCK>]
test-agent:
	@test -n "$(KEY)" || { echo "usage: make test-agent KEY=<public key .pub> [AGENT=<socket>]"; exit 2; }
	CARGO_TARGET_DIR=target/bins $(RECORD) bins build --locked $(BINARIES) --features writd/dev-keystore
	sh tool/build-writ-se.sh target/bins/debug
	WRIT_TEST_AGENT_KEY="$(KEY)" SSH_AUTH_SOCK="$(or $(AGENT),$(SSH_AUTH_SOCK))" \
		WRIT_BIN_DIR=$(CURDIR)/target/bins/debug cargo nextest run --locked --workspace --run-ignored only \
		-E 'binary_id(writ-integration::interop) & test(=your_agent_key_signs_approvals_rust_verifies)'

# End to end (docs/end-to-end.md): the real binaries in their own containers against a real
# Forgejo, every scenario run from a runner container, everything removed afterwards
# (tool/e2e.sh). Not part of `make ci` (it needs Docker): CI runs it as a job of its own.
# A filter for the scenarios: make e2e ARGS=wrapper_mode.
e2e:
	sh tool/e2e.sh $(ARGS)

# M5.7's benchmark (docs/history/m5.7-memory-wiped-on-free.md): writd with and without the
# wiping allocator under heavy load, alternated, and the allocation-heavy paths both ways, in
# release builds (tool/bench-alloc.py). Not part of `make ci`. RUNS per build (5 by default);
# LINUX=1 runs it in a Linux container (glibc's allocator, as in detached mode; Docker).
bench-alloc:
	python3 -I tool/bench-alloc.py --runs $(or $(RUNS),5) $(if $(LINUX),--linux)

# The GitHub manual check as one command (by hand: your approval key signs, Touch ID), against a
# THROWAWAY repository with a main: make github-check REPO=<owner>/<repo> [EMAIL=<a verified
# email of yours>, to check "Verified"]. Uses `gh` when it is installed and logged in.
github-check:
	@test -n "$(REPO)" || { echo "usage: make github-check REPO=<owner>/<repo> [EMAIL=<address>]"; exit 2; }
	sh tool/github-check.sh "$(REPO)" $(if $(EMAIL),--email "$(EMAIL)")

fmt:
	cargo fmt --all

# The development daemon on dev/writd.yaml (test keys in dev/data, approver key in
# dev/approvers, both gitignored).
run:
	$(RECORD) writd-dev build --locked -p writd --features dev-keystore
	sh tool/build-writ-se.sh target/debug
	cargo run --locked -p writd --features dev-keystore -- run dev/writd.yaml

# Pins the development daemon's host key and TLS certificate for the client
# (dev/data/client/known_hosts and tls_pins), and lists the client's reader key in
# dev/readers (see docs/guides/manual-checks.md).
dev-client:
	@mkdir -p dev/data/client
	@$(RECORD) writd-dev build --locked -q -p writd --features dev-keystore
	@$(RECORD) writ-dev build --locked -q -p writ-cli
	@WRIT_HOME=dev/data/client cargo run --locked -q -p writ-cli -- reader dev > dev/readers
	@host=$$(cargo run --locked -q -p writd --features dev-keystore -- host-key dev/writd.yaml) && \
		printf '[127.0.0.1]:2222 %s\n[127.0.0.1]:2223 %s\n' "$$host" "$$host" > dev/data/client/known_hosts
	@echo "[127.0.0.1]:8443 $$(cargo run --locked -q -p writd --features dev-keystore -- tls-fingerprint dev/writd.yaml)" > dev/data/client/tls_pins
	@echo "pinned in dev/data/client/known_hosts and dev/data/client/tls_pins; reader key in dev/readers"

# Installs the git hooks (tool/git-hooks) as stubs in .git/hooks: a push only of a tree
# `make ci` passed on. Never through a local core.hooksPath, which would turn off a global one.
hooks:
	@sh tool/install-hooks.sh
	@echo "pre-push allows only a tree make ci passed on (make push runs both)"

# The installer (deploy/install.sh, docs/operators/install.md): the release binaries built as
# you, then a setup installed, `local` on the Mac (SETUP=local answers its question; DRY_RUN=1
# lists every change and makes none; APPROVER=<your approval key's .pub>). Run again, it
# upgrades. `make uninstall` takes back what it made (PURGE=1 the daemon's data too, confirmed
# on the terminal; REPOS=undo|keep answers the question about the repositories writ init wired).
install:
	cargo build --release --locked $(BINARIES)
	sh tool/build-writ-se.sh target/release
	sh deploy/install.sh install

uninstall:
	sh deploy/install.sh uninstall
