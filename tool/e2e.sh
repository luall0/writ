#!/bin/sh
# make e2e: M4's acceptance against a real remote, Forgejo in Docker (docs/testing.md).
# Starts a throwaway Forgejo on random local ports, makes a user `writ` and an API token,
# runs crates/writ-integration/tests/e2e_forgejo.rs against it, and removes the container
# whatever happens. Needs Docker; nothing here touches your own git, SSH or remotes.
set -eu

IMAGE=codeberg.org/forgejo/forgejo:13.0.5
NAME="writ-e2e-forgejo-$$"

docker run -d --rm --name "$NAME" \
    -p 127.0.0.1::3000 -p 127.0.0.1::22 \
    -e FORGEJO__security__INSTALL_LOCK=true \
    -e FORGEJO__database__DB_TYPE=sqlite3 \
    -e FORGEJO__server__DOMAIN=127.0.0.1 \
    -e FORGEJO__server__ROOT_URL=http://127.0.0.1/ \
    "$IMAGE" >/dev/null
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT INT TERM

HTTP=$(docker port "$NAME" 3000/tcp | head -n 1)
SSH_PORT=$(docker port "$NAME" 22/tcp | head -n 1 | sed 's/.*://')

# Forgejo gives no signal when it is ready: its API answers. Bounded at 120 s.
tries=0
until curl -fsS "http://$HTTP/api/v1/version" >/dev/null 2>&1; do
    tries=$((tries + 1))
    if [ "$tries" -gt 240 ]; then
        echo "e2e: Forgejo did not start" >&2
        docker logs "$NAME" >&2 || true
        exit 1
    fi
    sleep 0.5
done

docker exec -u git "$NAME" forgejo admin user create --admin --username writ \
    --password "writ-e2e-$$-pass" --email writ@e2e.invalid --must-change-password=false >/dev/null
TOKEN=$(docker exec -u git "$NAME" forgejo admin user generate-access-token --username writ \
    --token-name e2e --scopes all --raw | tail -n 1)

CARGO_TARGET_DIR=target/bins cargo build --locked -p writd -p writ-cli -p writ-sign --features writd/dev-keystore
WRIT_BIN_DIR="$(pwd)/target/bins/debug" \
WRIT_E2E_FORGEJO_HTTP="http://$HTTP" \
WRIT_E2E_FORGEJO_SSH_PORT="$SSH_PORT" \
WRIT_E2E_FORGEJO_TOKEN="$TOKEN" \
    cargo test --locked -p writ-integration --test e2e_forgejo -- --ignored
