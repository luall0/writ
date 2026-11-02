#!/bin/sh
# make e2e: the end-to-end pipeline (docs/end-to-end.md). Builds the images (e2e/Dockerfile),
# starts Forgejo (and its two HTTPS fronts), writd and an agent host (e2e/compose.yaml) under a
# project of their own, runs the scenarios in the runner container, and removes everything
# whatever happens.
#
#   make e2e                          every scenario
#   make e2e ARGS=wrapper_mode        the scenarios whose name holds a filter (libtest's)
#   WRIT_E2E_KEEP=1 make e2e          keeps the stack afterwards, to look at it
#
# Needs Docker with compose, and make; nothing here touches your own git, SSH or remotes.
set -eu
cd "$(dirname "$0")/.."
PROJECT="writ-e2e-$$"
compose() { docker compose -p "$PROJECT" -f e2e/compose.yaml "$@"; }

cleanup() {
    status=$?
    trap - EXIT INT TERM
    if [ "$status" -ne 0 ]; then
        echo "e2e: failed; the daemon's log:" >&2
        compose exec -T writd tail -n 60 writd.log >&2 2>/dev/null || true
    fi
    if [ "${WRIT_E2E_KEEP:-}" = 1 ]; then
        echo "e2e: the stack is kept: docker compose -p $PROJECT -f e2e/compose.yaml --profile runner down -v --rmi local" >&2
    else
        compose --profile runner down -v --remove-orphans --rmi local >/dev/null 2>&1 || true
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

compose --profile runner build
compose up -d forgejo forgejo-https forgejo-https-system writd agent
compose run --rm -e WRIT_E2E_PROJECT="$PROJECT" runner "$@"
