#!/bin/sh
# make e2e: the end-to-end pipeline (docs/end-to-end.md). Builds the images (e2e/Dockerfile),
# starts Forgejo (and its two HTTPS fronts), writd, an agent host and the local mode machine
# (e2e/compose.yaml) under a project of their own, runs the scenarios in the runner container,
# and removes everything whatever happens.
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

# The layers this run left in Docker's build cache, built from this tree and never reused by a
# run on another one: the build's output (`mount / from exec …` of the RUN that records
# `e2e-binaries`), the binaries' COPY steps and the steps after them in each image (a layer
# is released only once the layers on top of it are, so the chain goes in one call). One
# filter, matching only steps of e2e/Dockerfile. Never the cargo cache mounts, which keep the
# next build incremental: their description (`cached mount …` of that RUN) matches none of
# these patterns, and a type filter can't protect them (`docker buildx prune` matches no plain
# layer by type). The copied tree (a few MB) is left to Docker's own GC.
BUILD_CACHE_STEPS='^mount...from.exec.*e2e-binaries|out.writd|out.writ-sign|writd-start|usr.local.bin.scenarios|WORKDIR..home.writ$|WORKDIR..home.agent$'
prune_build_cache() {
    docker buildx prune --all --force --filter "description~=$BUILD_CACHE_STEPS" >/dev/null 2>&1 || true
}

cleanup() {
    status=$?
    trap - EXIT INT TERM
    if [ "$status" -ne 0 ]; then
        echo "e2e: failed; the daemon's log:" >&2
        compose exec -T writd tail -n 60 writd.log >&2 2>/dev/null || true
        echo "e2e: the local daemon's log (scenario 24):" >&2
        compose exec -T local tail -n 40 /var/log/writd.log >&2 2>/dev/null || true
    fi
    if [ "${WRIT_E2E_KEEP:-}" = 1 ]; then
        echo "e2e: the stack is kept: docker compose -p $PROJECT -f e2e/compose.yaml --profile runner down -v --rmi local" >&2
    else
        compose --profile runner down -v --remove-orphans --rmi local >/dev/null 2>&1 || true
        prune_build_cache
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

compose --profile runner build
compose up -d forgejo forgejo-https forgejo-https-system socks-proxy http-proxy writd agent local
compose run --rm -e WRIT_E2E_PROJECT="$PROJECT" runner "$@"
