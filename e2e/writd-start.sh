#!/bin/sh
# The writd container's entrypoint. Before the operator set the daemon up, nothing runs: the
# setup writes its files and starts `writd run writd.yaml` itself, as the operator guide says
# (docs/operators/setup.md). Once set up (a container restart), the daemon starts again the
# same way, from its home, on the same relative path, its log appended to writd.log: sealed,
# until the approver runs `writ unseal`.
set -eu
cd "$HOME"
if [ -f writd.yaml ]; then
    exec writd run writd.yaml 2>>writd.log
fi
exec sleep infinity
