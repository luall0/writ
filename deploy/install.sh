#!/bin/sh
# Writ's installer (docs/architecture/deployment.md#installing-and-uninstalling), run by
# `make install` and `make uninstall`:
#
#   deploy/install.sh install     (guided on a terminal; without one: SETUP, APPROVER, DRY_RUN,
#                                 and on the Mac TLS_BACKEND, AGENT_BACKEND)
#   deploy/install.sh uninstall   (guided; without a terminal: DRY_RUN, REPOS)
#
# One frame for every setup (frame.sh: the choice of setup, the dry run, the manifest, the
# upgrade, the uninstall); each setup is its own steps (setups/<name>.sh), and adding one
# changes no other. It runs as you and asks sudo only for the steps that need root.
set -eu
DEPLOY=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=deploy/frame.sh
. "$DEPLOY/frame.sh"
main "$@"
