#!/bin/sh
# The stamp of the last tree `make ci` passed on, so the pre-push hook can allow a push
# without running CI itself. Git runs pre-push after it has read the remote's refs, with the
# connection open: a hook as long as `make ci` made the remote close it.
#
#   tree            prints HEAD's tree if the working tree is clean (no change, no untracked
#                   file, no file git doesn't compare: ignored outside the build cache and
#                   the dev daemon's data, assume-unchanged, skip-worktree), nothing
#                   otherwise: what `make ci` is about to test
#   record <tree>   once `make ci` passed: stamps <tree> if the working tree is still clean
#                   on that same tree
#   require-clean   exit 1 with the reason if the working tree is not clean
#   verified        exit 0 if the working tree is clean and HEAD's tree is the stamped one
#   pre-push        reads git's pre-push input on stdin; exit 0 if each pushed ref's tip has
#                   the stamped tree, 1 with the reason otherwise (fail closed: no stamp, an
#                   unreadable line or an unknown commit refuses). The commits below a tip
#                   aren't checked: a series of commits pushed at once ran `make ci` on its
#                   last tree only.
#
# The stamp is the tree, not the commit: what was tested is the content, so rewording a
# commit message keeps it. A convenience on the Mac, not a boundary: GitHub Actions runs
# `make ci` on every push, and `git push --no-verify` skips the hook anyway.
set -eu
cd "$(git rev-parse --show-toplevel)"
stamp=$(git rev-parse --git-path writ-ci-ok)

# HEAD's tree if nothing differs from it, failing otherwise. The status is read first, on its
# own: a failing `git status` must not read as an empty, clean one. git's status doesn't show
# what it doesn't compare, which the build may still read (an ignored `.rs` a tracked `mod`
# names, a file marked assume-unchanged or skip-worktree): each refuses too.
clean_tree() {
    status=$(git status --porcelain --untracked-files=all) || return 1
    [ -z "$status" ] || return 1
    # `git ls-files -v`: a lowercase tag is assume-unchanged, `S` skip-worktree.
    listed=$(git ls-files -v) || return 1
    hidden=$(printf '%s\n' "$listed" | grep -E '^([a-z]|S) ') || hidden=
    [ -z "$hidden" ] || return 1
    # Ignored files, each as the pattern that ignores it names it (a directory whole when the
    # pattern is the directory's): only the build cache, the dev daemon's data, Claude Code's
    # local files (its settings, the lock of its scheduled tasks) and the editors' and the OS's
    # own files may be. Not `traditional`: it names a directory whose files are
    # all ignored by the directory alone (`.claude/` for `.claude/settings.local.json`), which
    # the list below can't tell from a directory ignored whole.
    ignored=$(git status --porcelain --ignored=matching --untracked-files=normal) || return 1
    others=$(printf '%s\n' "$ignored" | sed -n 's/^!! //p' |
        grep -vE '^(target/|dev/data/|dev/approvers$|dev/readers$|dev/telegram-token$|\.claude/settings\.local\.json$|\.claude/scheduled_tasks\.lock$|\.idea/|\.vscode/)' |
        grep -vE '(^|/)(\.DS_Store|\.build/|xcuserdata/)') || others=
    [ -z "$others" ] || return 1
    git rev-parse --verify -q 'HEAD^{tree}'
}

stamped() {
    [ -f "$stamp" ] || return 1
    IFS= read -r s < "$stamp" || return 1
    printf '%s\n' "$s"
}

case "${1:-}" in
tree)
    if t=$(clean_tree); then
        printf '%s\n' "$t"
    else
        echo "make ci: uncommitted changes, untracked files, or files git doesn't compare (ignored, assume-unchanged, skip-worktree): the result won't be stamped for git push" >&2
    fi
    ;;
record)
    want=${2:-}
    [ -n "$want" ] || exit 0
    if now=$(clean_tree) && [ "$now" = "$want" ]; then
        printf '%s\n' "$want" > "$stamp.tmp"
        mv "$stamp.tmp" "$stamp"
        echo "make ci: passed on tree $want, stamped for git push"
    else
        echo "make ci: the working tree changed during the run: not stamped" >&2
    fi
    ;;
require-clean)
    if ! clean_tree > /dev/null; then
        echo "uncommitted changes, untracked files, or files git doesn't compare (ignored outside target/, assume-unchanged, skip-worktree): commit, remove or unmark them first (make ci stamps only a clean tree)" >&2
        exit 1
    fi
    ;;
verified)
    t=$(clean_tree) || exit 1
    s=$(stamped) || exit 1
    [ "$t" = "$s" ]
    ;;
pre-push)
    s=$(stamped) || s=""
    refused=0
    # Each line: <local ref> <local sha> <remote ref> <remote sha>.
    while read -r local_ref local_sha remote_ref remote_sha; do
        case "$local_sha" in
        *[!0]*) ;;
        "") echo "pre-push: unreadable input line: refused" >&2; refused=1; continue ;;
        *) continue ;; # all zeros: a deletion, nothing is sent
        esac
        t=$(git rev-parse --verify -q "$local_sha^{tree}") || t=""
        if [ -z "$s" ] || [ -z "$t" ] || [ "$t" != "$s" ]; then
            echo "pre-push: $local_ref ($local_sha) has not passed make ci here" >&2
            refused=1
        fi
    done
    if [ "$refused" -ne 0 ]; then
        echo "pre-push: run make ci on a clean checkout of that commit, then push again (make push does both)" >&2
        exit 1
    fi
    ;;
*)
    echo "usage: $0 tree | record <tree> | require-clean | verified | pre-push" >&2
    exit 2
    ;;
esac
