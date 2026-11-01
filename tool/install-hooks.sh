#!/bin/sh
# Installs the repository's git hooks (tool/git-hooks) as stubs in .git/hooks, which call the
# tracked hook. It never sets core.hooksPath: a local one would override a global
# core.hooksPath, and hooks installed there would stop running. Git runs .git/hooks itself when
# no core.hooksPath is set; a global hooks directory that chains to the repository's own hooks
# (`$(git rev-parse --git-common-dir)/hooks/<name>`) runs them too.
set -eu
top=$(git rev-parse --show-toplevel)
hooks="$(cd "$top" && cd "$(git rev-parse --git-common-dir)" && pwd)/hooks"
mkdir -p "$hooks"

# An earlier `make hooks` set core.hooksPath locally: remove it.
if [ "$(git config --local --get core.hooksPath || true)" = "tool/git-hooks" ]; then
    git config --local --unset core.hooksPath
    echo "removed the local core.hooksPath"
fi

marker="# Installed by make hooks (tool/install-hooks.sh)."
for source in "$top"/tool/git-hooks/*; do
    name=$(basename "$source")
    target="$hooks/$name"
    if [ -e "$target" ] && ! grep -qF "$marker" "$target"; then
        echo "$target exists and was not installed by make hooks: left as is" >&2
        exit 1
    fi
    cat > "$target" <<EOF
#!/bin/sh
$marker
exec "\$(git rev-parse --show-toplevel)/tool/git-hooks/$name" "\$@"
EOF
    chmod +x "$target"
    echo "installed $name"
done

global=$(git config --global --get core.hooksPath || true)
if [ -n "$global" ]; then
    echo "note: core.hooksPath is set globally ($global); these hooks run only if it chains to .git/hooks"
fi
