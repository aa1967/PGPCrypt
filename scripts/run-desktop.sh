#!/bin/sh
set -eu
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
qt_root=$(dirname -- "$repo_root")/.pgpcrypt-tools/qt
if [ -d "$qt_root/usr/lib/x86_64-linux-gnu/qt6/plugins" ]; then
    export QT_PLUGIN_PATH="$qt_root/usr/lib/x86_64-linux-gnu/qt6/plugins"
fi
profile=debug
if [ "${1:-}" = --release ]; then profile=release; shift; fi
exec "$repo_root/target/$profile/pgpcrypt-desktop" "$@"
