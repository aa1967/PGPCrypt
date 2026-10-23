#!/bin/sh
set -eu
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"
qt_root=$(dirname -- "$repo_root")/.pgpcrypt-tools/qt/usr
rpath=""
if [ -d "$qt_root/lib/x86_64-linux-gnu/pkgconfig" ]; then
    export PKG_CONFIG_PATH="$qt_root/lib/x86_64-linux-gnu/pkgconfig"
    qt_flags=$(pkg-config --define-variable="prefix=$qt_root" --cflags --libs Qt6Widgets)
    rpath="-Wl,-rpath,$qt_root/lib/x86_64-linux-gnu"
else
    qt_flags=$(pkg-config --cflags --libs Qt6Widgets)
fi
mkdir -p target/validation
# Compiler flags intentionally split; no data from user files is interpolated.
# shellcheck disable=SC2086
g++ -std=c++20 -O2 -Wall -Wextra -Werror tests/removable_policy.cpp -o target/validation/removable-policy $qt_flags $rpath
target/validation/removable-policy
