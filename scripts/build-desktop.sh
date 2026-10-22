#!/bin/sh
set -eu
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
qt_root=$(dirname -- "$repo_root")/.pgpcrypt-tools/qt
cd "$repo_root"
profile=debug
if [ "${1:-}" = --release ]; then
    profile=release
    ./scripts/dev.sh build --release --locked --bin pgpcrypt-worker -j 4
else
    test "$#" -eq 0
    ./scripts/dev.sh build --locked --bin pgpcrypt-worker -j 4
fi
mkdir -p target/qt
if [ -f "$qt_root/usr/lib/x86_64-linux-gnu/pkgconfig/Qt6Widgets.pc" ]; then
    export PKG_CONFIG_PATH="$qt_root/usr/lib/x86_64-linux-gnu/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
    qt_flags=$(pkg-config --define-variable="prefix=$qt_root/usr" --cflags --libs Qt6Widgets Qt6DBus)
    qt_rpath="-Wl,-rpath,$qt_root/usr/lib/x86_64-linux-gnu"
    qt_moc="$qt_root/usr/lib/qt6/libexec/moc"
else
    qt_flags=$(pkg-config --cflags --libs Qt6Widgets Qt6DBus)
    qt_rpath=""
    qt_moc=$(pkg-config --variable=libexecdir Qt6Core)/moc
fi
# Installed packages must resolve Qt from Debian, never a developer workspace.
if [ "$profile" = release ]; then qt_rpath=""; fi
"$qt_moc" desktop/main.cpp -o target/qt/main.moc
# pkg-config emits compiler flags, intentionally split as individual arguments.
# shellcheck disable=SC2086
g++ -std=c++20 -O2 -Wall -Wextra -Werror -fPIC -fstack-protector-strong \
    -D_FORTIFY_SOURCE=3 -Wl,-z,relro,-z,now -Itarget/qt \
    desktop/main.cpp -o "target/$profile/pgpcrypt-desktop" $qt_flags $qt_rpath
