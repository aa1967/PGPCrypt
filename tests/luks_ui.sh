#!/bin/sh
set -eu
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
qt_root=$(dirname -- "$repo_root")/.pgpcrypt-tools/qt
cd "$repo_root"
mkdir -p target/validation
if [ -f "$qt_root/usr/lib/x86_64-linux-gnu/pkgconfig/Qt6Widgets.pc" ]; then
    export PKG_CONFIG_PATH="$qt_root/usr/lib/x86_64-linux-gnu/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
    qt_flags=$(pkg-config --define-variable="prefix=$qt_root/usr" --cflags --libs Qt6Widgets Qt6DBus)
    strength_flags="-I$qt_root/usr/include -L$qt_root/usr/lib/x86_64-linux-gnu -lzxcvbn"
    export LD_LIBRARY_PATH="$qt_root/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    export QT_PLUGIN_PATH="$qt_root/usr/lib/x86_64-linux-gnu/qt6/plugins"
else
    qt_flags=$(pkg-config --cflags --libs Qt6Widgets Qt6DBus)
    strength_flags=-lzxcvbn
fi
# Only this synthetic D-Bus service is used, never the system service or mounts.
# shellcheck disable=SC2086
g++ -std=c++20 -O2 -Wall -Wextra -Werror -fPIC tests/luks_service.cpp \
    -o target/validation/luks-service-check $qt_flags $strength_flags
QT_QPA_PLATFORM=offscreen dbus-run-session -- target/validation/luks-service-check
