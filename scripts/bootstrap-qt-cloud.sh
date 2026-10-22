#!/bin/sh
set -eu
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tools_root=$(dirname -- "$repo_root")/.pgpcrypt-tools
qt_root="$tools_root/qt"
apt_root="$tools_root/apt"
if [ -f "$qt_root/usr/lib/x86_64-linux-gnu/pkgconfig/Qt6Widgets.pc" ] && \
   [ -f "$qt_root/usr/lib/x86_64-linux-gnu/qt6/plugins/platforms/libqwayland-generic.so" ] && \
   [ -f "$qt_root/usr/include/zxcvbn.h" ]; then
    exit 0
fi
# Rootless extraction for the Debian 13 amd64 cloud image. Normal desktops use
# the system qt6-base-dev/qt6-wayland packages instead. APT retains signature and
# package-checksum verification; never use trusted=yes or allow-unauthenticated.
. "$repo_root/scripts/debian-apt-config.sh"
configure_cloud_apt
mkdir -p "$qt_root"
/usr/bin/apt-get update
/usr/bin/apt-get --download-only --no-install-recommends -y install qt6-base-dev qt6-wayland libzxcvbn-dev
# Installed runtime packages otherwise do not get downloaded; these must also
# exist in the extraction root for its development symlinks to resolve.
/usr/bin/apt-get --download-only --reinstall -y install libqt6core6t64 libqt6gui6 libqt6widgets6 libqt6dbus6 libzxcvbn0
for package in "$apt_root"/archives/*.deb; do dpkg-deb -x "$package" "$qt_root"; done
