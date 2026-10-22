#!/bin/sh
set -eu
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tools_root=$(dirname -- "$repo_root")/.pgpcrypt-tools
apt_root="$tools_root/apt"
if [ -x "$tools_root/debian-rust/usr/bin/cargo" ] && \
   [ -x "$tools_root/debian-rust/usr/bin/rustfmt" ] && \
   [ -e "$tools_root/debian-sodium/usr/lib/x86_64-linux-gnu/libsodium.so" ]; then
    exit 0
fi
# Source-build tools come from authenticated Debian packages, not rustup.
. "$repo_root/scripts/debian-apt-config.sh"
configure_cloud_apt
/usr/bin/apt-get update
/usr/bin/apt-get --download-only --reinstall -y install rustc cargo libstd-rust-dev \
    rustfmt rust-clippy age libsodium-dev libsodium23
mkdir -p "$tools_root/debian-rust" "$tools_root/debian-sodium"
for package in "$apt_root"/archives/rustc_*.deb "$apt_root"/archives/cargo_*.deb \
    "$apt_root"/archives/libstd-rust-*.deb "$apt_root"/archives/rustfmt_*.deb \
    "$apt_root"/archives/rust-clippy_*.deb "$apt_root"/archives/age_*.deb; do
    dpkg-deb -x "$package" "$tools_root/debian-rust"
done
for package in "$apt_root"/archives/libsodium-dev_*.deb "$apt_root"/archives/libsodium23_*.deb; do
    dpkg-deb -x "$package" "$tools_root/debian-sodium"
done
