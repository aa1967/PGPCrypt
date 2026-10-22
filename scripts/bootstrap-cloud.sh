#!/bin/sh
set -eu
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tools_root=$(dirname -- "$repo_root")/.pgpcrypt-tools
apt_root="$tools_root/apt"
# Source-build tools come from authenticated Debian packages, not rustup.
. "$repo_root/scripts/debian-apt-config.sh"
configure_cloud_apt
/usr/bin/apt-get update
/usr/bin/apt-get --download-only --reinstall -y install -t trixie-backports rustc cargo libstd-rust-dev \
    rustfmt rust-clippy
/usr/bin/apt-get --download-only --reinstall -y install age libsodium-dev libsodium23
mkdir -p "$tools_root/debian-rust" "$tools_root/debian-sodium"
for package in "$apt_root"/archives/libllvm22_*.deb "$apt_root"/archives/rustc_*.deb "$apt_root"/archives/cargo_*.deb \
    "$apt_root"/archives/libstd-rust-*.deb "$apt_root"/archives/rustfmt_*.deb \
    "$apt_root"/archives/rust-clippy_*.deb "$apt_root"/archives/age_*.deb; do
    case "$(dpkg-deb -f "$package" Package)" in
        rustc|cargo|rustfmt|rust-clippy|libstd-rust*)
            case "$(dpkg-deb -f "$package" Version)" in *bpo13*) ;; *) continue ;; esac ;;
    esac
    dpkg-deb -x "$package" "$tools_root/debian-rust"
done
for package in "$apt_root"/archives/libsodium-dev_*.deb "$apt_root"/archives/libsodium23_*.deb; do
    dpkg-deb -x "$package" "$tools_root/debian-sodium"
done
