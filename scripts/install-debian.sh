#!/bin/sh
# End users installing a package do not install Rust or any build tools.
set -eu
usage() {
    cat <<'EOF'
Usage:
  ./scripts/install-debian.sh --package /path/to/pgpcrypt.deb
  ./scripts/install-debian.sh --build

--package installs an already compiled package and Debian runtime dependencies.
--build installs build tools through APT, builds this checkout, then installs it.
No website visit, rustup, or separate Rust installer is used.
EOF
}
case "${1:-}" in
    --help|-h) usage; exit 0 ;;
    --package) test "$#" -eq 2 || { usage; exit 2; } ;;
    --build) test "$#" -eq 1 || { usage; exit 2; } ;;
    *) usage; exit 2 ;;
esac
. /etc/os-release
if [ "$ID" != debian ] || [ "$VERSION_ID" != 13 ]; then
    echo "This installer targets Debian 13." >&2; exit 1
fi
sudo_cmd=""
if [ "$(id -u)" -ne 0 ]; then command -v sudo >/dev/null; sudo_cmd=sudo; fi
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
$sudo_cmd apt-get update
if [ "$1" = --build ]; then
    $sudo_cmd apt-get install -y build-essential pkg-config libssl-dev clang libclang-dev \
        qt6-base-dev qt6-wayland rustc cargo python3 binutils dpkg-dev \
        desktop-file-utils libsodium-dev age gnupg
    cd "$repo_root"
    ./scripts/build-deb.sh
    package_version=${PGPCRYPT_PACKAGE_VERSION:-0.1.0~alpha2}
    archive="$repo_root/dist/pgpcrypt_${package_version}_$(dpkg --print-architecture).deb"
else
    archive=$(realpath -- "$2")
    test -f "$archive"
fi
$sudo_cmd apt-get install -y "$archive"
printf '%s\n' "Installed. Run: pgpcrypt"
