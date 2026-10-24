#!/bin/sh
set -eu
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"
./scripts/build-desktop.sh --release
./scripts/dev.sh build --release --locked --features legacy-migration --bin pgpcrypt-migrate --bin pgpcrypt-qrexec -j 4
package_version=${PGPCRYPT_PACKAGE_VERSION:-0.1.0~alpha15}
dpkg --validate-version "$package_version"
# GitHub release uploads normalize '~' to '.', so choose that filename before
# computing checksums. Debian's internal Version retains prerelease ordering.
filename_version=$(printf '%s' "$package_version" | tr '~' '.')
package_arch=$(dpkg --print-architecture)
stage=$(mktemp -d "$repo_root/target/package.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
install -d "$stage/DEBIAN" "$stage/usr/bin" "$stage/usr/lib/pgpcrypt" \
    "$stage/usr/share/applications" "$stage/usr/share/icons/hicolor/scalable/apps" \
    "$stage/usr/share/doc/pgpcrypt"
install -m 755 target/release/pgpcrypt-worker target/release/pgpcrypt-desktop target/release/pgpcrypt-migrate target/release/pgpcrypt-qrexec "$stage/usr/lib/pgpcrypt/"
strip --strip-unneeded "$stage/usr/lib/pgpcrypt/pgpcrypt-desktop"
install -m 755 packaging/pgpcrypt-launcher "$stage/usr/bin/pgpcrypt"
ln -s ../lib/pgpcrypt/pgpcrypt-migrate "$stage/usr/bin/pgpcrypt-migrate"
install -d "$stage/etc/qubes-rpc"
install -m 755 packaging/qubes/pgpcrypt.Sign packaging/qubes/pgpcrypt.Decrypt packaging/qubes/pgpcrypt.Lock "$stage/etc/qubes-rpc/"
install -m 644 packaging/pgpcrypt.desktop "$stage/usr/share/applications/"
install -m 644 packaging/pgpcrypt.svg "$stage/usr/share/icons/hicolor/scalable/apps/"
install -m 644 README.md "$stage/usr/share/doc/pgpcrypt/"
cp -R docs "$stage/usr/share/doc/pgpcrypt/design"
install -d "$stage/usr/share/doc/pgpcrypt/third-party-licenses"
cp -R packaging/licenses/. "$stage/usr/share/doc/pgpcrypt/third-party-licenses/"
# Include this prototype's sources/build instructions for local inspection and
# rebuilding, rather than distributing only an opaque linked executable.
tar -czf "$stage/usr/share/doc/pgpcrypt/source.tar.gz" \
    Cargo.toml Cargo.lock rust-toolchain.toml src desktop scripts tests packaging docs .github README.md .gitignore
./scripts/dev.sh metadata --locked --all-features --format-version 1 > "$stage/usr/share/doc/pgpcrypt/cargo-metadata.json"
python3 - "$stage/usr/share/doc/pgpcrypt" <<'PY'
import json, pathlib, shutil, sys
root = pathlib.Path(sys.argv[1])
metadata = json.loads((root/'cargo-metadata.json').read_text())
packages = []
for package in metadata['packages']:
    if package['name'] == 'pgpcrypt':
        continue
    packages.append({key: package.get(key) for key in ('name','version','license','repository')})
    source = pathlib.Path(package['manifest_path']).parent
    destination = root/'third-party-licenses'/(package['name']+'-'+package['version'])
    for entry in source.iterdir():
        if entry.is_file() and entry.name.upper().startswith(('LICENSE','COPYING','COPYRIGHT','NOTICE')):
            destination.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(entry,destination/entry.name)
(root/'dependencies.json').write_text(json.dumps(packages,indent=2)+'\n')
# Build-machine paths do not belong in installed documentation.
(root/'cargo-metadata.json').unlink()
PY
cat > "$stage/usr/share/doc/pgpcrypt/copyright" <<'EOF'
PGPCrypt is an experimental local-evaluation build.
No public redistribution license has yet been selected for the application.
Third-party components retain their own licenses; see dependencies.json and
third-party-licenses. Application source/build instructions are in source.tar.gz.
Complete a license/compliance review before publishing a distribution repository.
EOF
find "$stage/usr/share/doc/pgpcrypt" -type d -exec chmod 755 {} +
find "$stage/usr/share/doc/pgpcrypt" -type f -exec chmod 644 {} +
installed_size=$(du -sk "$stage/usr" | cut -f1)
cat > "$stage/DEBIAN/control" <<EOF
Package: pgpcrypt
Version: $package_version
Section: utils
Priority: optional
Architecture: $package_arch
Maintainer: PGPCrypt contributors
Installed-Size: $installed_size
Depends: libc6 (>= 2.41), libgcc-s1, libssl3t64 (>= 3.5.7-1~deb13u3), libsodium23, libzxcvbn0, libqt6core6t64 (>= 6.8.2), libqt6gui6 (>= 6.8.2), libqt6widgets6 (>= 6.8.2), libqt6dbus6 (>= 6.8.2), libqt6network6 (>= 6.8.2), qt6-qpa-plugins, qt6-wayland
Description: Experimental encrypted OpenPGP vault and desktop text workspace
 Stores public and private OpenPGP keys and notes in a passphrase-encrypted vault.
 Qt6 desktop interface with a separate Rust crypto worker.
 Standard age v1 or KDBX 4.1 vault encryption; application alpha for local evaluation.
EOF
mkdir -p dist
archive="$repo_root/dist/pgpcrypt_${filename_version}_${package_arch}.deb"
dpkg-deb --root-owner-group --build "$stage" "$archive"
(cd dist && sha256sum "pgpcrypt_${filename_version}_${package_arch}.deb" > SHA256SUMS)
printf '%s\n' "$archive"
