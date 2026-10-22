# Debian 13 installation

## Compiled package: runtime only

```sh
pgpcrypt_install_dir=$(mktemp -d /tmp/pgpcrypt-install.XXXXXX)
chmod 755 "$pgpcrypt_install_dir"
install -m 644 ~/Downloads/pgpcrypt_0.1.0.alpha7_amd64.deb "$pgpcrypt_install_dir/pgpcrypt.deb"
sudo apt update
sudo apt install "$pgpcrypt_install_dir/pgpcrypt.deb"
pgpcrypt
```

No Rust, Cargo, rustup, compiler or build headers are required. The package
contains the compiled Qt UI, compiled Rust worker, optional legacy converter,
menu entry and icon. APT installs Qt/OpenSSL/libsodium/libzxcvbn runtime libraries.
It installs no service, privileged helper, network listener or user GnuPG keyring.

Remove it with `sudo apt remove pgpcrypt`; user-created vaults remain untouched.
A public APT repository is not required for local `.deb` installation.

## Source build with Debian-packaged tools

```sh
sudo apt update
sudo apt install -y git ca-certificates
git clone --branch v0.1.0-alpha7 https://github.com/aa1967/PGPCrypt.git
cd PGPCrypt
./scripts/install-debian.sh --build
pgpcrypt
```

The script installs build tools using APT and builds/installs the package. Rust 1.89+ is required; the installer obtains Rust/Cargo 1.96.1 from signed Debian 13 backports. Runtime package installation needs neither Rust nor backports. No separate toolchain website is used.

To build without installing:

```sh
./scripts/build-deb.sh
python3 scripts/check-deb.py dist/pgpcrypt_0.1.0.alpha7_amd64.deb
```

## Reproducibility and validation limits

Runtime dependencies intentionally exclude rustc/cargo/rustup. Release binaries
have no workspace-specific RPATH/RUNPATH. Third-party licenses and application
source/build instructions are included. The archive checker tests the packaged
workflows without a system install; that is distinct from fresh-VM install/removal.
See VALIDATION.md for actual evidence.

`dist/SHA256SUMS` detects accidental artifact corruption; it is not a signed
publisher identity. A public release additionally needs license/compliance
review, maintained builds, a signed update/distribution policy and release testing.
The scripts build locally and do not publish anything.

## Permission messages

APT's `Download is performed unsandboxed as root` notice for a local `.deb`
usually means `_apt` cannot read the file or traverse a private home directory.
The notice alone is not an installation failure. Use a fresh readable `/tmp`
directory and mode-644 copy as above; do not make your home directory public
or disable APT sandboxing. The source/package installer stages the archive
that way automatically.

Launch `pgpcrypt` as your ordinary desktop user. Create defaults to
`~/vault.pgpcrypt.age`, and short filenames resolve under your home. The vault
directory must exist and allow your user to create/replace files; the adjacent
`.lock` file must also be accessible. The app identifies which file operation
failed and preserves the OS error. It does not change ownership or permissions
on existing vaults. If a previous vault was created as root or belongs to
another account, use a directory and vault copy owned by your account rather
than running the GUI with sudo. Existing destinations are never overwritten.
