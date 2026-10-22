# Debian 13 installation

## Compiled package: runtime only

```sh
cd ~/Downloads
sudo apt update
sudo apt install ./pgpcrypt_0.1.0.alpha3_amd64.deb
pgpcrypt
```

No Rust, Cargo, rustup, compiler or build headers are required. The package
contains the compiled Qt UI, compiled Rust worker, optional legacy converter,
menu entry and icon. APT installs Qt/OpenSSL/libsodium runtime libraries.
It installs no service, privileged helper, network listener or user GnuPG keyring.

Remove it with `sudo apt remove pgpcrypt`; user-created vaults remain untouched.
A public APT repository is not required for local `.deb` installation.

## Source build with Debian-packaged tools

```sh
sudo apt update
sudo apt install -y git ca-certificates
git clone --branch v0.1.0-alpha3 https://github.com/aa1967/PGPCrypt.git
cd PGPCrypt
./scripts/install-debian.sh --build
pgpcrypt
```

The script installs build tools using APT and builds/installs the package. Rust 1.85.1 from Debian 13 is supported. No separate toolchain website is used.

To build without installing:

```sh
./scripts/build-deb.sh
python3 scripts/check-deb.py dist/pgpcrypt_0.1.0.alpha3_amd64.deb
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
