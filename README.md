# PGPCrypt

An encrypted OpenPGP key vault and text workspace for **Debian 13 amd64**.
Alpha software; keep backups and use disposable keys while evaluating it.

## Install

Download and install from the command line. These verified direct downloads
are available independently of the GitHub release workflow:

```sh
sudo apt update
sudo apt install -y curl ca-certificates
pgpcrypt_install_dir=$(mktemp -d /tmp/pgpcrypt-install.XXXXXX)
chmod 755 "$pgpcrypt_install_dir"
cd "$pgpcrypt_install_dir"
curl --fail --location --remote-name https://raw.githubusercontent.com/aa1967/PGPCrypt/alpha9-packages/pgpcrypt_0.1.0.alpha9_amd64.deb
curl --fail --location --remote-name https://raw.githubusercontent.com/aa1967/PGPCrypt/alpha9-packages/SHA256SUMS
sha256sum --check SHA256SUMS
chmod 644 pgpcrypt_0.1.0.alpha9_amd64.deb
sudo apt install ./pgpcrypt_0.1.0.alpha9_amd64.deb
pgpcrypt
```

Keep Debian security updates enabled. No Rust or compiler installation is needed. You can also launch PGPCrypt from
the application menu.

## Build and install from source

```sh
sudo apt update
sudo apt install -y git ca-certificates
git clone --branch v0.1.0-alpha9 https://github.com/aa1967/PGPCrypt.git
cd PGPCrypt
./scripts/install-debian.sh --build
pgpcrypt
```

The installer gets all build dependencies, including Rust, through APT.

## Remove

```sh
sudo apt remove pgpcrypt
```

Your vault files are kept.
