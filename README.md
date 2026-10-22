# PGPCrypt

An encrypted OpenPGP key vault and text workspace for **Debian 13 amd64**.
Alpha software; keep backups and use disposable keys while evaluating it.

## Install

Download and install from the command line, or get the files from
[Releases](https://github.com/aa1967/PGPCrypt/releases):

```sh
sudo apt update
sudo apt install -y curl ca-certificates
cd ~/Downloads
curl --fail --location --remote-name https://github.com/aa1967/PGPCrypt/releases/download/v0.1.0-alpha3/pgpcrypt_0.1.0~alpha3_amd64.deb
curl --fail --location --remote-name https://github.com/aa1967/PGPCrypt/releases/download/v0.1.0-alpha3/SHA256SUMS
sha256sum --check SHA256SUMS
sudo apt install ./pgpcrypt_0.1.0~alpha3_amd64.deb
pgpcrypt
```

No Rust or compiler installation is needed. You can also launch PGPCrypt from
the application menu.

## Build and install from source

```sh
sudo apt update
sudo apt install -y git ca-certificates
git clone --branch v0.1.0-alpha3 https://github.com/aa1967/PGPCrypt.git
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
