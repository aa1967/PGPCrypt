# PGPCrypt alpha4 package

This branch holds a ready-to-install Debian 13 amd64 package while the GitHub
release workflow waits for a runner. Application source is at tag
[v0.1.0-alpha4](https://github.com/aa1967/PGPCrypt/tree/v0.1.0-alpha4).
The package contains its source archive and dependency notices.

## Download and install

```sh
sudo apt update
sudo apt install -y curl ca-certificates
pgpcrypt_install_dir=$(mktemp -d /tmp/pgpcrypt-install.XXXXXX)
chmod 755 "$pgpcrypt_install_dir"
cd "$pgpcrypt_install_dir"
curl --fail --location --remote-name https://raw.githubusercontent.com/aa1967/PGPCrypt/alpha4-packages/pgpcrypt_0.1.0.alpha4_amd64.deb
curl --fail --location --remote-name https://raw.githubusercontent.com/aa1967/PGPCrypt/alpha4-packages/SHA256SUMS
sha256sum --check SHA256SUMS
chmod 644 pgpcrypt_0.1.0.alpha4_amd64.deb
sudo apt install ./pgpcrypt_0.1.0.alpha4_amd64.deb
pgpcrypt
```

Create defaults to `~/vault.pgpcrypt.age`. Run the app as your ordinary user.
Alpha software: keep backups and evaluate using disposable keys.
