# PGPCrypt alpha5 — Debian 13 amd64

Compiled evaluation package. Rust is not needed to install it. Source and
Qubes/KDBX guidance: https://github.com/aa1967/PGPCrypt/tree/v0.1.0-alpha5

Download the `.deb` and `SHA256SUMS` from this branch using the **Raw** download
links, then install in the Debian 13 guest:

```sh
sha256sum --check SHA256SUMS
pgpcrypt_install_dir=$(mktemp -d /tmp/pgpcrypt-install.XXXXXX)
chmod 755 "$pgpcrypt_install_dir"
install -m 644 pgpcrypt_0.1.0.alpha5_amd64.deb "$pgpcrypt_install_dir/pgpcrypt.deb"
sudo apt update
sudo apt install "$pgpcrypt_install_dir/pgpcrypt.deb"
pgpcrypt
```

In a minimal Qubes guest without sudo, use a root guest terminal for APT and
launch PGPCrypt separately as the ordinary user. Keep vaults under that user's
home. Use disposable keys and backups: this is alpha software. Optional KDBX
writing is experimental upstream. No qrexec service or dom0 lock bridge is
installed. SOURCE_COMMIT identifies the source for this package. This standalone
download branch is not intended to be merged into the source branch.
