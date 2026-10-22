# PGPCrypt alpha7 — Debian 13 amd64

Compiled evaluation package; Rust is not needed to install it.
Source: https://github.com/aa1967/PGPCrypt/tree/v0.1.0-alpha7
Settings: https://github.com/aa1967/PGPCrypt/blob/v0.1.0-alpha7/docs/SETTINGS.md
Qubes setup: https://github.com/aa1967/PGPCrypt/blob/v0.1.0-alpha7/docs/QUBES.md

Download the `.deb` and SHA256SUMS using their Raw links, then:

```sh
sha256sum --check SHA256SUMS
pgpcrypt_install_dir=$(mktemp -d /tmp/pgpcrypt-install.XXXXXX)
chmod 755 "$pgpcrypt_install_dir"
install -m 644 pgpcrypt_0.1.0.alpha7_amd64.deb "$pgpcrypt_install_dir/pgpcrypt.deb"
sudo apt update
sudo apt install "$pgpcrypt_install_dir/pgpcrypt.deb"
pgpcrypt
```

In a minimal Qubes guest without sudo, use a root guest terminal for APT and
launch the GUI separately as the ordinary user. Keep vaults in that user's home.

Automatic locking and clipboard clearing are now off until enabled in Settings.
Settings also contains themes and conversion. Notes page removed with saved
contents retained; key passwords are prompted on demand. Subkey management is
under Keys. Qubes Sign/Decrypt/Lock services require opt-in and reviewed dom0
policy; actual Qubes transport/host events still need VM evaluation. Guest
installation does not install dom0 policy or lock hooks.

Back up before upgrading: older PGPCrypt cannot reopen the new settings schema.
KeePassXC remains compatible. This is alpha software; KDBX writing is marked
experimental upstream. SOURCE_COMMIT identifies this package's source. Do not
merge this standalone download branch into the source branch.
