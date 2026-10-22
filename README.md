# PGPCrypt alpha6 — Debian 13 amd64

Compiled evaluation package; Rust is not needed for installation.
Source: https://github.com/aa1967/PGPCrypt/tree/v0.1.0-alpha6

Download the `.deb` and SHA256SUMS using their Raw download links, then:

```sh
sha256sum --check SHA256SUMS
pgpcrypt_install_dir=$(mktemp -d /tmp/pgpcrypt-install.XXXXXX)
chmod 755 "$pgpcrypt_install_dir"
install -m 644 pgpcrypt_0.1.0.alpha6_amd64.deb "$pgpcrypt_install_dir/pgpcrypt.deb"
sudo apt update
sudo apt install "$pgpcrypt_install_dir/pgpcrypt.deb"
pgpcrypt
```

For a minimal Qubes guest without sudo, use a root guest terminal for APT and
launch PGPCrypt separately as the ordinary user. Keep vaults in that user's home.

Private-key passwords are optional with no minimum. Notepad contains recipients,
signing-key selection and text operations; its default signing key is encrypted
inside the vault and survives reopening/conversion. Vault passwords still
require 16 characters. Back up before upgrading: alpha6 reads old files, but
older PGPCrypt versions reject files saved with its new settings schema.
KeePassXC can still open the standard KDBX database. KDBX writing remains
experimental upstream. SOURCE_COMMIT identifies this package's source. This
download branch is separate from the source and is not intended to be merged.
