# PGPCrypt alpha9 Debian 13 amd64 download

This branch contains the validated package, not application source.
Do not merge it into main. Source is tag v0.1.0-alpha9, branch pgpcrypt-alpha9,
and SOURCE_COMMIT. All sources/build instructions and licenses are in the .deb.
SHA256SUMS checks integrity, not publisher identity.

Download the .deb and SHA256SUMS into one writable directory, verify with
`sha256sum --check SHA256SUMS`, then `sudo apt update` and
`sudo apt install ./pgpcrypt_0.1.0.alpha9_amd64.deb`.
No Rust compiler is needed. Keep Debian security updates enabled.

Alpha software: keep backups. Optional password/expiry destruction cannot hide
forensic evidence or erase SSD/COW/Qubes snapshots/backups. Dummy views are
empty/read-only. Read source docs/VAULT_PROTECTION.md before enabling protection.
Validation evidence is in docs/VALIDATION.md.
