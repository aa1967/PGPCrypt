# PGPCrypt alpha8 Debian 13 amd64 download

This branch contains the validated download package, not application source.
Do not merge it into main. Source: tag v0.1.0-alpha8 and branch pgpcrypt-alpha8.
SOURCE_COMMIT identifies the included source; all sources and licenses are also
inside the .deb. SHA256SUMS verifies download integrity, not publisher identity.

Download the .deb and SHA256SUMS into the same writable directory, run
`sha256sum --check SHA256SUMS`, then install with
`sudo apt update` and `sudo apt install ./pgpcrypt_0.1.0.alpha8_amd64.deb`.
No Rust compiler is needed. Enable Debian security updates.

Alpha software: keep backups. See the source's docs/SECURITY_REVIEW_ALPHA8.md
and docs/VALIDATION.md for evidence and remaining limits.
