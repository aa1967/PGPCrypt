# ADR 001: standard age v1 vault container

Status: accepted for alpha2. The user confirmed direct KeePassXC compatibility
is not required; a standard encrypted-file container is sufficient.

## Decision

Use the established age v1 encrypted-file format through the maintained Rust
`age` 0.12.1 crate. Use Sequoia OpenPGP for the independent OpenPGP operations.
Do not implement encryption framing, key wrapping, stream nonces, or password
hashing ourselves. The previous `PGPVLT01` container is retired from normal
operation and supported only by an explicit, read-only migration tool.

The encrypted plaintext has a versioned PGPCrypt JSON schema. A custom
application schema is not a custom encryption protocol. All identities,
certificates (including public keys), fingerprints and notes live inside that
payload. No plaintext keyring or external index is used.

## Why this choice

- age v1 is an established file-encryption specification with independent Go
  and Rust implementations. That provides a practical interoperability check.
- Its passphrase mode uses memory-hard scrypt and authenticated encryption;
  the library owns the complete construction rather than a new application codec.
- The small vault currently needs encrypted snapshots rather than a relational
  query engine. File encryption therefore fits its storage needs.
- Keeping Rust/Sequoia preserves existing tested OpenPGP operations and reduces
  memory-safety risks in the worker. Rust is a build-time choice, not a user
  runtime or a separate installer requirement.
- KDBX remains a valid alternative if KeePass compatibility becomes required.
  We did not select a Rust KDBX writer explicitly marked experimental, nor copy
  KeePassXC's cipher choice without its complete integrity construction.

This is a reasoned fit, not a claim that any format is universally best or that
the complete app is audited because it uses an established container.

## Cryptographic and operational profile

age v1 uses a fresh random **128-bit file key**, HKDF/HMAC-SHA-256 and
ChaCha20-Poly1305 authenticated encryption. It targets approximately 128-bit
security; it must not be advertised as a 256-bit-security vault merely because
ChaCha20 uses a 256-bit derived key. Passphrase entropy and offline-guessing cost
are separate limits.

PGPCrypt writes the standard scrypt recipient with N=2^18, r=8, p=1
(approximately 256 MiB). This cost is explicit and independent of compiler
optimization. Unlock caps the advertised work factor at 18 to bound memory/CPU
use before authentication. Valid externally created age passphrase files with a
lower cost can be read if they contain the supported schema; saves use cost 18.
The password is UTF-8 without trimming or normalization.

Every save uses the library to produce a fresh age file key/salt and a complete
finalized stream. Decode and authenticate the complete bounded stream before
exposing any parsed vault data. Writes remain private, ciphertext-only temporary
files followed by atomic replacement and sync. Retain advisory writer locking.

The passphrase must remain in a zeroizing secret in the worker while unlocked
because a fresh passphrase-encrypted age snapshot is produced on each save.
This is a deliberate memory-exposure tradeoff. The worker and session UI terminate
on lock; this cannot erase external copies, swap or hibernation images.

## Boundaries and future work

The outer header reveals age framing, salt and scrypt cost. Size, filename and
filesystem timestamps remain visible. Rollback, deletion and lost-passphrase
recovery are not solved by authenticated encryption.

Multiple age recipients are alternative unlock routes, not multi-factor AND
requirements. Adding a hardware recipient must not be described as MFA. USB,
hardware factors and recovery require a separately reviewed profile and UX.

## Evidence and sources

- [Stable age v1 specification](https://age-encryption.org/v1)
- [C2SP age specification](https://c2sp.org/age)
- [Rust age implementation](https://github.com/str4d/rage)
- [Go reference implementation](https://github.com/FiloSottile/age)
- [Vault schema](VAULT_FORMAT.md) and [validation report](VALIDATION.md)

Tests include independent Debian Go age decryption of app-generated vaults,
Go age re-encryption read back by PGPCrypt, wrong passphrases, modified/truncated/
appended ciphertext, metadata visibility checks, and legacy conversion.
