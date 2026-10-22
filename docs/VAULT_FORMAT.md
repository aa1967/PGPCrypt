# Vault format: age v1 plus encrypted schema 2

The outer container is the unmodified [age v1 format](https://age-encryption.org/v1),
implemented by `age` 0.12.1. The app defines no crypto header, nonce format,
authentication-tag placement or key-wrapping construction. The accepted choice
and tradeoffs are in [ADR 001](ADR-001-vault-format.md).

## Public container

A new file starts with `age-encryption.org/v1`. It uses the standard passphrase
scrypt recipient, a fresh salt, authenticated header, and streaming authenticated
payload. It contains no OpenPGP identities or public-key recipients in its header.
The app writes work factor 18 (N=2^18, r=8, p=1) and caps unlock work at 18.
Do not label this Argon2id or AES encryption: those were other design options.

## Encrypted plaintext

After complete authenticated decryption, the plaintext is UTF-8 JSON:

```json
{
  "application": "PGPCrypt",
  "schema": 2,
  "data": {
    "certificates": [],
    "notes": "",
    "revocations": [],
    "idle_timeout_seconds": 300
  }
}
```

`certificates` contains arrays of transferable OpenPGP bytes, including secret
material when present. All identity data and indexes are inside encryption.
`revocations` contains objects with `fingerprint` and `armor` fields: emergency
revocation signatures are kept separate from the certificates so storing a ticket
does not apply it. `idle_timeout_seconds` ranges from 60 to 3600.

Schema-1 vaults are read with empty revocations and a 300-second timeout. Every
save writes schema 2. Older applications reject schema 2; preserve a backup
before upgrading. Unknown fields and unsupported versions are rejected.
The schema version is private, separate from the public age format version.

The writer pads JSON with spaces to a 4096-byte boundary inside encryption.
Maximum decoded payload is 16 MiB; encrypted input is bounded at 17 MiB before
parsing. No compression is used. Fully consume and authenticate the age stream
before returning data; never return a partially verified vault.

## Persistence

Create/sync a same-directory 0600 temporary ciphertext file, atomically persist,
then sync the directory. Creation never overwrites an existing vault. Refuse
symlink destinations. Hold a nonblocking flock in an adjacent empty `.lock` file
throughout the unlocked session. This coordinates cooperating writers, not
malicious directory owners. No plaintext sidecar or WAL is created.

## Alpha1 conversion

The retired `PGPVLT01` format is rejected by the app with migration guidance.
`pgpcrypt-migrate OLD NEW` reads it using Debian's libsodium and writes a separate
age vault. It never updates the old file and refuses an existing destination.
Its prompts do not echo passphrases or put them in arguments/environment variables.
The normal worker contains no legacy reader/writer. The old writer is removed.

Container validity does not authenticate a person's identity, prevent rollback,
hide file size/timestamps, or erase copies held by the operating system.
