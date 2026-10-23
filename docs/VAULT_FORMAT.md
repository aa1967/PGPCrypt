# Vault format: age v1 plus encrypted schema 8

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
  "schema": 8,
  "data": {
    "certificates": [],
    "notes": "",
    "revocations": [],
    "idle_timeout_seconds": 300,
    "default_signing_key": "",
    "profiles": [],
    "documents": [],
    "preferences": {
      "auto_lock": false,
      "lock_on_focus_loss": false,
      "lock_on_session_events": false,
      "clipboard_clear_seconds": 0,
      "theme": "light",
      "qubes_rpc": false,
      "notepad_popout": false,
      "activity_clear_seconds": 0,
      "show_session_stats": false,
      "allow_removable_media": false
    }
  }
}
```

`certificates` contains arrays of transferable OpenPGP bytes, including secret
material when present. All identity data and indexes are inside encryption.
`revocations` contains objects with `fingerprint` and `armor` fields: emergency
revocation signatures are kept separate from the certificates so storing a ticket
does not apply it. `idle_timeout_seconds` ranges from 60 to 3600.

Schema-1 vaults are read with empty revocations and a 300-second timeout.
Schemas 1 and 2 default to no saved signing key. Schemas 1–3 default to all
automatic locking, clipboard wiping and RPC options off. Every save writes
schema 8 with encrypted preferences, identity fields, profiles and documents. Schemas 1–4
default to empty profiles/documents. `default_signing_key` is empty for no
default; inactivity duration remains 60–3600 seconds but has no effect until
`preferences.auto_lock` is enabled. Clipboard delay is 0 (off) or 5–1800 seconds.
Schemas 1–5 default missing identity fields to empty strings. Missing `preferences.notepad_popout` now defaults to false; explicitly stored
values remain unchanged. Schema 8 adds optional activity/media/counter preferences;
activity clearing is 0 or 5–3600 seconds and counters/media default off. The Notepad option controls
window layout and adds no independent worker or copy of the editor state. Older PGPCrypt releases reject schema 8; preserve a backup before upgrading. Unknown fields and unsupported versions are rejected.
The schema version is private, separate from the public age format version.

The writer pads JSON with spaces to a 4096-byte boundary inside encryption.
Maximum decoded payload is 16 MiB; encrypted input is bounded at 17 MiB before
parsing. No compression is used. Fully consume and authenticate the age stream
before returning data; never return a partially verified vault.

`profiles` contains `{id,name,username,email,url,notes,fingerprints}` objects.
The optional identity fields are private organizational metadata, not changes to
the public OpenPGP identity. Usernames and emails are bounded to 256 characters,
URLs to 2048, and notes to 16 KiB, using portable XML text. IDs are random 128-bit
lowercase hexadecimal identifiers; names are unique ignoring case, have 1–80
characters without controls, and cannot be All. Membership references known
certificate fingerprints without duplicates. There are at most 64 profiles.
`documents` contains `{id,title,text,profile_id,created_at,updated_at}` objects.
Titles have 1–120 characters without controls, text is at most 4 MiB, and the
profile reference is empty or valid. New titles are unique ignoring case within
a profile; blank titles become `untitled` and collisions receive ` (1)`, ` (2)`,
and so on. Older snapshots with duplicate titles remain readable; a later save
or move resolves a collision for the affected document. Timestamps are Unix seconds. A vault has
at most 1024 documents within its overall 16 MiB bound. All is an implicit view,
not a stored profile. See [WORKSPACE.md](WORKSPACE.md).

## Persistence

Create/sync a same-directory 0600 temporary ciphertext file, atomically persist,
then sync the directory. Creation never overwrites an existing vault. Refuse
symlink destinations. Hold a nonblocking flock in an adjacent empty `.lock` file
throughout the unlocked session. This coordinates cooperating writers, not
malicious directory owners. No plaintext document sidecar or WAL is created.
The optional emergency destruction feature uses a separate public KDF verifier
and ciphertext binding; see [EMERGENCY_PASSWORD.md](EMERGENCY_PASSWORD.md).

## Alpha1 conversion

The retired `PGPVLT01` format is rejected by the app with migration guidance.
`pgpcrypt-migrate OLD NEW` reads it using Debian's libsodium and writes a separate
age vault. It never updates the old file and refuses an existing destination.
Its prompts do not echo passphrases or put them in arguments/environment variables.
The normal worker contains no legacy reader/writer. The old writer is removed.

Container validity does not authenticate a person's identity, prevent rollback,
hide file size/timestamps, or erase copies held by the operating system.

## Optional KDBX 4.1 (alpha5)

This document describes the age payload. KDBX files use the separate standard
KeePass container and ordinary entries described in
[KDBX_COMPATIBILITY.md](KDBX_COMPATIBILITY.md), rather than this JSON envelope.
Open detects magic bytes; creation requires an explicit format.
