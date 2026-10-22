# Security boundaries

The app is an alpha, not an independently audited product. Its **encryption
container is standard age v1**, not a new crypto format. See
[ADR 001](ADR-001-vault-format.md) and [the schema](VAULT_FORMAT.md).

## Implemented protections

The Rust worker uses `age` 0.12.1 for complete passphrase-file encryption and
Sequoia OpenPGP 2.4/OpenSSL for OpenPGP operations. No primitives or OpenPGP
packet parsers are implemented by PGPCrypt. Cargo.lock pins registry checksums;
Debian supplies native libraries. The normal worker has no libsodium dependency
or legacy crypto codec. Debian libsodium is used only by the separate recovery
binary to read alpha1 files.

All public/private key bytes, identities, emails, fingerprints, notes and schema
metadata are inside encryption. There is no default GnuPG home/agent access,
background networking, telemetry, plaintext autosave or external keyring index.
The complete vault stream authenticates before parsing; decrypted text is also
buffered until its OpenPGP reader finishes successfully. Unknown/invalid
signatures fail verification. Signature validity does not establish identity.

New age snapshots use scrypt N=2^18,r=8,p=1 and fresh library-generated file keys
and salts. Header work is capped before derivation. age v1 has a 128-bit random
file key and approximately 128-bit security; passphrase entropy is an additional
limit. Do not market it as 256-bit security merely from a cipher's key size.
The worker retains the passphrase in a zeroizing SecretString while unlocked
because saving makes a fresh standard passphrase-encrypted age file.

OpenPGP generation uses Ed25519/Cv25519, v4 certificates and approximately
three-year validity. Encryption selects AES-256; the integrity format follows
recipient features. GnuPG-compatible generated certificates advertise SEIPDv1;
SEIPDv2 AEAD is supported where advertised. StandardPolicy rejects weak document
signatures and unsuitable keys; modern RFC 9580 paths are tested separately.
Vault age encryption is independent of this OpenPGP interoperability choice.

The Qt6 session UI and worker disable core dumps/process dumpability. The worker
owns stored/generated private keys. Pasted private-key imports necessarily pass
through GUI buffers. Private pipes are bounded, requests/responses matched,
and crypto runs outside the GUI event loop. Lock confirms worker termination,
then replaces the UI process. Parent-death signals prevent live orphan workers.
The supervisor itself can outlive a desktop launcher that exits after launch.

## Remaining boundaries

- age framing, KDF cost/salt, size, filenames and filesystem metadata remain visible.
- Root, malware, keyloggers, screen capture and a compromised unlocked desktop
  are outside the locked-file confidentiality goal.
- Qt strings, clipboard managers, allocators, rendering caches, accessibility,
  input methods and library internals can retain copies. Memory is not universally
  locked. Process exit does not erase swap, hibernation or prior captures.
- Deletion does not securely erase SSD/snapshot/backup copies. A valid older vault
  can replace the current file undetected. Offline guessing cannot be rate-limited.
- Lock discards unsaved text/notes. Expensive jobs can be killed, but no hard
  real-time lock deadline is promised. Native GNOME/Plasma signal delivery still
  needs validation; current subscriptions are best-effort.
- File locks coordinate cooperating writers. Malicious directory owners and
  alternate-path aliases are not fully defended; use a directory you control.
- Public exports, recipient identifiers and signatures can identify/link people.
  This is not an anonymity guarantee or a way to retract already published keys.
- Backups/recovery UX, revocation management, passphrase changes, hardware factors,
  broader file workflows and parser fuzzing still require work before real custody.

An established crypto container does not replace dependency/advisory review,
license review, release hardening, realistic recovery tests or an independent
security assessment. Packaging validation is distinct from fresh-VM installation.
