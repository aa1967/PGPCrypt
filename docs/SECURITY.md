# Security boundaries

The app is an alpha, not an independently audited product. See the scoped
[alpha8 security review](SECURITY_REVIEW_ALPHA8.md) for findings and advisory limits. Its **encryption
container is standard age v1**, not a new crypto format. See
[ADR 001](ADR-001-vault-format.md) and [the schema](VAULT_FORMAT.md).

## Implemented protections

The Rust worker uses `age` 0.12.1 for complete passphrase-file encryption and
Sequoia OpenPGP 2.4/OpenSSL for OpenPGP operations. No primitives or OpenPGP
packet parsers are implemented by PGPCrypt. Cargo.lock pins registry checksums;
Debian supplies native libraries. The normal worker has no libsodium dependency
or legacy crypto codec. Debian libsodium is used only by the separate recovery
binary to read alpha1 files.

All public/private key bytes, identities, emails, fingerprints, profiles,
saved documents, notes and schema
metadata are inside encryption. There is no default GnuPG home/agent access,
background networking, telemetry, plaintext document autosave or external keyring
index. The user-requested recent-vault feature stores paths outside encryption
on this device by default; disable it in Vault settings to clear and stop recording
them. Paths may reveal identifying names, even without any PGP key metadata.
Notepad documents saved to the vault remain inside its encryption. Explicit
Export writes an ordinary file outside the vault; readable output requires
confirmation. Import loads text without automatically saving it.
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
Imported secret-key S2Ks are bounded before derivation (Argon2 at most 256 MiB,
10 passes, 4 lanes; at most 16 encrypted packet unlocks per operation and a
combined Argon2 work budget). Unsupported S2Ks fail explicitly. This caps
password-derivation work, not every possible parser/CPU cost. Validated self-bound
identities are displayed; ownership still needs a verified full fingerprint.
Text signing uses the standard cleartext framework; signing does not conceal text.

New passwords have no minimum or complexity requirement and are bounded to
128 Unicode characters. Local strength estimates are advisory. Older longer
passwords remain accepted for unlocking. Empty and short passwords have little
or no resistance to offline guessing; the limit is an input/work bound, not an
additional cryptographic protection. Passwords are used exactly as entered,
without trimming or normalization.

Private-key display/export verifies the password for every protected secret
packet without removing that protection from the export. Exports containing
unprotected packets also require the vault password. Keys with different packet
passwords cannot currently be exported through this single-password workflow;
normalize their protection first. These checks govern explicit actions inside
an already-unlocked trusted session; they do not isolate keys from that session.

The Qt6 session UI and worker disable core dumps/process dumpability. The worker
owns stored/generated private keys. Pasted private-key imports necessarily pass
through GUI buffers. Private pipes are bounded, requests/responses matched,
and crypto runs outside the GUI event loop. Lock confirms worker termination,
then replaces the UI process. Parent-death signals prevent live orphan workers.
The supervisor itself can outlive a desktop launcher that exits after launch.

## Profiles and emergency destruction

Profiles are encrypted organizational filters, not separate vaults or security
principals. The worker applies profile membership to crypto requests, while the
whole unlocked vault remains in trusted worker memory. Use separate vault files
for independently encrypted identities. Verification displays only validated
self-bound identities together with the full fingerprint.

Optional protection has a separate public master flag, purpose-separated
Argon2id password verifiers and an inactivity policy bound to ciphertext. Records
reveal feature presence, allow offline guessing and may expose unlock/deadline
timestamps; they contain no PGP keys or identities. Dummy sessions are empty and
read-only, without decrypting the real vault. A local-clock expiry check can
destroy an overdue copy before password authentication or decryption.
The trigger is best-effort in-place overwrite at unchanged byte length. It does
not guarantee physical erasure, plausible deniability, concealment of changes,
or deletion of Qubes snapshots/backups. Read [the exact limits](VAULT_PROTECTION.md).
Only disposable fixtures are used for destruction checks.

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
