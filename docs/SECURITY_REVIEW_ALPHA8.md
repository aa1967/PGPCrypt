# Alpha8 security review and next steps

This is a focused source review and dependency-advisory comparison, not an
independent audit. It cannot establish that the application is safe against
every known attack. The locked-file objective is to conceal the entire PGP
keyring; public exports, messages and signatures have separate privacy limits.

## Findings addressed in this change

| Finding | Change | Practical limit |
| --- | --- | --- |
| Signing produced an opaque signed OpenPGP message, whose `PGP MESSAGE` heading looked like encryption. | Text signing now produces readable `PGP SIGNED MESSAGE` output. Verification continues to accept cleartext and opaque signatures. | Cleartext signatures canonicalize whitespace; exact-byte file signatures need a detached-signature workflow. |
| A certificate may contain both protected and unprotected signing keys. Selecting its first signing key could prompt for a password even when an unprotected signing key was usable. | Signing considers usable candidates and tries an unprotected signing key without a password first. Actual password failures trigger the dialog; an empty password remains valid input. | Different subkeys can have different passwords. Explicit signing-subkey selection would make this more visible. |
| Imported secret-key password derivation could request excessive Argon2 memory or repeated expensive derivations. | Secret-unlock paths share bounds for S2K parameters and an operation budget before derivation. Unsupported protection methods fail explicitly. | These are resource ceilings, not a hard execution deadline. Legacy weak protection remains possible on imported keys. |
| Raw imported user IDs could appear as ordinary identity labels without a current, valid self-binding. | Primary identity displays use policy-validated self-bindings. | A valid self-binding proves that the key asserted the identity, not that the person owns it. Verify full fingerprints independently. |
| A KeePassXC save made while PGPCrypt held an older snapshot could be overwritten on the next PGPCrypt save. | Saves check the existing ciphertext against the opened/saved snapshot and refuse external changes, deletion or unsafe path replacement. | Applications do not share a locking protocol. A check followed by rename cannot prevent every race with an uncooperative concurrent writer; open the vault in one application at a time. |
| A directory-sync failure after atomic replacement could be handled as though the write had not committed. | The committed-write error is distinguished from a pre-commit failure; the session locks rather than continuing with a conflicting snapshot. | Filesystem durability after a sync error is uncertain. Reopen the file and restore a separately retained backup if needed. |

Functional validation for these changes is recorded separately in
[VALIDATION.md](VALIDATION.md), after the source push. This document does not
turn a planned check into a passed check.

## Encryption and key-handling conclusions

- The app delegates cryptographic primitives and OpenPGP packets to age,
  Sequoia/OpenSSL and keepass-rs. Fresh library-generated keys, salts and file
  keys are used. There is no application-designed cipher or nonce scheme.
- age v1 uses a random 128-bit file key. Its passphrase profile uses scrypt;
  password entropy still limits resistance to offline guessing. KDBX4 uses its
  standard authenticated header/block construction and Argon2id profile.
- Policy checks reject unsuitable, expired or revoked keys for new operations;
  decryption can require old keys to recover historical ciphertext. Legacy
  import compatibility is not an endorsement of weak algorithms for new keys.
- Authentication is checked before exposing decrypted content. Keep this rule
  when adding streaming, attachments or large-file output. Never release
  unauthenticated partial plaintext to a viewer or destination file.
- Lock replaces the UI process and terminates the key worker. Qt buffers,
  clipboard managers, swap, host captures and a compromised unlocked qube
  remain outside a reliable erasure guarantee.
- Optional private-key passwords protect exported secret packets. They are
  separate from the vault password; leaving them blank does not remove the
  encrypted vault's protection, but makes any private-key export more sensitive.

## Dependency advisory comparison

On 22 October 2026, the locked 291 packages were compared with the official
[RustSec advisory database snapshot
`640bf5a9`](https://github.com/RustSec/advisory-db/tree/640bf5a9f06e66d8721e8772766531fe77c8630d).
There were 51 advisory records for crate names present in this lockfile. A
read-only range comparison found no vulnerable-version match in those records.
This was a lightweight advisory comparison, not a `cargo audit` run, a supply
chain audit or a guarantee about undisclosed vulnerabilities and native code.

One applicable **maintenance warning** remains:
[RUSTSEC-2026-0374](https://rustsec.org/advisories/RUSTSEC-2026-0374.html) marks
`basic-toml` 0.1.10 unmaintained and lists no patched release. It arrives through
age's localization build dependencies (`i18n-config` and `i18n-embed` procedural
macros). It is not the runtime vault parser. Track upstream replacement and
repeat advisory checks when updating dependencies; do not describe this warning
as a discovered vault decryption vulnerability.

The locked age 0.12.1 is newer than the fixes for
[its 2024 plugin issue](https://rustsec.org/advisories/RUSTSEC-2024-0433.html).
Sequoia 2.4.2 is newer than the fixes for its
[2023 parsing panic](https://rustsec.org/advisories/RUSTSEC-2023-0038.html),
[2024 parser loop](https://rustsec.org/advisories/RUSTSEC-2024-0345.html) and
[2025 ECDH unwrap panic](https://rustsec.org/advisories/RUSTSEC-2025-0136.html).
No keepass 0.17.0 advisory record appeared in the fetched database; its upstream
still calls KDBX4.1 writing **experimental**. Standard KDBX framing and successful
KeePassXC interoperability do not substitute for independent review of that
implementation.

The first check found Debian OpenSSL `3.5.7-1~deb13u2` on the cloud machine. A
refreshed, authenticated Debian security index identified
`3.5.7-1~deb13u3`; the verified packages were downloaded and extracted without
replacing host system files. Its Debian changelog explicitly includes
`CVE-2026-54872` (non-NIST curve scalar-multiplication timing) and the other
September security fixes. Alpha8 requires `libssl3t64 >= 3.5.7-1~deb13u3` and
uses the updated library for cloud builds and validation. The target Debian
system must retain security updates.

The Debian security tracker and OpenSSL's live advisory website were blocked
by this environment's network policy. The accessible official OpenSSL source
[NEWS](https://github.com/openssl/openssl/blob/50b6c3085ac69129d6676f6c467bf2705fecec50/NEWS.md)
and [CHANGES](https://github.com/openssl/openssl/blob/50b6c3085ac69129d6676f6c467bf2705fecec50/CHANGES.md)
list 3.5.8 and 3.5.9 security releases. Many items concern TLS, QUIC, CMS or CMP,
outside the app's normal paths, but there are also cryptographic API and curve
timing fixes. Debian's authenticated package and changelog establish its
backports despite the unchanged upstream `3.5.7` version. This is a targeted
OpenSSL check; it is not a complete advisory assessment of Qt, the kernel and
every other native runtime component.

## KDBX portability and corruption boundaries

Keys remain standard armored OpenPGP text in protected custom fields, with
ordinary entry titles and fingerprints for finding them in KeePassXC. Public
and private armor can be copied into another OpenPGP application. The vault
password is not stored in those fields, nor are separate key passwords.

The adapter authenticates KDBX, bounds KDF work, validates its supported XML
profile and rejects unsupported features rather than silently discarding them.
Supported unrelated entries are retained during ordinary saves. Conversion to
another format copies PGPCrypt data; it is not a general KeePass database
converter. Existing source files remain intact. See
[KDBX_COMPATIBILITY.md](KDBX_COMPATIBILITY.md) for the exact profile.

Atomic replacement reduces partial-write corruption; authentication detects
modified ciphertext. Neither can recover a deleted file, reliably repair
corruption, detect every rollback to an older valid snapshot or replace backups.
Retain a separate encrypted backup and verify it opens with KeePassXC before
depending on it for long-term recovery.

## Recommended features, in priority order

1. **Recovery and retirement kit.** Guided encrypted backups, an independent
   reopen/restore check, and an export manifest containing public/private armor,
   revocation certificates and simple recovery instructions. This would make
   leaving the application practical without relying on its future availability.
2. **Fingerprint trust records.** Record independently checked fingerprints,
   warn on identity collisions/key changes and show signature validity separately
   from identity trust. A QR fingerprint comparison could reduce transcription
   mistakes without requiring a network service.
3. **Detached signatures and sign-and-encrypt.** Support exact-byte file signing,
   visible signer/subkey selection and one clear operation that signs before
   encrypting. Preserve authentication-before-output for file decryption.
4. **Privacy preview.** Before export or encryption, show which identities,
   comments, recipient identifiers and signer identifiers the resulting artifact
   can reveal. An optional anonymous-recipient mode can hide PKESK recipient key
   IDs; it does not hide every metadata relationship, signer information or
   traffic pattern and increases decryption work.
5. **Hardware/offline primary-key workflow.** Keep certification keys offline,
   use scoped signing/encryption subkeys and support established hardware-backed
   OpenPGP interfaces. Define recovery first. A TOTP prompt alone cannot add
   cryptographic protection to an offline encrypted file; alternative age
   recipients are separate unlock routes, not an AND-style second factor.
6. **Qubes permissions by task and key.** Bind named client qubes to selected
   signing keys and permitted operations, with per-request approval, rate limits
   and clear content previews. Keep a separate offline vault for certification
   material. Validate the policy and host-lock hook in a real Qubes system.
7. **Release and parser assurance.** Signed APT releases, reproducible-build
   comparisons, a dependency inventory, recurring advisory review, malformed-input
   fuzzing and an independent assessment before treating the app as mature key
   custody software.

These are recommendations, not claims of novelty or features already present.

## Primary references

- [age format specification](https://github.com/C2SP/C2SP/blob/fea9004f73fbec8cf7a8b1936430e2487eb23b55/age.md): file keys, authenticated framing and independent recipient wrapping.
- [Sequoia 2.4.2 API](https://docs.rs/sequoia-openpgp/2.4.2/sequoia_openpgp/): policy, cleartext signing and secret-key protection APIs; the locally cached matching crate source was inspected.
- [keepass-rs v0.17.0 README](https://github.com/sseemayer/keepass-rs/blob/v0.17.0/README.md): supported formats and experimental writer status.
- [KeePassXC 2.7.10 KDBX4 reader](https://github.com/keepassxreboot/keepassxc/blob/2.7.10/src/format/Kdbx4Reader.cpp): header and block authentication behavior used as an interoperability reference.
- [RustSec database](https://github.com/RustSec/advisory-db): the advisory snapshot and individual records cited above.
- [Debian security archive](https://security.debian.org/debian-security/): authenticated package indexes and the downloaded `3.5.7-1~deb13u3` package's `changelog.Debian.gz` provided the backport evidence.
- [Debian OpenSSL security tracker](https://security-tracker.debian.org/tracker/source-package/openssl) and [OpenSSL vulnerabilities](https://openssl-library.org/news/vulnerabilities/index.html): these live advisory pages could not be read in this environment; the signed Debian archive and official OpenSSL source supplied the narrower evidence above.
