# KDBX compatibility proposal

Supporting both age v1 and KDBX is feasible. KDBX is a different outer container,
not an age file renamed to `.kdbx`. A creation selector and detection on open can
share the existing OpenPGP worker while using separate persistence backends.
KDBX is not implemented in this version; there is no nonfunctional selector.

## Portable layout

Use a normal KDBX 4.1 database with Argon2id and AES-256, supported by current
KeePass 2 and KeePassXC. KeePassX and older KeePass versions may not support that
combination; compatibility must name the versions actually checked.

Put a `PGPCrypt` group in the database. Each certificate is a normal entry:

| KeePass field | Contents |
| --- | --- |
| Title | User-chosen name or pseudonym |
| UserName | Optional email |
| Notes | Public comment and full fingerprint |
| OpenPGP.PublicKey | Armored public certificate |
| OpenPGP.PrivateKey | Armored, separately passphrase-protected private certificate |
| OpenPGP.Revocation | Armored emergency revocation certificate |

Private material and revocation tickets should use protected custom fields.
The password field should remain empty: storing the private-key passphrase in
the same entry would weaken its independence. A separate notes entry and settings
entry store vault-wide notes and idle timeout. No plugin or proprietary binary
attachment is necessary to recover a key: open in KeePassXC/KeePass 2, reveal the
field, copy its armor to an OpenPGP tool, and supply the private-key passphrase.
All entry contents and identity-bearing metadata must remain inside KDBX
encryption. The usual filesystem/container size and KDF leakage still applies.

The app should recognize only its own group/fields, preserve unrelated entries,
history, attachments, metadata and unknown fields, and refuse unsupported
features instead of discarding them. This is especially important after a user
edits the database in KeePassXC. Write a fresh encrypted snapshot atomically,
hold a file lock, and never extract plaintext XML or keys to temporary files.
Conversion must write a new destination and leave the source unchanged.

## Current implementation constraint

The Rust `keepass` crate 0.17.0 describes its KDBX4.1 **writing as experimental**
and requires Rust 1.89. Debian 13 packages Rust 1.85.1. Adding that version now
would reintroduce a separate compiler installation and an experimental writer,
both contrary to this project's requirements. Pinning an old library just to
avoid that conflict also needs a security and compatibility review.

Before adding KDBX, select a maintained writer with a compatible toolchain or
reassess a supported backend integration. Bound advertised KDF memory/time,
authenticate before exposing plaintext, limit XML/decompression sizes, and
reject unsupported key-file/hardware requirements explicitly. Interoperability
must cover creation, edits and reopening in both KeePassXC and KeePass 2,
including protected custom fields and preservation of unrelated data. That work
is separate from simply implementing an XML field mapping.

## Recoverability of existing age vaults

age v1 is already an independently implemented container. With Debian's `age`
CLI you can recover the encrypted JSON without PGPCrypt:

```sh
sudo apt install age
age --decrypt /path/to/private.pgpcrypt.age
```

This prompts for the vault passphrase and prints the decrypted JSON to the
terminal. Use a private environment: terminal scrollback can retain it. The
`certificates` arrays contain standard OpenPGP bytes, not a proprietary key
format. Public/private armor exported from PGPCrypt is usable in other OpenPGP
software now. Private exports retain their separate key passphrase.

References:
- [KeePass KDBX format](https://keepass.info/help/kb/kdbx.html)
- [keepass crate 0.17.0](https://crates.io/crates/keepass/0.17.0)
- [keepass-rs upstream README](https://github.com/sseemayer/keepass-rs)
