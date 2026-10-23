# KDBX support

Create vault offers age v1 (default) or KDBX 4.1. Opening detects the format from
its contents, independently of the filename. OpenPGP operations use the same
Sequoia worker for both. KDBX persistence uses pinned `keepass` 0.17.0, whose
upstream describes writing as experimental. This integration remains alpha;
use disposable keys and backups until it has received independent review.

## Cryptography and supported profile

New KDBX files use AES-256-CBC with KDBX's authenticated header/HMAC block stream,
Argon2id v1.3 (64 MiB, 3 iterations, 1 lane), and ChaCha20 protected fields.
The maintained library performs all cryptographic operations. No new cipher,
KDF or encryption framing is defined by PGPCrypt. Saves regenerate salts and
keys, retaining the supported KDF settings of existing databases. Saves write
KDBX 4.1, including after KeePassXC has saved a compatible KDBX 4.0 snapshot. The application checks the public container framing before invoking it.

The first read/write profile accepts KDBX 4.0 and 4.1, AES-256, Argon2id v1.3, no
compression, a 32-byte salt, 64–256 MiB memory, 1–10 iterations and 1–4 lanes.
Files and authenticated XML are bounded to 16 MiB; XML nesting is limited to 32.
Unknown header/XML fields, XML doctypes, attachments, custom icons, compressed
files and public custom header data are refused. A complete authenticated block
stream must end exactly at EOF. These restrictions prevent unbounded KDF work,
decompression expansion and silent removal of unsupported plugin/future data.
No XML/entry data reaches the application until authentication succeeds.
Password-only unlock is supported; key files and hardware factors are not yet
implemented. Do not remove a key file from an existing database to make it open.

KeePassXC can open the generated standard database without a plugin. Keep
compression disabled and the supported KDF settings if saving it there for
reopening here. KeePass 2 compatibility follows the standard format but has not
been exercised in this environment. KeePassX's older formats are not supported.
PGPCrypt is not a general-purpose KeePass database editor.

## Recover keys without PGPCrypt

Open the database in KeePassXC and select its `PGPCrypt` group. Each key is a
normal entry with these custom attributes:

| Field | Contents |
| --- | --- |
| Title | First OpenPGP identity, or fingerprint |
| PGPCrypt.Type / PGPCrypt.Schema | `key` / `1` (do not edit) |
| OpenPGP.Fingerprint | Full fingerprint (do not edit) |
| OpenPGP.PublicKey | Armored public certificate |
| OpenPGP.PrivateKey | Armored private certificate, if present |
| OpenPGP.Revocation | Armored emergency revocation certificate, if present |

Each key entry includes short recovery instructions in its Notes. The three
armored fields use KeePass protected values. Reveal and copy the
needed armor into a trusted OpenPGP tool. Private packets retain their
independent password if one was chosen; it is never stored in a KeePass password field.
Keys created or imported without a key password have unprotected secret
packets inside the encrypted container; take care when copying those packets out.

The `Vault notes and settings` entry holds the protected `Notes` field and
`PGPCrypt.IdleTimeoutSeconds`, plus protected `PGPCrypt.DefaultSigningKey`
(empty means no default). The settings entry uses `PGPCrypt.Schema=4`; key
entries remain schema 1. Older settings are read with defaults for missing fields. Protected
`PGPCrypt.Preferences` holds JSON for themes, locking, clipboard clearing and
Qubes opt-in; all new automatic behaviors default off.
Protected `PGPCrypt.Profiles` contains profile IDs, names and key memberships as
JSON. Saved text documents are ordinary entries in the PGPCrypt group with
`PGPCrypt.Type=document`, `PGPCrypt.Schema=1`, Title, protected Notes, and
`PGPCrypt.DocumentId`, `PGPCrypt.ProfileId`, `PGPCrypt.CreatedAt` and
`PGPCrypt.UpdatedAt`. Read or copy their Notes in KeePassXC. Existing document
IDs and structural fields must remain valid. Deleted managed documents are
removed on save; supported unrelated entries outside the group remain intact.
Older PGPCrypt versions reject the new settings schema; KeePassXC can still
open the standard database. Structural markers and fingerprints must agree;
duplicate settings, duplicate fingerprints and unknown entries inside this
group are rejected. Put unrelated KeePass entries in another group or the root.
Supported unrelated entries, history and custom string fields are retained on
KDBX saves. Keep only one application open on a database at a time: PGPCrypt's
advisory lock is not KeePassXC's lock protocol. Alpha8 compares the encrypted
file against the opened/saved snapshot before saving and immediately before
replacement; detected outside changes are refused without overwriting them. Lock
and reopen to load KeePassXC changes. A small check/rename race remains with
non-cooperating editors, so simultaneous editing is unsupported. Atomic ciphertext
replacement, file fsync and directory fsync protect normal saves; if directory
sync fails after replacement, the session closes and must be reopened. Neither
this nor KDBX authentication substitutes for backups or detects rollback to an
older valid copy. Unsupported extensions fail
closed rather than being intentionally discarded.

## Convert without overwriting

Unlock the source, save any note edits, and select **Save converted copy…**.
Choose the target format, a new filename and a new confirmed password/passphrase
(at least 16 characters). Conversion writes ciphertext atomically with mode
0600, refuses existing files and symbolic links, and leaves the source bytes
unchanged. No plaintext temporary file is created. The current session continues
using the original; lock and open the destination to switch.

Conversion copies saved PGPCrypt keys (including encrypted private packets),
revocations, retained notes, idle timeout, default signing key, preferences,
profiles and saved documents. Optional protection records and triggers are configured separately for each
destination and are not copied. Unrelated KeePass entries, history and other
KeePass-only information are not part of an age vault and stay in the source.
Keep the source until you have opened and checked the destination. Conversion
is not secure deletion of the original or any backup.

Existing age files can also be recovered independently using Debian's `age`:

```sh
age --decrypt /path/to/vault.pgpcrypt.age
```

This prompts privately then prints decrypted JSON; terminal scrollback can
retain it. `data.certificates` contains arrays of standard OpenPGP bytes.

References: [KDBX specification](https://keepass.info/help/kb/kdbx.html),
[keepass-rs](https://github.com/sseemayer/keepass-rs),
[crate 0.17.0](https://crates.io/crates/keepass/0.17.0).
