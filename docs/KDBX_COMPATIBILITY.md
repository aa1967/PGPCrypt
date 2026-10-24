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
(empty means no default). The settings entry uses `PGPCrypt.Schema=9`; key
entries remain schema 1. Older settings are read with defaults for missing fields. Protected
`PGPCrypt.Preferences` holds JSON for themes, locking, clipboard clearing and
Qubes opt-in; all new automatic behaviors default off.
Protected `PGPCrypt.Profiles` contains stable identity IDs and the PGPCrypt
profile metadata snapshot. Each identity is also a **real child group** of
`PGPCrypt`, with a stable `PGPCrypt.ProfileId` in group custom data and strict
structural markers. This group marker uses `profile:<32hex>` to distinguish it
from binary custom data; entry fields and profile JSON retain the bare 32-hex ID. Its name is the identity name; renaming that group in KeePassXC updates
the identity when PGPCrypt opens it. The group contains:

- **Identity details**, an ordinary entry with protected UserName, Email, URL
  and Notes fields. These fields are authoritative for KeePassXC edits.
- Saved documents with Title and protected Notes. Their stable IDs and timestamps
  remain in `PGPCrypt.DocumentId`, `PGPCrypt.CreatedAt` and `PGPCrypt.UpdatedAt`.
  Moving a document between identity groups changes its profile; moving it to
  the PGPCrypt root makes it unassigned. The physical group is authoritative.
- **Key <fingerprint>** reference entries pointing to canonical key entries in
  the PGPCrypt root. They include the fingerprint, canonical entry UUID and
  recovery instructions, **not duplicate armored keys**. One key can appear in
  several identity groups without stale copies of its secret material. Removing
  a reference removes that identity membership, not the canonical key. Read or
  copy the armor from the canonical entry's Advanced fields.

Unassigned saved documents remain in the PGPCrypt root. Older supported settings
schemas 1–8 remain readable and migrate on save; managed entry IDs, supported
custom fields and history survive moves. Structural group/entry markers, IDs and
reference targets must remain coherent. Unsupported new groups, misplaced
identity entries, duplicate IDs or forged references are refused. PGPCrypt does
not silently adopt manually created unmarked groups as new profiles.

Deleted managed documents, identity groups and references are removed during
PGPCrypt saves; supported unrelated entries outside the PGPCrypt group remain
intact. The app does not turn arbitrary KeePass hierarchies into profiles.
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
(up to 128 Unicode characters, with no enforced minimum). Conversion writes ciphertext atomically with mode
0600, refuses existing files and symbolic links, and leaves the source bytes
unchanged. No plaintext temporary file is created. The current session continues
using the original; lock and open the destination to switch.

Conversion copies saved PGPCrypt keys (including encrypted private packets),
revocations, retained notes, idle timeout, default signing key, preferences,
profiles and saved documents. In **both directions, age v1 → KDBX 4.1 and
KDBX 4.1 → age v1**, the destination does not receive the source
`.pgpcrypt-protection`, `.pgpcrypt-dummy`, `.pgpcrypt-emergency` or
`.pgpcrypt-expiry` records. Those per-vault PGPCrypt records hold the advanced
protection settings outside both standard containers. Configure any desired
options separately after normally unlocking the new copy. Ordinary encrypted
preferences, such as themes and Notepad layout, are copied. Unrelated KeePass entries, history and other
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

Settings schema 7 adds activity clearing, session counters and removable-media
preferences. Missing Notepad layout preferences now default embedded; explicit
values are retained. Settings schemas 1–6 remain readable and group handling
from schema 6 is preserved. Encryption and key entry schemas are unchanged.

Settings schema 8 adds a protected welcome block and reusable manual workflows
to `PGPCrypt.Preferences` JSON. Missing fields default to an empty welcome and
the two built-in workflows; an explicitly empty workflow list remains empty.
These can be recovered by revealing/copying the protected JSON in KeePassXC.
They do not change the standard KDBX container, key entry fields or identity
groups. KeePassXC does not execute PGPCrypt workflows. See [WORKFLOWS.md](WORKFLOWS.md).

Settings schema 9 extends the protected preferences JSON with structured workflow
key selections, required signers and filename patterns. Existing string-only steps
remain readable. These changes do not alter the standard KDBX crypto or canonical
key/identity entries. Actual batch paths and passwords are never persisted there.
