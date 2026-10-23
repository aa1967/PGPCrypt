# Hidden storage and writable dummy views

## Decision for this version

Remove identifying dummy-session status text and keep activity messages generic.
Keep dummy sessions read-only, keep the documented protection records, and add
no root helper or new encrypted wrapper in this release. These UI changes do not
make the feature forensically hidden or establish plausible deniability.

This review compares the implementation with the age specification and official
VeraCrypt documentation. It is a design investigation, not a hidden-volume
security assessment or a real-Qubes validation.

## What the current files reveal

PGPCrypt preserves ordinary age v1 and KDBX 4.1 files. Its adjacent protection
records hold the master/option flags, purpose-separated salted Argon2id
verifiers, and a local-clock inactivity policy. They bind to the vault's current
ciphertext. They contain no PGP keys, identities or plaintext passwords, but
their existence reveals configuration; the verifiers permit offline guessing
and the inactivity record exposes timing metadata. See
[VAULT_PROTECTION.md](VAULT_PROTECTION.md).

Renaming records to dotfiles or moving them into a private per-user directory
can reduce accidental exposure in a file manager. It does not conceal them from
the same user, an administrator, disk inspection, backups or snapshots. Moving
them also changes backup/portability behavior and can leave triggers unavailable
when the vault is copied. No such migration is implemented here.

Root ownership is a permissions boundary, not hidden storage. A normal desktop
process could not read mode-0600 root-owned records; it would need a privileged
service, authorization interface and carefully limited operations. The service,
its installation, paths and records would still leave evidence. This would add
a privilege boundary and recovery burden without providing the requested
concealment. Qubes dom0 should not acquire vault credentials or protection
records for this purpose; the vault belongs in its dedicated guest.

## Why VeraCrypt can put two views in one container

VeraCrypt's hidden-volume design reserves a separate encrypted filesystem inside
the outer volume's random-looking free space. The outer and hidden volumes have
different passwords and headers; selecting a password mounts a different
filesystem. This is a storage layout, not merely a second password that returns
an empty application database. See [Hidden Volume][vc-hidden] and
[Plausible Deniability][vc-deniability].

The upstream documentation also warns that outer-volume writes can overwrite a
hidden volume unless its protection mechanism is used. Its hidden-volume
precautions discuss snapshots at several points in time and information written
by operating systems or other applications outside the hidden volume. A hidden
container is therefore not a guarantee against every forensic or coercion
scenario. See [write protection][vc-protection] and
[security requirements][vc-requirements].

An established external container could hold an otherwise unchanged PGPCrypt
vault **and all its companion files** within its mounted filesystem. A real
vault and an independent decoy vault could then live in different filesystems,
with the storage tool selecting the view. KeePassXC recovery of a KDBX vault
would remain possible after that filesystem is mounted. This is a possible
separate integration, not something PGPCrypt currently creates or manages.
Recent-file history, host/guest traces, backups and Qubes saved VM state would
still need consideration.

## Constraints of age and KDBX

The [age specification][age-spec] says:

> An scrypt stanza, if present, MUST be the only stanza in the header.

Standard age passphrase encryption therefore cannot add another scrypt stanza
for a dummy password. In age's multi-recipient modes, recipients unlock the same
file key and authenticated payload; they do not select separate plaintext
databases. Placing protection settings only inside the real encrypted payload
would also prevent checking them before its normal password is supplied.

KDBX uses its composite master-key/KDF flow to authenticate and decrypt a single
database; its normal entry/group hierarchy is not a hidden-volume facility.
KDBX 4 does have public custom header data: the upstream KeePassXC
[reader][kdbx-reader] and [writer][kdbx-writer] support it. A reviewed future
extension might embed some PGPCrypt records there while retaining a standard
KDBX container. Those records would remain visible metadata, however. It would
require a new specification for authentication, ciphertext binding, rewriting
and compatible-editor behavior. PGPCrypt currently rejects this header feature.
The existing whole-file SHA-256 binding cannot simply be copied inside the file
it hashes without defining a different construction.

Sidecar files are thus not a mathematical necessity. Alternatives include
supported public metadata, a separate state store or another enclosing
container. None automatically supplies hidden-volume security. A new wrapper
around both formats would also stop the outer file from opening directly in
ordinary age/KeePass tools. Preserving standard recovery remains a priority.

## Why a writable dummy needs a separate design

The current dummy session never decrypts the real payload. It holds empty data
and deliberately denies mutations in both the worker and vault writer.
`Vault::open_empty_read_only` retains the real file path but has no real vault
password. Removing that guard could replace the real vault with empty/decoy data
under an unrelated or empty password. It is not a safe implementation shortcut.

A writable decoy would need its own authenticated encrypted storage and keys,
an explicit destination/session type that cannot target the real vault, and
crash-safe handling of both views. It would also need defined behavior for
document/key creation, size changes, conversions, backups, option resets,
inactivity/destruction interactions and external KeePass edits. Persistent decoy
state would leave additional evidence unless backed by a separately reviewed
hidden-storage design. Keep the existing write denial until those requirements
are specified and independently assessed.

## Sources and retrieval

Official website requests were blocked by the cloud network proxy. The research
read the linked official GitHub documentation/specification sources instead;
the human-facing KDBX specification is listed as a reference, not a retrieved
page. No hidden volume was mounted and no runtime checks were performed.

- [age specification source][age-spec]
- [KDBX specification](https://keepass.info/help/kb/kdbx.html)
- [KeePassXC KDBX 4 reader][kdbx-reader] and [writer][kdbx-writer]
- [VeraCrypt hidden volume documentation][vc-hidden]
- [VeraCrypt hidden-volume security requirements][vc-requirements]
- [VeraCrypt hidden-volume write protection][vc-protection]
- [VeraCrypt plausible-deniability documentation][vc-deniability]

[age-spec]: https://github.com/C2SP/C2SP/blob/main/age.md
[kdbx-reader]: https://github.com/keepassxreboot/keepassxc/blob/develop/src/format/Kdbx4Reader.cpp
[kdbx-writer]: https://github.com/keepassxreboot/keepassxc/blob/develop/src/format/Kdbx4Writer.cpp
[vc-hidden]: https://github.com/veracrypt/VeraCrypt/blob/master/doc/html/en/Hidden%20Volume.html
[vc-requirements]: https://github.com/veracrypt/VeraCrypt/blob/master/doc/html/en/Security%20Requirements%20for%20Hidden%20Volumes.html
[vc-protection]: https://github.com/veracrypt/VeraCrypt/blob/master/doc/html/en/Protection%20of%20Hidden%20Volumes.html
[vc-deniability]: https://github.com/veracrypt/VeraCrypt/blob/master/doc/html/en/Plausible%20Deniability.html
