# Reference review: KeePassXC, KGpg, and Kleopatra

The comparison below informed alpha1. Alpha2 supersedes the earlier storage
choice with [standard age v1](ADR-001-vault-format.md), after confirmation that
direct KeePassXC compatibility is not required.

This review uses upstream source and Debian 13's signed package metadata, rather
than inferring security properties from a product's reputation. It is an
architecture comparison, not an audit or a vulnerability assessment.

## What Debian 13 supplies

The package indexes inspected report these versions. Debian security revisions
can change; installed systems should retain security updates.

| Reference | Debian 13 version observed | GUI | Cryptographic/storage approach |
| --- | --- | --- | --- |
| KeePassX | `2.0.3+keepassxc1` | Transitional package | Installs KeePassXC; Debian notes original KeePassX is no longer developed. |
| KeePassXC | `2.7.10+dfsg1-1` | C++ / Qt5 Widgets | Botan symmetric crypto, Argon2 implementation, KDBX database reader/writer. |
| KGpg | `4:25.04.0-1` | C++ / Qt6 / KDE Frameworks | GnuPG-oriented key management and transaction processes; also depends on GpgME. |
| Kleopatra | `4:24.12.3-1+deb13u1` | C++ / Qt6 / KDE Frameworks | Libkleo, GpgME++ and QGpgME Qt6 around GnuPG. |

Debian's KeePassX package description makes **KeePassXC**, rather than the old
KeePassX backend, the useful current reference. Historical KeePassX source uses
Qt5 and libgcrypt; do not confuse that with KeePassXC's Botan backend.

## Lessons from KeePassXC

KeePassXC does not gain its security merely from selecting AES. Its format,
key derivation, authenticated framing, database lifecycle, and implementation
all contribute. Its KDBX4 reader/writer derives keys, authenticates the header,
and uses HMAC-authenticated block streams around encrypted data. The cipher
layer supports modes including AES-256/CBC and ChaCha20; integrity belongs to
the complete KDBX construction. Copying its cipher choice without its
authentication design would not reproduce its protection.

The Argon2 KDF supports Argon2d and Argon2id, explicit version, memory, parallelism,
and time cost. Configurability and a calibration UI are relevant improvements
over PGPCrypt's fixed prototype KDF profile. Existing libsodium Argon2id and
XChaCha20-Poly1305 are established primitives; this review does not find them
unsuitable merely because KeePassXC uses Botan.

**KDBX is a serious candidate for the production container**, with OpenPGP
certificates as encrypted attachments/fields and identities inside the encrypted
database. Before adoption, verify metadata confidentiality, authentication,
parser bounds, write/recovery behavior, unsupported fields, maintenance, and
cross-application round trips. A general password manager opening the database
could expose or alter PGP-specific data; define its schema and compatibility.

One Rust candidate, `keepass`/keepass-rs 0.17.0, describes its KDBX4.1 writing
support as **experimental**. It is not the same implementation as KeePassXC.
This iteration therefore does not silently replace the tested prototype
container with that writer, implement another KDBX codec, or claim KeePassXC's
security history. Direct reuse of KeePassXC code requires API/maintenance and
license review; it is not a drop-in independent vault SDK.

## Lessons from PGP GUIs

KGpg uses Qt/KDE menus, actions, key lists, details, toolbars, and a text editor.
Its editor exposes ordinary undo/redo. An established PGP GUI is therefore not
automatically designed to erase every plaintext memory copy.

Kleopatra offers certificate models and job/result handling through Libkleo and
QGpgME. GnuPG's ecosystem provides broad hardware and interoperability support.
Its normal keyring/agent workflow does not provide PGPCrypt's defining property:
hiding the complete public keyring inside a locked portable container. Reusing
the default persistent GnuPG home would defeat that requirement.

## Decisions applied

1. **Qt6 Widgets** for a key table, details, recipient selection, text/notes views,
   and native theme behavior. No WebEngine.
2. **Rust worker** for vault custody and Sequoia operations. The GUI receives
   metadata, public exports, and results, never stored/generated secret keys.
   Pasting a private-key import is an explicit exception: the GUI sees those
   bytes before forwarding them. There is no private-key export protocol operation.
3. **Process replacement on lock.** Confirm worker termination, exit the unlocked
   UI, and let a supervisor holding no vault data start a fresh locked UI. Linux
   parent-death signals prevent orphaned workers. This is lifecycle isolation,
   not a sandbox against a malicious UI or root.
4. **Asynchronous jobs over bounded private pipes.** KDF and crypto do not block
   the UI event loop. No network listener, secret command-line arguments,
   persistent IPC logs, or shared GnuPG home.
5. **GUI controls.** Disable document undo, render plaintext as plaintext, avoid
   vault-file dialogs that may retain recent paths, and request locking through
   desktop/session signals as well as idle/focus loss.
6. **Standard container.** Alpha2 uses maintained age v1 encryption rather than
   the earlier custom container or an experimental KDBX writer.

Qt has ordinary strings, implicit sharing, caches, input methods, and clipboard
interactions. It is selected for mature native APIs and alignment with these
reference apps, not a promise of secure GUI memory.

## Sources

Version-pinned upstream source used for the Debian reference comparison:

- [KeePassXC 2.7.10 dependencies](https://github.com/keepassxreboot/keepassxc/blob/2.7.10/CMakeLists.txt)
- [KeePassXC cipher backend](https://github.com/keepassxreboot/keepassxc/blob/2.7.10/src/crypto/SymmetricCipher.cpp)
- [KeePassXC Argon2](https://github.com/keepassxreboot/keepassxc/blob/2.7.10/src/crypto/kdf/Argon2Kdf.cpp)
- [KeePassXC KDBX4 reader](https://github.com/keepassxreboot/keepassxc/blob/2.7.10/src/format/Kdbx4Reader.cpp)
- [KeePassXC KDBX4 writer](https://github.com/keepassxreboot/keepassxc/blob/2.7.10/src/format/Kdbx4Writer.cpp)
- [KGpg 25.04.0 dependencies](https://github.com/KDE/kgpg/blob/v25.04.0/CMakeLists.txt)
- [KGpg key manager](https://github.com/KDE/kgpg/blob/v25.04.0/keysmanager.cpp)
- [KGpg editor](https://github.com/KDE/kgpg/blob/v25.04.0/editor/kgpgeditor.cpp)
- [KGpg process transactions](https://github.com/KDE/kgpg/blob/v25.04.0/transactions/kgpgtransactionprivate.cpp)
- [Kleopatra 24.12.3 dependencies](https://github.com/KDE/kleopatra/blob/v24.12.3/CMakeLists.txt)
- [keepass-rs 0.17.0 README](https://docs.rs/crate/keepass/0.17.0/source/README.md)

Package observations came from `apt-cache policy/show` using authenticated
`trixie` and `trixie-security` indexes at deb.debian.org/security.debian.org.
