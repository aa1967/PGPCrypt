# PGPCrypt architecture and delivery scope

Target: Debian 13 desktop. Qt6 Widgets UI inspired by KGpg, separate Rust worker,
no account or runtime network requirement. The app is alpha; its accepted crypto
container is standard age v1. See [ADR 001](ADR-001-vault-format.md).

## Security objective

Hide the complete public and private OpenPGP keyring, including identities,
fingerprints and notes, when the vault is locked. Encrypt the entire application
schema and indexes. Do not use the user's persistent GnuPG home or gpg-agent.
Do not promise anonymity, rollback detection, secure SSD erasure, or secrecy
against a compromised unlocked desktop. File size/names/timestamps remain visible.

## Components

| Component | Choice | Boundary |
| --- | --- | --- |
| UI | C++ / Qt6 Widgets | Native key table, details and plaintext editor; ordinary GUI memory is not securely wiped. |
| Vault worker | Rust / age 0.12.1 | Standard age v1 passphrase encryption of the complete schema. |
| OpenPGP | Sequoia / Debian OpenSSL | Library-managed keys, signing, encryption and parsing; no custom primitives. |
| Password profile | Standard age scrypt, cost 18 | About 256 MiB; explicit write cost and bounded unlock cost. |
| Persistence | 0600 ciphertext-only temporary files and atomic replacement | No plaintext WAL or index; advisory writer lock. |
| Recovery utility | Separate Rust binary / Debian libsodium | Read-only alpha1 decoder and new age destination; never used by normal worker. |
| Distribution | Compiled Debian package | Runtime libraries only; Rust/Cargo are source-build tools supplied through APT. |

age handles file keys, salts, header authentication, stream framing and nonce
management. The app defines only a bounded, versioned encrypted JSON schema.
Every save is a fresh standard age file. Fully authenticate before parsing or
exposing data. Existing custom `PGPVLT01` writing is removed.

## Lifecycle

A supervisor with no vault data starts a UI session. The UI starts its worker
using bounded private stdin/stdout pipes; no passwords are placed in command
arguments. Stored/generated private keys do not return to the GUI; private-key
paste/import is an explicit exception. Crypto jobs are asynchronous to Qt.

Lock cancels work, confirms worker termination, exits the session UI, and starts
a fresh locked UI. Parent-death signals cover crashes. Idle/focus loss and native
session subscriptions request lock. Validate real session signal behavior before
claiming complete GNOME/Plasma integration. Clipboard/external copies and swap
remain outside this process lifecycle's protection.

## Functional roadmap

The original goal remains broader than the current slice:

- Key generation, import/export, safe update merge, full fingerprints/capabilities.
- Identity/subkey management, expiry, rotation, revocation certificates and trust decisions.
- Encrypt/decrypt/sign/verify text, detached and cleartext signatures, sign-and-encrypt.
- Large-file streaming with authenticated output handling, overwrite/path safeguards,
  cancellation, public/private export distinctions and explicit secret-export confirmation.
- Backups, restore, password changes, version migration and recovery policy.
- Hardware-backed OpenPGP keys and optional additional vault factors.
- Optional explicit discovery/publication only; no background network identity leaks.
- Debian packaging, fresh-VM validation, dependency review, fuzzing and independent review.

The alpha currently implements vault create/open/save/lock, notes, key generation/
import/merge/public export, text operations, isolated interoperability tests, and
local Debian packaging. Other features above are planned, not implied by the UI.

## Factor and recovery rules

Initial unlock is passphrase only. Additional age recipients are **alternative**
unlock routes, not multi-factor AND requirements. A USB file, hardware key or
recovery recipient cannot be casually added and labelled MFA. Any combined-factor
profile requires separate key-derivation/recovery design and review. TOTP prompts
alone do not strengthen an offline encrypted file. No silent password-only fallback.

Old backups retain old credentials. Fresh file keys on save do not retract data
or secrets already learned from old snapshots. Losing required factors without
an independently designed recovery path means losing access.

## Evidence

Use actual functional, negative/authentication, migration and cross-implementation
tests, not syntax-only or zero-test success. Keep failed/skipped/unrun checks
separate. See [VALIDATION.md](VALIDATION.md), [UI_SECURITY.md](UI_SECURITY.md),
and the historical [reference review](REFERENCE_REVIEW.md).

## Optional KDBX and Qubes preparation (alpha5)

The vault layer dispatches age v1 or KDBX 4.1 persistence. `src/kdbx.rs` uses
keepass-rs for crypto and an application-level preflight to bound KDF work,
reject compression and refuse unsupported XML fields. `convert_copy` writes
a new encrypted destination without modifying the source. See
[KDBX_COMPATIBILITY.md](KDBX_COMPATIBILITY.md) for portable entry fields.

`src/qubes.rs` defines a strict future remote decoder, separate from the local
worker request type. No RPC bridge is installed. See [QUBES.md](QUBES.md) for
StandaloneVM deployment and the remaining authenticated broker/policy work.

## Alpha7 settings, subkeys and Qubes broker

The GUI exposes an optional same-user Unix socket broker only while unlocked
and explicitly enabled in encrypted preferences. The qrexec adapter validates
a separate sign/decrypt allowlist and authenticated environment identity; local
GUI approval and on-demand key-password entry precede worker requests. A dom0
lock-only service is separately gated. The worker still has no listening socket.
See QUBES.md for guest trust boundaries, policy and real-VM validation needs.

Preferences (all automatic modes off initially) live in age payload schema 4
or KDBX settings schema 3. Subkey creation uses Sequoia KeyBuilder/SubkeyBuilder
and the primary secret to certify a binding, then commits a new ciphertext
snapshot. The removed notes page retains existing data in both backends.
