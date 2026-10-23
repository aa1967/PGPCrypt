# Validation history

## Alpha10 evidence

Functional source `c98830b` and GUI validation fixes `d528114`/`d22db75` were
pushed before their functional checks. All 68 Rust tests passed: 52 core,
4 protection protocol, 1 GnuPG interoperability and 11 worker/lifecycle checks.
New coverage includes blank/short passwords, 128 Unicode character bounds,
legacy long-key passwords, verified private exports including mixed protected
and unprotected packets, master/option disable-and-erase behavior, reset without
old passwords, fresh salts and stale-verifier password reuse rejection.
Destruction checks used only fresh disposable fixtures.

Identity metadata and stable document IDs, collision suffixes, properties-only
updates, profile deletion/moves and both conversion directions passed. The
independent Debian age implementation decrypted schema 6 and produced readable
fixtures for schemas 1–6, including a 216-character legacy vault password.
KeePassXC 2.7.10 read protected key/document/identity fields, edited standard
identity UserName/URL/Notes fields, reopened them in PGPCrypt and preserved them
through conversion. Existing unrelated-entry and stale-write checks passed.

The packaged age and KDBX Qt workflows passed, including authenticated private
export, actual master warning/button and per-option checkbox paths, blank masked
password dialogs, short-password setup, save rebinding, disable/erase and clean
re-enable. Four-page navigation, profiles/documents, verification identity,
Copy/Paste, recent vaults, local broker approval/denial and worker shutdown remain
covered. The supervisor replaced the UI process on lock. The enlarged Notepad
layout was visually inspected offscreen. ELF/no-RPATH dependencies, package
ownership/modes, source/licenses, Qubes handlers, security-library minimum and
permission-error guidance passed without a system install. Rust compilation,
formatting and Clippy, plus Qt warnings-as-errors compilation, passed.

These checks are not a fresh-VM installation, real Qubes transport validation,
physical erasure proof or independent security audit. Native compositor and
clipboard behavior, power-loss recovery and remaining storage races are outside
this evidence. Password strength is advisory; weak or blank passwords remain
weak. KDBX writing is still experimental upstream. See SECURITY.md and
VAULT_PROTECTION.md for the continuing boundaries.

## Alpha9 evidence

Functional source `fcfb8b3` was pushed before tests. All 49 Rust checks passed:
37 core, 3 protection protocol, 1 GnuPG interop and 8 worker/lifecycle checks.
Coverage includes purpose-separated password records, master-off disarming,
unsafe file/record rejection, same-length destruction, dummy views that never
decrypt or change real contents, normal-unlock deadline reset and overdue
pre-decryption destruction. Destruction used only fresh disposable fixtures.

Profiles scoped default signers/recipients/verification; new/imported keys joined
the selected profile. Both conversion directions preserved memberships and saved
text. Deleting profiles retained keys/documents, and deleted KDBX documents did
not resurrect on later saves. Valid 4 MiB escaped documents passed private IPC,
save/get/reopen in both formats. Independent Debian age compatibility passed for
schemas 1–5; KeePassXC 2.7.10 read/edited protected document content and profiles,
retained keys/unrelated entries and passed stale-write refusal and age conversion.

The packaged age/KDBX Qt workflows and lock/restart check passed. These covered
four-page navigation, profile filters, internal document browsing, verification
identity display, actual Copy/Paste, read-only control restrictions, isolated
recent-history persistence/clearing and one-click access to the password form.
The Notepad layout was visually reviewed offscreen. A follow-up theme palette
refresh was pushed as `833b651` before checking the updated GUI. Packaging checked
ELF dependencies/no RPATH, owners/modes, source/license files, Qubes handlers,
OpenSSL security minimum and writable-path guidance without a system install.
Rust formatting/Clippy and C++ warnings-as-errors compilation passed.

Real Qubes transport/host hooks, native clipboard/compositor behavior, physical
erasure, forensic concealment, adversarial power-loss/filesystem behavior and an
independent audit remain unverified. Inactivity depends on local clock/companion
records and is bypassable by other software; dummy views are read-only. See
[VAULT_PROTECTION.md](VAULT_PROTECTION.md). KDBX writing remains experimental
upstream. Alpha8's advisory comparison was not a new comprehensive alpha9 audit.

## Alpha8 evidence

Functional source `2901826` and follow-up test expectations `afda4f9` / `74f7347`
were pushed before their checks ran. All 30 Rust tests passed in the final
combined runs (23 core, 1 independent GnuPG interop, 6 worker/lifecycle/adapter).
New coverage exercises readable signatures, altered text rejection, legacy
opaque verification, mixed-password signing candidates, imported empty
passwords, hostile/aggregate S2K work refusal, and reopening the largest generated
text messages. Cleartext newline assertions distinguish framework text from
GnuPG's rendered separator; signatures are independently checked with `gpg --verify`.

Independent Debian age schema-1/2/3/4 compatibility passed. KeePassXC 2.7.10
read all protected armor fields, retained user-edited key notes and unrelated
entries, edited/saved/reopened KDBX, and recovered the keys through age conversion.
Its save made while PGPCrypt was open was preserved; PGPCrypt refused the stale
write and reopened the external change. Core coverage also rejected deleted or
symlinked stale destinations and mixed public/private KDBX fields.

The alpha8 `.deb` passed packaged age and KDBX Qt workflows, including clear-sign,
verify, optional key passwords, private message save/load, local Qubes approval/
denial and worker termination. Lock/restart produced a different UI process.
The updated Notepad layout was visually checked offscreen in Solarized dark.
All four packaged ELF dependencies resolved without RPATH, RPC handlers and
OpenSSL minimum dependency were present, and writable-path guidance passed.
No system installation was performed. Rust formatting/Clippy and C++
warnings-as-errors compilation passed. Cloud compilation/validation used the
rootlessly extracted, authenticated Debian OpenSSL `3.5.7-1~deb13u3` libraries.

These checks do not cover real Qubes transport/host hooks, native clipboard/
compositor behavior, abrupt-power-loss recovery, every filesystem race, or an
independent security audit. The KDBX writer remains experimental upstream.
Advisory findings and remaining scope are in [the review](SECURITY_REVIEW_ALPHA8.md).

## Alpha7 evidence

Functional source `1f9bee2` was pushed before execution. All 24 Rust tests passed
(17 core, 1 GnuPG interop, 6 worker/lifecycle/adapter checks). New tests covered
all-off preference defaults, invalid bounds/themes, saved preferences through
both conversion directions, new signing/encryption subkeys under a protected
primary, password-request codes, actual signing/decryption using the new subkeys,
and qrexec operation/domain/privilege rejection without stderr leakage.

Independent Debian age interoperability passed for age schemas 1/2/3/4;
KeePassXC 2.7.10 protected-field read/edit/save and age conversion passed.
The packaged age and KDBX Qt workflows passed: two pages only, no default focus
lock, default signing key restoration, Dark/Solarized palette application,
local Qubes broker rejection/approval and dom0-crypto denial, broker disable,
on-demand protected-key passwords, crypto/retained notes and lock/restart.
The Solarized Notepad layout was visually reviewed offscreen.

The four packaged binaries passed ELF/dependency/no-RPATH checks. RPC handlers
were present and no dom0 policy was installed. Permission guidance, ownership,
formatting, Clippy and C++ warnings-as-errors passed. No system installation was
performed. Native clipboard/compositor behavior, real Qubes policy/inter-qube
transport/host events, host-hook deployment and an independent security audit
remain untested in this cloud environment. Local broker tests are not a claim
of real-Qubes certification.

## Alpha6 evidence

Functional source at `ee740b8` was pushed before tests. All 22 Rust tests passed
(17 core, 1 GnuPG interoperability, 4 worker/lifecycle), as did independent age
and Debian KeePassXC 2.7.10 interoperability. New checks covered passwordless
and one-character key passwords, adding/removing key protection, wrong-password
rejection, explicit unprotected export, default signing key validation and
persistence through reopening and conversions in both directions.

The `.deb` passed packaged Qt workflows for age with a one-character key password
and KDBX with no key password: recipients/signing controls were on Notepad,
saved defaults were restored, recipient checks survived refresh, and crypto,
notes and lock/restart passed. ELF/runtime/path/permission checks passed without
installing system files. Formatting, Clippy and C++ warnings-as-errors passed.
Follow-up source `c769c28` passed previous KDBX settings-schema compatibility
and independent age schema-1/2/3 reopening checks. Its KDBX Notepad workflow
passed again with a screenshot: all recipient/signing/default/password/action
controls fit on the Notepad page. These follow-up checks also ran after pushing.

## Alpha5 evidence

Source was pushed before tests. Debian backports Rust/Cargo 1.96.1 built the
application against Debian 13 libraries; no rustup installation was used.
Functional source validated at `9c0e87b` (later documentation updates do not
change these binaries):

| Check | Result |
| --- | --- |
| Rust all-features | 20 passed: 16 core, 1 parent-death and 3 worker protocol tests; no failures or ignored tests. |
| KDBX authentication/bounds | Wrong password, modified/truncated/appended data, excessive KDF cost and unsupported XML rejected. |
| Conversion | age → KDBX → age retained key packets, revocation, notes and timeout; originals unchanged; existing destination refused; mode 0600. |
| KeePassXC 2.7.10 (Debian 13) | Read protected public/private armor and revocation; edit notes/save as KDBX 4.0; reopen and save as 4.1; unrelated entry retained and readable again in KeePassXC. |
| age 1.2.1 | Independently decrypted PGPCrypt JSON, re-encrypted it, and PGPCrypt reopened it. |
| Future remote protocol | Unknown operations, passwords, spoofed domain fields, unsupported versions and oversized/multiple frames rejected. No qrexec service is enabled. |
| Packaged Qt workflows | age and KDBX create/generate/encrypt/decrypt/sign/verify/notes/lock passed offscreen; supervisor replaced the UI process on lock. |
| Package | ELF dependencies resolved, no build RPATH, private vault creation and read-only-directory permission guidance passed. No system installation performed. |
| Tooling | Rust formatting/Clippy and C++ warnings-as-errors compile passed. Action commit pins verified upstream to use Node.js 24. |

The workflow repeats source, interoperability and package checks on GitHub after
push. A real Debian StandaloneVM install, Qubes clipboard/lock/suspend behavior,
KeePass 2, power-loss recovery, independent security review and comprehensive
advisory assessment remain untested. The KDBX writer is marked experimental by
its upstream. These results establish interoperability and regression coverage,
not a security audit.

## Alpha4 workflow

No tests run before the source push, following the user's workflow preference.
Post-push checks cover the new start/create flow, live weak/strong estimates,
matching confirmation, and default-home creation when started in a protected
package directory. The package checker drops root privileges in Debian CI.
These results must come from the actual run; source compilation is not a test.

## Alpha3 workflow

At the user's request, tests are not run locally before committing or pushing.
Alpha3 source tests, interoperability checks and package checks are configured
to run on GitHub after the push. The older results below do not validate alpha3
key options, passphrase changes, revocation export, schema 2 or timeout controls.
Compilation/package production is not a functional test.

## Alpha2 evidence

Build target: Debian 13 amd64. The source compiles with **Debian's packaged
Rust/Cargo 1.85.1**, extracted rootlessly for this cloud machine. No rustup or
website-supplied toolchain is required by the documented installation paths.

| Check | Evidence |
| --- | --- |
| Rust core/integration tests | 12 passed with all features; no failures/ignored tests. Empty binary/doc harnesses are not counted. |
| age compatibility | App-generated vault decrypted by Debian Go age 1.2.1, then Go-encrypted payload reopened by PGPCrypt. |
| Vault authentication | Wrong passphrase, header/payload modification, truncation and appended data rejected. |
| Resource bounds | Excessive advertised scrypt cost rejected as ExcessiveWork before derivation. |
| Legacy recovery | Known alpha1 fixture converted, keys/notes preserved, original bytes unchanged. |
| GnuPG interoperability | Encrypt/decrypt and sign/verify both ways; changed signatures rejected. |
| Worker lifecycle | Locked-operation rejection, EOF, explicit lock termination and parent-death test passed. |
| Rust tooling | Formatting and Clippy pass using Debian tools; warnings treated as errors. |
| Qt build/workflow | Native build warnings as errors; offscreen create/key/text/notes workflow and worker termination tested. |
| Supervisor | Lock starts a different UI process. |
| Debian package | Compiled UI/worker/converter, menu/icon, dependencies and source/license notices; no Rust/Cargo runtime dependency. |
| Archive check | ELF dependencies resolve, no RPATH/RUNPATH, assets validate, packaged workflow/restart checks pass. |

The current CI commands are in `.github/workflows/debian.yml`. CI configuration is prepared for GitHub but has not
been run on GitHub by this task. Local results do not establish a public release.

Still unrun: a clean Debian VM system install/removal, real GNOME/Plasma lock/
suspend delivery, native Wayland integration, power-loss recovery testing,
independent security audit and comprehensive dependency/advisory assessment.
The alpha1 X11 dummy-display test does not establish alpha2 native desktop testing.
