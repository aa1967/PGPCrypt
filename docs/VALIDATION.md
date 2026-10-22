# Validation history

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
