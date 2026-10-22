# Validation history

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
