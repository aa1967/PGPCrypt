# Validation evidence for alpha2

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

Commands are in README.md. CI configuration is prepared for GitHub but has not
been run on GitHub by this task. Local results do not establish a public release.

Still unrun: a clean Debian VM system install/removal, real GNOME/Plasma lock/
suspend delivery, native Wayland integration, power-loss recovery testing,
independent security audit and comprehensive dependency/advisory assessment.
The alpha1 X11 dummy-display test does not establish alpha2 native desktop testing.
