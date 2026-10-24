# Validation history

## Alpha15 evidence

Source `e5d8e49`, correction `7b6cba7` and editor coverage `713ef86` were pushed to `pgpcrypt-alpha15`
before their affected functional checks. **78 distinct Rust checks passed**:
60 core, 4 protection protocol, 1 GnuPG interop and 13 worker/lifecycle checks.
The initial full run passed 77 checks; the new multi-signer test then failed
because its readback used a nonexistent `settings_get` operation. The test was
corrected to inspect the existing open response and passed on rerun for age and
KDBX. No production Rust code changed for that correction. Remaining checks
were not unnecessarily repeated locally; the tag workflow repeats the full suite.
Formatting and final all-target/all-feature Clippy passed; desktop compilation
uses warnings as errors.

New worker coverage exercises multiple signers with separate passwords, public
per-key password hints, explicit decryption-key restrictions, all-required signer
verification, missing/incorrect signer rejection without a result payload, invalid
filename patterns without modifying ciphertext, and portable structured workflow
preferences through both conversion directions. Workflow-model tests reject
unknown operations, credential fields, duplicate/malformed key selections,
unsupported pattern tokens, path traversal and excessive steps.

Independent age interoperability passed current schema 10 and legacy schemas
1–9. Independent KeePassXC interoperability passed protected structured workflow
preferences under settings schema 9, canonical keys, identity groups/references,
external edits, stale-write refusal and conversion. Removable-media checks passed.

Both actual packaged age/KDBX desktop workflows passed, including three batch
files with valid inputs surrounding a bad input, separate result windows, private
output modes, no overwrite/symlink behavior, continued execution after failure,
unchanged Notepad input/output, side-by-side four-action panels and lock cleanup.
A final package rerun also drove the Automation editor's actual key-picker dialog
and Save workflows button, confirming persisted explicit keys and Notepad reload.
Workflow list data is initialized before selection signals can populate the editor.
Direct launcher startup, permission guidance and supervisor process replacement
also passed. Package metadata, dependencies, source/licenses, modes, ownership,
Qubes handlers and ELF RPATH checks passed. No system installation was performed.
The layout was inspected in an offscreen screenshot, then recent-note columns
were adjusted and the rebuilt package's desktop workflows passed again.

Final README/evidence-only repackaging must preserve the validated executable
and launcher hashes. Public package bytes, checksum and source commit are checked
before publishing install links/tag. GitHub independently repeats its complete
source/package/interoperability workflow before attaching release assets; consult
that run for its remote result.

These are component checks, not an independent audit. Native Qubes, USB hardware,
desktop lock/suspend delivery and clipboard-manager behavior remain unvalidated.
KDBX writing remains experimental upstream. Batch exports may be readable outside
the vault, completed files survive later failure, and Qt/library copies are not
all memory-locked. Scripts, arbitrary binary file processing and background or
remote automation are not implemented. Exact limits are in WORKFLOWS.md.

## Alpha14 evidence

Source `3db3f45` was pushed to `pgpcrypt-alpha14` before functional checks.
All **76 Rust checks** passed: 59 core, 4 protection protocol, 1 GnuPG interop
and 12 worker/lifecycle checks. Formatting and all-target/all-feature Clippy
passed; Qt6 desktop compilation uses warnings as errors.

The new protocol coverage exercises age and KDBX subkey batches with separate
purposes/expiries, rejection without changing ciphertext when a later row is
invalid, actual signing/encryption/decryption/verification, malformed workflow
steps/names and welcome control sequences, reopen and bidirectional conversion.
Manual workflow/welcome preferences and subkey counts survive both formats.
Independent Debian age interoperability passed for current schema 9 and legacy
schemas 1–8. Independent KeePassXC interoperability passed protected fields,
identity groups/references, external edits, stale-write refusal and conversion,
including protected workflow/welcome JSON under KDBX settings schema 8.

Actual packaged checks passed ordinary-user direct launcher startup, permission
failure guidance, both complete age/KDBX Qt workflows and supervisor replacement
on lock. The expanded desktop checks cover real failed opens before unlock,
counter/welcome/inventory display, clipboard replacement and one-click key import,
Sign→Encrypt and Decrypt→Verify, authenticated Output reuse, changed-Output proof
invalidation, failed-step abort, signature-failure recovery, document save/load,
protection controls and clipboard cleanup. The final layout was inspected in an
offscreen screenshot. Removable-media policy checks passed. Package metadata,
dependencies, source/licenses, modes, ownership, Qubes handlers and ELF RPATH
checks passed; no system installation was performed.

Final README/evidence-only repackaging must preserve the hashes of all four
validated executables and the launcher. Public package bytes/checksums/source
commit are verified before updating install links and publishing the tag.
GitHub's tag workflow independently repeats source, package and interoperability
checks before attaching release assets; consult that run for its remote result.

These component checks are not an independent security audit. Native Qubes,
USB hardware, desktop lock/suspend delivery and clipboard-manager behavior remain
unvalidated. KDBX writing remains experimental upstream. Profile/key/tag workflow
associations are documented research, not executable automation. Bubblewrap
remains deferred. Public metadata in session activity is visible while unlocked,
but message bodies, passwords and advanced-protection events are excluded.

## Alpha13 evidence

Source `228e8ff` was pushed to the existing PR #10 before functional checks.
Bubblewrap invocation, namespace checks and the Bubblewrap package/build
requirement have been removed. The desktop compiles with warnings as errors.

Post-push package checks passed direct startup through the packaged launcher
(relocated only to the unpacked fixture), both age and KDBX Qt workflows,
key/message/document operations, clipboard cleanup and supervisor process
replacement on lock. Checks also passed runtime dependencies with no Bubblewrap,
ELF RPATH/ownership/modes, sources/licenses, Qubes handlers and writable-location
permission guidance. Shell syntax checks passed. No system installation was run.

The worker, migration utility and Qubes adapter binaries are byte-identical to
the validated alpha12 binaries. No crypto/storage-format or worker source changed;
alpha12's 75 Rust and independent interoperability results remain the baseline
for those components. They were not rerun locally for this launcher/UI removal.
The GitHub workflow still runs its complete source, interoperability and package
checks on the PR and release tag; see its run for the current remote result.

Only the desktop launcher/UI and packaging behavior changed. Recent-vault state
can persist again and existing opt-in desktop D-Bus handlers are no longer
blocked by the wrapper. Native lock/suspend delivery, real Qubes/USB hardware
and an independent audit remain unvalidated. Sandboxing is deferred, with
alternatives documented in SANDBOX.md. Final documentation repackaging must
retain the validated binary and launcher hashes.

## Alpha12 evidence

Source `5a874d3`, namespace-check correction `75dea4b`, and launcher/policy
coverage `dd63aa2` were pushed before their affected functional checks.
All **75 Rust checks** passed: 59 core, 4 protection protocol, 1 GnuPG interop
and 11 worker/lifecycle checks. This includes dedicated secret-page separation,
exact UTF-8/empty passwords, path-free swap reporting, preference bounds,
new theme persistence, legacy reads, key authentication and corruption guards.
Formatting, all-target/all-feature Clippy and Qt warnings-as-errors compilation
passed. No Git hooks or pre-push functional tests were used.

Independent age interoperability passed for current encrypted schema 8 and
legacy schemas 1–7. KeePassXC 2.7.10 passed protected key/document/identity-group
reads, field/group edits, membership references, stale-write refusal and age
conversion with KDBX settings schema 7. Crypto formats and KDF parameters did
not change. Old explicit Notepad layout preferences remain honored.

The actual Debian package passed both Qt vault workflows and supervisor restart:
embedded-by-default and shared detached Notepad, a separate Saved notes table
and matching recent-document IDs, key capability alignment/all-selected defaults,
expiry off, valid/altered signature rows and recovery, sanitized activity bounds,
clear-to-Ready, private-key authorization and clipboard cleanup with its timer
off. Package checks covered ELF dependencies/no RPATH, ownership/modes,
Bubblewrap dependency, sources/licenses, Qubes handlers and permission guidance.
The four new palettes have text/selection contrast ratios above 4.5:1.

The real release worker reported locked selected buffers and no active swap on
this runner. A separate child restricted to RLIMIT_MEMLOCK=0 correctly reported
locking unavailable, without aborting or claiming protection. Unit checks cover
active/unknown swap parsing without returning device names. GUI/library/KDF/key
packet copies are not all locked.

Removable-media policy checks passed ordinary files, conventional mount paths,
real symlink aliases, missing output targets and explicit opt-in. Launcher
checks passed temporary-state arguments, spaced home paths, symlink refusal,
D-Bus address blocking and namespace-error propagation. **Live Bubblewrap
isolation could not run:** an independent namespace capability probe failed
with `bwrap: setting up uid map: Read-only file system` on this cloud runner.
The packaged launcher remains fail-closed. Offscreen GUI checks directly
executed the packaged UI/worker; they do not establish live sandbox behavior.

No system installation, native compositor/clipboard manager, real USB hardware,
or real Qubes transport was exercised. Desktop D-Bus lock/suspend signals are
blocked by the wrapper. See SANDBOX.md for these limits; this evidence is not an
independent security audit. Final documentation repackaging must retain all
validated executable and launcher hashes.

## Alpha11 evidence

Source `643d120` and follow-up fixes `2dbe6c6`, `656b8f2`, `5d103ca` and
`0558422` were pushed before their affected functional checks. All 72 Rust
checks passed across the final combined runs: 56 core, 4 protection protocol,
1 GnuPG interoperability and 11 worker/lifecycle checks. The last document
conversion assertion was rerun by itself after correcting an ordering assumption:
actual identity groups change traversal order; stable IDs and all document
properties remained equal. No product behavior changed for that assertion.

KDBX tests covered actual identity groups, group rename, shared-key references,
reference removal, document moves, schema-5 migration preserving entry IDs,
history and custom fields, malformed-group/forged-reference rejection and one
canonical copy of private armor. Group IDs use a `profile:` prefix because the
upstream custom-data parser otherwise infers bare hex text as Base64 binary.
Independent KeePassXC 2.7.10 read and edited groups/fields, moved documents,
removed a membership reference, preserved canonical keys/unrelated entries and
passed stale-write refusal and age conversion. Independent Debian age
interoperability passed for schema 7 and legacy schemas 1–6. Existing independent
GnuPG encrypt/decrypt and sign/verify checks passed.

Protocol checks covered default-on and persisted-off Notepad layout, typed
verification failures with no successful payload or stale signer metadata,
ordinary dummy status, document counts after moves/deletion/conversion, and
refusal of duplicate certificate fingerprints before a public copy could
replace private material during conversion.

Packaged Qt checks passed in age and KDBX for one shared Notepad widget,
embedded/separate-window toggles, mirrored profiles, unsaved-text retention,
identity overview/counts and draft preservation, public-key copy, neutral
read-only status, bounded/sanitized activity filtering, explicit valid/altered
signature comparisons and failure recovery, protection setup/reset and
lock cleanup. Worker termination and supervisor process replacement passed.
The separate Notepad layout was visually inspected offscreen. Package checks
covered runtime dependencies/no RPATH, ownership/modes, sources/licenses,
Qubes handlers, security-library minimum and writable-path guidance. Rust
formatting, all-target Clippy and Qt warnings-as-errors compilation passed.
Final documentation repackaging must retain the validated binary hashes.

No system installation, native compositor/clipboard integration or real Qubes
transport was exercised. The activity view is not a durable audit log, and
removing dummy labels does not establish forensic concealment. Dummy remains
read-only; no root helper or storage-wrapper change was introduced. Physical
erasure, adversarial filesystem/power-loss behavior, hidden-volume security and
an independent application audit remain outside this evidence. KDBX writing
remains experimental upstream. See SECURITY.md and HIDDEN_STORAGE_RESEARCH.md.

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
