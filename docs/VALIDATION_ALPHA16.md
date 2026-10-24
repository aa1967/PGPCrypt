# Alpha16 validation record

Functional checks run only after the corresponding source has been pushed,
following the user's requested workflow. No local Git hooks are installed.

The change is confined to Qt disk controls, contextual help, packaging and
documentation. Rust cryptographic code and database wire formats are unchanged.

Validated implementation: `8b2d24e` on `pgpcrypt-alpha16`. All following
functional checks ran after that source, or the earlier corresponding source,
was pushed. Subsequent release changes update documentation/install links only.

| Check | Result |
| --- | --- |
| Native C++20 release build with `-Wall -Wextra -Werror`, stack protection, RELRO/NOW | Passed |
| Isolated UDisks integration via a private D-Bus session | Passed |
| Same service/dialog checks with AddressSanitizer (Qt leak detection disabled) | Passed |
| Actual Qt dialog: refuse existing file, allocate a new 64 MiB file on its thread, confirm/clear credentials, create with a short password, select and mount the returned loop | Passed with fake service; no real mount |
| Packaged ordinary-user launcher and permission-error guidance | Passed |
| Packaged age and KDBX complete GUI workflows, including key creation, sign/verify, documents, profiles, automation/batches and protection controls | Passed |
| Packaged supervisor lock/restart with worker termination | Passed |
| Package ownership/modes, declared dependencies, executable linkage/RPATH, bundled sources/licenses and Qubes handlers | Passed |
| Landing-page and LUKS creation-dialog screenshots | Captured and visually inspected |
| Runtime dependency/agent names in cached signed Debian 13 index | Confirmed |

The service checks cover exclusive private file creation, final-symlink and
directory refusal, full non-sparse allocation, cancellation, descriptor passing,
binary IPC passwords, new-file-only formatting, refusing repeat formatting,
duplicate-loop refusal, system-marked owned loops, excluding an active OS
filesystem even when internal drives are enabled, restrictive/read-only mount
requests, existing mount behavior, wrong-password errors, busy unmounts, failed
locks, and unmount/lock/detach ordering. Tests use a synthetic service name and
session-bus connection explicitly injected into the service/dialog. Production
uses the system bus and standard UDisks name; no environment override is added.

Early checks exposed missing registration for a D-Bus array type and a dangling
callback capture in the test harness. Both were fixed, pushed, and then checked
again; the final isolated and sanitizer runs pass. Upstream code inspection
also led to handling conservative UDisks system hints and refusing ambiguous
backing-path reuse rather than risking the wrong already-open inode.

No local Rust functional suite or independent age/KDBX interoperability suite
was rerun for this UI-only change; those existing suites remain in the GitHub
release workflow. The package's complete GUI workflows were run against both
unchanged crypto backends. Final documentation-only repacking is checked against
the validated executable/launcher hashes before publication, and public package
bytes, SHA256SUMS and SOURCE_COMMIT are verified independently of release CI.

Local evidence is under ignored `target/validation/alpha16-*` (build, service,
sanitizer, package logs and screenshots). Fontconfig cache/offscreen-plugin
notices in this cloud environment did not fail the checks.

No claim is made for real loop/device-mapper creation, kernel filesystem mounts,
interactive desktop polkit authorization, system installation, USB/Qubes device
attachment, physical erasure, plausible deniability, or an independent security
audit. These require testing/review beyond this cloud environment.
