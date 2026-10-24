# Alpha16 validation record

Functional checks run only after the corresponding source has been pushed,
following the user's requested workflow. No local Git hooks are installed.

The change is confined to Qt disk controls, contextual help, packaging and
documentation. Rust cryptographic code and database wire formats are unchanged.

Planned checks: native warning-clean compilation; isolated fake-UDisks D-Bus
integration (no system service or real devices); packaged launcher, age/KDBX
GUI workflows and lock/restart; standard package permissions, dependency/source
contents and executable-link inspection. Results will be filled after execution.

No claim is made for real loop/device-mapper creation, kernel filesystem mounts,
interactive desktop polkit authorization, system installation, USB/Qubes device
attachment, physical erasure, plausible deniability, or an independent security
audit. These require testing/review beyond this cloud environment.
