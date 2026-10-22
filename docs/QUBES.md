# Qubes 4.3: Debian 13 StandaloneVM evaluation

The current target is a Debian 13 amd64 StandaloneVM. Neither a real Qubes
session nor dom0 lock propagation has been tested by this cloud build.
PGPCrypt runs entirely inside the guest. It does not currently provide Split
GPG, a qrexec service, or automatic dom0 screen-lock integration.

## Install and isolate

Use a dedicated, persistent StandaloneVM, for example `pgp-vault`. Download the
`.deb` and SHA256SUMS in a download qube, then transfer them using Qubes file
copy. Verify the checksum in the destination. Install the package and its Debian
runtime dependencies as root while updates are available. No Rust compiler is
needed for the compiled package.

For a minimal guest without sudo, open a root terminal from dom0 using the
existing Qubes tools (substitute your qube name):

```sh
qvm-run -u root pgp-vault xterm
```

In that guest root terminal (replace the package path with its transferred path):

```sh
apt update
install -m 644 /home/user/QubesIncoming/DOWNLOAD-QUBE/pgpcrypt_0.1.0.alpha5_amd64.deb /tmp/pgpcrypt.deb
apt install /tmp/pgpcrypt.deb
rm /tmp/pgpcrypt.deb
```

Close the root terminal and launch `pgpcrypt` as the ordinary guest user.
Create the vault inside that user's home, for example `/home/user/vault.kdbx`.
`/database` is a root-owned filesystem location and normally gives permission
denied. Use a persistent vault qube; a DisposableVM is unsuitable for the only
copy of a database. Never install the app, its build tools or vault in dom0.

After dependency installation, disconnect the vault qube's NetVM through Qube
Settings. Keep updating it through an appropriate Qubes maintenance workflow.
Start evaluation with at least 1 GiB assigned RAM: age's KDF alone needs about
256 MiB; Qt, Rust and the guest require additional memory. This is guidance, not
a measured minimum. A minimal Debian guest needs Qubes GUI integration working;
the package pulls Qt's runtime libraries, not the full GNOME/KDE desktop.
Template-based deployment can follow later: install software in the template,
but keep personal vaults in the AppVM home, never in the shared template.

## Current lock and clipboard behavior

Inactivity (default five minutes), guest session/screen lock, guest suspend and
loss of application focus close the session and kill its worker. A timer gap
over 15 seconds also locks. Unsaved editor/notes content is discarded on lock.
Guest logind/screensaver signals do **not** guarantee notification of dom0 lock
or host suspend. Explicitly lock PGPCrypt before locking the host or pausing,
saving or suspending the qube. VM saved state can contain unlocked process RAM;
a vault's file encryption does not encrypt the rest of a VM's saved memory.

Qubes clipboard transfer needs evaluation with focus locking enabled. For
outgoing text: copy within PGPCrypt, press Ctrl+Shift+C while it is still focused,
switch to the destination, then Ctrl+Shift+V and paste. Switching away locks
PGPCrypt. Incoming transfer requires reopening/unlocking as needed. Clipboard
contents already copied outside the process cannot be retracted by locking.
Avoid transferring keys or revocation tickets through everyday client qubes.

## qrexec preparation in alpha5

`src/qubes.rs` defines a separate versioned request decoder for future `sign`
and `decrypt` RPCs. It accepts one JSON line up to 1 MiB, validates full signing
fingerprints, rejects unknown fields/operations and has no password, vault path,
import, export, settings or key-enumeration operation. It does **not** execute
requests or connect clients to the desktop worker. No RPC handler or policy is
installed by the package; enabling access requires the following further work.

1. A per-user local broker must bind to the unlocked GUI's lifetime and a private
   runtime directory. Locked/unavailable sessions refuse requests; remote calls
   cannot unlock or select a vault. Never expose the worker stdin protocol.
2. A thin qrexec adapter obtains the authenticated client identity from qrexec's
   `QREXEC_REMOTE_DOMAIN` environment. The JSON never supplies the domain. Do not
   accept arbitrary environment claims through a general local invocation.
3. Separate services `pgpcrypt.Sign` and `pgpcrypt.Decrypt` bind the service to the
   allowed operation; service arguments are disallowed. No shell expansion,
   caller-controlled filenames or command templates. Read exactly one bounded
   frame, wait for EOF with a deadline, bound output, cancel on disconnect, and
   serialize requests. Enforce an overall deadline/rate limit as well as size.
4. Policy first denies all clients. An administrator may add narrowly scoped
   `ask` rules for named client and vault qubes; no wildcard allow rule. Local
   GUI confirmation must independently show the qrexec-authenticated caller,
   operation, key fingerprint and signing content. A policy prompt is not a
   substitute for approving the cryptographic operation. Key passwords are
   entered locally in the vault GUI only. UI cancellation, timeout or lock
   prevents execution/release of results. Decryption returns plaintext to the
   approved client; a malicious approved client can retain it.
5. A separate authenticated lock-only route can later propagate dom0 lock and
   suspend events. It must only terminate sessions, never unlock or run crypto,
   and must work when the GUI event loop is busy. Do not claim host lock support
   until tested on Qubes 4.3 with a running operation and pending prompt.

This is a dedicated vault protocol, not GnuPG's gpg-agent wire protocol.
Qubes Split GPG 2 expects GnuPG/gpg-agent and does not directly provide this
application's metadata-hidden-while-locked vault behavior. Fingerprints,
recipient IDs, signatures, file sizes and activity timing can still be visible
outside the vault during approved operations.

Before installing any future RPC handler, verify locked denial; caller identity
spoofing rejection; policy denial; every local approval/cancel path; oversized,
truncated and stalled input; concurrent clients; lock during requests; guest and
dom0 suspend/lock; and that no plaintext logs or temporary files are produced.

Official references:
- [Qubes qrexec](https://www.qubes-os.org/doc/qrexec/)
- [Qrexec policy](https://www.qubes-os.org/doc/qrexec-policy/)
- [Minimal templates](https://www.qubes-os.org/doc/templates/minimal/)
- [Split GPG 2](https://github.com/QubesOS/qubes-app-linux-split-gpg2)
