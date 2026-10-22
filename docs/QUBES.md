# Qubes 4.3: Debian 13 StandaloneVM

PGPCrypt implements opt-in qrexec signing/decryption and a separate dom0-only lock
service. The cloud checks exercise the local broker and adapter rejection paths;
a real Qubes 4.3 guest, policy prompts, inter-qube transport and host lock/suspend
still require testing. This protocol is PGPCrypt-specific, not Split GPG 2 or a
GnuPG/gpg-agent replacement.

## Guest installation

Use a dedicated persistent Debian 13 amd64 StandaloneVM, such as `pgp-vault`.
Download the `.deb` and SHA256SUMS in a download qube, transfer both through Qubes
file copy, verify the checksum, then install with APT in the vault qube.
No Rust compiler is needed. In a minimal guest without sudo, open a root guest
terminal from dom0 using `qvm-run -u root pgp-vault xterm`; run APT there, then
launch `pgpcrypt` separately as the ordinary guest user. Keep vaults under that
user's home, such as `/home/user/vault.kdbx`. `/database` normally belongs to
root and gives permission denied.

Keep the vault qube offline after dependency installation, with a planned Qubes
update workflow. Start evaluation with at least 1 GiB guest RAM (guidance, not a
measured minimum); age's KDF alone uses about 256 MiB. Keep backups and avoid
using a DisposableVM for the only database copy. Install nothing from this
project in dom0 except a reviewed policy and, optionally, the small lock hook.

## Enable remote operations

1. Install alpha8 in the vault qube. The package provides the root-owned
   `/etc/qubes-rpc/pgpcrypt.Sign`, `.Decrypt` and `.Lock` handlers and a narrow
   Rust adapter. It installs no dom0 policy or host-lock hooks.
2. Unlock the vault and enable **Settings → Preferences → Allow requests from other Qubes**.
   The user must have a private `/run/user/UID` directory, owned by that user and
   mode 0700, normally created by logind. The broker socket lives in its private
   `pgpcrypt` subdirectory. Only one enabled broker may run per guest user.
3. Review `packaging/qubes/30-pgpcrypt.policy.example`, replace the exact qube
   names and user if needed, and install it as a policy in dom0. Its named
   `work-mail → pgp-vault` rules ask for Sign/Decrypt; Lock allows dom0 only;
   remaining callers/arguments are denied. Place these rules before any broad
   local allow/ask rule. Do not replace them with wildcard allow rules.
4. In a client qube, feed one JSON line to `qrexec-client-vm pgp-vault
   pgpcrypt.Sign` or `.Decrypt`, close stdin, then read its one-line JSON reply.
   The Sign service returns a readable cleartext signature. Version 1 request examples:

```json
{"version":1,"operation":"sign","fingerprint":"FULL_40_OR_64_HEX_FINGERPRINT","text":"Text to sign"}
{"version":1,"operation":"decrypt","text":"-----BEGIN PGP MESSAGE-----\n..."}
```

These examples describe the data format; the placeholder fingerprint must be
replaced with the full fingerprint of a valid private signing key in the vault.
A successful response is `{"ok":true,"data":{...}}`; failed/denied requests
return a generic error without key, path or request details. Callers never send
key/vault passwords, paths, import/export requests or identity-enumeration
commands. The service name must match the JSON operation; service arguments are
forbidden. Client input must reach EOF within 10 seconds and fit one 1 MiB JSON
line. Responses are bounded at 8 MiB, with a 90-second adapter read timeout.

The GUI shows the qrexec-authenticated source qube, operation, signing
fingerprint and full signing/ciphertext content, and asks for approval. Policy
approval alone does not authorize crypto. Decrypted plaintext goes to that
approved client, which can retain it. Password prompts appear locally and are
never returned to the client. Cancel/timeout/lock prevents result release. A
client disconnect cancels pending prompts; already-running worker operations may
finish, but their result is discarded. Lock kills the worker.

## Optional host-lock forwarding

In Settings enable **Lock on desktop lock / suspend / Qubes host-lock requests**
and enable Qubes RPC. With the named dom0 policy installed, the following dom0
command requests lock without shell execution in the guest or starting a stopped
qube:

```sh
qvm-run --no-autostart --pass-io --service --user user pgp-vault pgpcrypt.Lock </dev/null
```

`packaging/qubes/lock-vault.example` contains this command as a hook. Configure
it with the existing dom0 locker/suspend mechanism only after testing it. No
automatic locker modification is installed. Guest logind signals do not imply
dom0 notifications; verify your actual locker and suspend paths. If the GUI is
busy or unavailable, verify lock by closing/shutting down the qube before
assuming the keys have left RAM. Saved/paused VM state can retain unlocked RAM.

All automatic lock modes and clipboard clearing are off by default. Settings
provides inactivity (1–60 minutes), focus-loss and session-lock controls. Switching
qubes therefore no longer immediately locks the default configuration. Qubes
clipboard transfers remain outside PGPCrypt's clipboard ownership once copied;
its optional wipe cannot remove copies in another qube, dom0 or a clipboard
manager.

## Trust and validation boundaries

Qrexec supplies `QREXEC_REMOTE_DOMAIN`; no client JSON field can choose it. The
adapter and GUI verify same-UID Unix socket peers and private directory ownership.
The whole vault guest and its same-user software are trusted: a compromised
process there can forge local requests or environments and interfere with GUI
input. The adapter's inherited qrexec identity is meaningful across qube
boundaries, not an isolation boundary against other code already inside this
trusted guest. Keep general browsing/download tools in a separate qube.

No request can open/unlock a vault, export private keys or list identities.
The GUI accepts one crypto request at a time, caps concurrent connections at four and crypto approval prompts at one per
second, uses a five-second local input deadline and a 60-second approval
prompt deadline. Remote requests do not grant a general worker interface.
Lock requests are independent of crypto queue approval and accepted from dom0
only when their setting is enabled. Subkey/key management is local-only.

Before relying on it, test policy denial, source names, approval/rejection,
password/cancel flows, locked denial, input deadlines, disconnects, concurrency,
and dom0 lock/suspend on Qubes 4.3. This work is not an independent security audit.

References:
- [Qubes qrexec implementation and environment](https://github.com/QubesOS/qubes-doc/blob/main/developer/services/qrexec.rst)
- [Qubes policy documentation](https://github.com/QubesOS/qubes-doc/blob/main/user/advanced-topics/rpc-policy.rst)
- [qvm-run service mode](https://github.com/QubesOS/qubes-core-admin-client/blob/main/qubesadmin/tools/qvm_run.py)
- [Split GPG 2](https://github.com/QubesOS/qubes-app-linux-split-gpg2)
