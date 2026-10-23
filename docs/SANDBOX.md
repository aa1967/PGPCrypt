# Runtime protections and deferred sandboxing

## Current launcher (alpha13 onward)

The installed launcher starts PGPCrypt directly as the desktop user. Bubblewrap
is not installed, invoked, or checked by the application or its CI workflow;
user namespaces are not required. No alternate sandbox has been enabled.
Normal XDG directories and D-Bus connections remain available. The launcher
refuses root and forwards command-line arguments to the desktop supervisor.

Qt file dialogs still use widget mode and automatic QSettings file-dialog
history remains disabled. PGPCrypt's separate recent-vault feature again saves
up to five paths in its private per-user state file, unless disabled in Vault
settings. These paths are outside vault encryption; passwords are never saved
there. Nothing about this change hides paths from the host or erases old traces.
Desktop lock/suspend signals can reach the existing opt-in handlers when the
session provides them. Qubes lock still needs the documented dom0 hook and the
Qubes-request and lock-event settings. No machine policy is changed automatically.

## Retained protections

The Rust worker probes `/proc/swaps` at startup, reporting only active/none/
unknown, never device names. It cannot determine swap encryption. Retained
vault-password copies use dedicated anonymous pages, `mlock`, `MADV_DONTDUMP`,
and a compiler-resistant wipe before unlock/unmap. Dedicated mappings avoid
page-sharing `munlock` mistakes. Memory-limit/locking failure is visible in
Vault settings; no extra privileges or unlimited-lock setting is requested.
The process also disables core dumps and dumpability. **GUI text, OpenPGP key
packets, KDF allocations and library/request copies are not all memory-locked.**
Use OS-level encrypted swap or no swap when your threat model requires it.
This is not a complete memory audit.

Lock clears the clipboard/primary selection if PGPCrypt still owns the data
or it matches a digest of the last explicit app copy, regardless of the optional
timer. Unrelated copied text is retained. Clipboard managers, Qubes clipboard
transfers and external copies cannot be recalled.

Removable-media preferences restrict PGPCrypt **message** reads/writes, not
system mounting or vault selection. The picker hides conventional `/media`,
`/run/media`, `/mnt` locations and mounts identified through Linux device
ancestry; path and opened-file device checks also reject direct/symlinked paths.
Those conventional directories are conservatively blocked even for fixed
storage. Unknown network/FUSE aliases, hostile same-user mount races and all
hardware configurations are not covered by this application preference.
Use Qubes USB/device policy for system-wide isolation.

Activity uses fixed messages, a 200-event bound, memory-only storage and optional
periodic clearing. Clear resets it to Ready. No content, names, fingerprints,
paths, credentials, password roles or protection events are recorded. Optional
session counters include completed actions and failed opens in this GUI launch;
a failed open can mean a file error, not just a bad password. Other processes,
offline attacks and prior launches are not tracked. Counters default off.

## Deferred sandbox design

Bubblewrap was removed at the user's request after alpha12 introduced launcher
and CI complexity. The old implementation is retained in Git history at
`v0.1.0-alpha12:packaging/pgpcrypt-launcher`; its namespace checks are not part of
current builds. It masked XDG state and networking but also interrupted recent
history and desktop D-Bus hooks. This runner could not validate live isolation.

Possible future approaches, not implemented:

| Approach | Useful boundary | Tradeoff to investigate |
| --- | --- | --- |
| Qubes vault Qube with no NetVM and named-client qrexec policy | Reuses the user's existing VM isolation and keeps keys in the vault Qube | Requires Qubes policy setup; desktop paths remain visible inside that Qube |
| Debian AppArmor profile | Restricts application file/network permissions through OS policy | Needs a reviewed profile, distro/kernel support and permission handling for user-chosen vault paths |
| Optional Flatpak distribution with a narrow permission set | Supplies a maintained desktop sandbox and portal integration | Adds a runtime/distribution path; GUI integration, vault dialogs, D-Bus and Qubes service access need validation |

Before adopting any approach, test installation in Debian 13-min/Qubes, vault
creation and atomic saves, lock/suspend, clipboard, key import/export, both
formats, and the Qubes broker. Keep normal installation usable without changing
kernel namespace policy or installing a root helper. Filesystem metadata and a
hostile host remain outside what an app sandbox can conceal.

References: [Qubes documentation](https://doc.qubes-os.org/),
[Debian AppArmor](https://wiki.debian.org/AppArmor), and
[Flatpak sandbox permissions](https://docs.flatpak.org/en/latest/sandbox-permissions.html).
