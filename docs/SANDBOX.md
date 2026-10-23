# Packaged sandbox and memory limits

The Debian launcher requires Bubblewrap and fails closed if user namespaces are
unavailable. It drops capabilities, isolates IP/abstract-socket networking,
processes and IPC, and overlays `$HOME/.config`, `.local`, `.cache` and `/tmp`
with temporary memory-backed filesystems. XDG config/data/state/cache point into
these overlays. Qt uses widget file dialogs, with portal integration disabled;
D-Bus addresses and the standard session/system bus sockets are blocked.
X11/Wayland display access and the Qubes service socket remain available.

These measures reduce application-state persistence, not host visibility.
The host kernel, display server, backups, filesystem metadata, monitoring tools
and a compromised host can observe paths or plaintext. Other filesystem access
still runs with the user's permissions. Alternate service sockets and other
processes are not a comprehensive hostile-desktop sandbox. Existing history
from previous versions is not removed. No root helper is installed.

Recent vaults are available only during one launcher lifetime, including lock
restarts; all temporary history disappears when that launcher exits. Vaults and
converted copies cannot be placed in the temporary directories. Store them in
a persistent folder such as `~/Documents`. The launcher rejects symlinked XDG
home directories rather than masking an unintended destination. It launches
without CLI arguments; source-development binaries do not use this wrapper.

D-Bus desktop lock/suspend signals are unavailable inside this sandbox.
Inactivity/focus locking and explicit Ctrl+L remain available. Qubes lock needs
the separate documented dom0 hook; the local Qubes service can still use its
filesystem Unix socket. This has not established real Qubes transport behavior.
If Bubblewrap reports that namespaces are disabled, review your Qube/host
namespace policy; the application does not silently start without isolation.

The Rust worker probes `/proc/swaps` at startup, reporting only active/none/
unknown, never device names. It cannot determine swap encryption. Retained
vault-password copies use dedicated anonymous pages, `mlock`, `MADV_DONTDUMP`,
and a compiler-resistant wipe before unlock/unmap. Dedicated mappings avoid
page-sharing `munlock` mistakes. Memory-limit/locking failure is visible in
Vault settings; no extra privileges or unlimited-lock setting is requested.
The process also disables core dumps and dumpability. **GUI text, OpenPGP key
packets, KDF allocations and library/request copies are not all memory-locked.**
Temporary filesystems may themselves swap. Use OS-level encrypted swap or no
swap when your threat model requires it. This is not a complete memory audit.

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
