# Optional LUKS disk utility

The landing page provides **Unlock & mount**, **Create LUKS2**, and
**Unmount & lock** along its bottom edge. Ordinary **Create vault**, **Open
vault**, recent-vault selection and the database password page are unchanged.
An age or KDBX database can be used without any LUKS container.

**The two lock states are independent. Locking a database, closing PGPCrypt or
crashing does not unmount a LUKS volume.** Use **Unmount & lock** on the landing
page or another system disk tool to close it. A busy filesystem is not forcibly
unmounted; the app reports that it remains unlocked. Do not assume the volume
is closed until that action succeeds. This is an optional disk utility, not a
new database format or a replacement for KDBX authentication.

## Operation and dependencies

The ordinary-user Qt GUI talks to the system **UDisks2** D-Bus service. UDisks
uses the distribution's libblockdev/cryptsetup stack. PGPCrypt installs no
privileged project helper, sudo rule, new polkit grant, mount unit or crypttab
entry. The GUI never formats existing disks or files. Passwords travel through
local D-Bus messages as binary credentials, not command-line arguments or a
plaintext keyfile. D-Bus, UDisks and the OS remain trusted; GUI/service/library
credential copies are not all memory-locked or guaranteed wiped.

The Debian package installs `udisks2`, `libblockdev-crypto3`, `cryptsetup-bin`,
`e2fsprogs` and `polkitd`, and recommends a desktop authentication agent. If an
agent is absent in a minimal desktop, install/start one suitable for that session
(for example `lxpolkit`). Normal desktop installations may already provide an
agent. There is no new automatic authorization rule. Denied authentication or
an unavailable service fails with guidance; ordinary database opening continues
to work. No drive enumeration or UDisks call happens merely by displaying the
landing page.

Existing file containers are opened without following a final symlink, checked
as regular files and attached using a Unix descriptor. Existing same-user loop
attachments are reused to avoid opening the same backing file twice through
this utility. The disk picker hides system-marked drives by default. **Show
internal LUKS drives** includes otherwise eligible internal/Qubes virtual drives,
subject to OS authorization. Active volumes at operating-system mount locations
remain excluded. Container loops owned by your user are included even when
UDisks conservatively marks them as system devices. Only unlocking, mounting
and closing are exposed for existing drives.
Only a directly contained filesystem is mounted; partition tables inside a
LUKS volume require an external disk tool. Mount requests use
`nosuid,nodev,noexec` and optionally `ro`. Existing writable mounts are not
silently relabeled read-only. These flags reduce exposure, not kernel filesystem
parsing risk: open only trusted volumes.

Container creation reserves a **new file with O_EXCL/O_NOFOLLOW and mode 0600**,
fully writes system randomness on a background thread, synchronizes it, passes
its descriptor to UDisks, then requests `luks2` plus `ext4` and caller ownership.
The capacity range is 64 MiB–64 GiB, default 256 MiB. No sparse allocation is
used. UDisks/cryptsetup supply their normal LUKS2 cipher/KDF defaults rather than
a home-grown crypto implementation. It can require noticeable time and memory.
Interrupted/failed creation deliberately leaves the incomplete file for manual
inspection/removal; it never deletes an existing target to retry. Service
timeouts mean completion is unknown, not that nothing happened: refresh before
retrying. A successfully formatted container may be unlocked but not mounted;
select it under **Unlock & mount** to mount it, then create/open a database in
the mounted folder shown under **Mounts**.

LUKS headers, capacity, UUIDs, block changes and system mount activity may be
visible. Full initialization does not provide plausible deniability or physical
erasure. Standard LUKS encryption does not replace the database's authentication.
Existing PGPCrypt dummy/wipe/expiry settings still apply to the selected database
copy and its companion records; they do not wipe LUKS slots or close a mapping.
LUKS's ordinary bound keyslots unlock the same volume, not different real/decoy
workspaces. Header backups, filesystems, VM snapshots and saved memory remain
relevant to recovery and erasure.

## Qubes

Install/use the utility inside the Debian 13 standalone vault qube, never dom0.
UDisks can see only devices made available to that guest. Attach a USB/block
device with the ordinary Qubes mechanisms before opening it. This feature does
not install a new dom0 policy or bypass qrexec. The vault's removable-message
setting continues to govern message import/export, not this explicit disk tool.
The question-mark controls expose the same explanations on hover or click and
are accessible by keyboard.

## Validation scope

An isolated fake UDisks service tests descriptor passing, new-file-only
formatting, password transport, system-volume exclusion, loop reuse, mount
flags, wrong-password errors, busy/error behavior, and unmount-before-lock
ordering without mounting a real device or running a system service. Packaged
GUI checks cover the unchanged database flows and the landing-page controls.
Actual polkit prompts, kernel loop/device-mapper mounts, real drive/filesystem
behavior and Qubes 4.3 hardware integration still require testing in the target
standalone qube. These are not claimed by mocked-service tests.

[UDisks2 API source](https://github.com/storaged-project/udisks/blob/udisks-2.10.1/data/org.freedesktop.UDisks2.xml)
