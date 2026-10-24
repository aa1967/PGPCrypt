# Vault settings

Unlock a vault and select **Vault settings**. Appearance, session security,
conversion and advanced protections are all on this scrollable page. Preferences
stay inside vault encryption and survive age/KDBX conversion. The locked landing
screen uses the default light theme.

- **Inactivity lock**: off by default; enable for 1–60 minutes. Focus-loss and
  desktop/suspend/Qubes lock-event options are independent and also default off.
- **Clipboard timer**: off by default; enable for 5 seconds–30 minutes. It clears
  only app-owned or matching copied text. Lock clears such clipboard/primary
  content even when the timer is off. Clipboard managers, Qubes transfers and
  OS history may retain copies.
- **Remember recent vaults on this device**: on by default, per device. Stores up
  to five paths outside encryption, never passwords. Disabling clears the record
  and stops recording paths. Qt automatic file-dialog history stays disabled.
- **Theme**: Light, Warm light, Dark, Nord, Solarized light/dark, Ruby light/dark,
  Hacker green or Cyberpunk. Applied after unlock.
- **Open Notepad in its own window**: off by default. Both layouts share the same
  widgets, worker and editor state, with no second database writer.
- **Activity clearing**: off by default; an optional 5-second–60-minute timer
  resets entries to Ready. Clear does the same immediately. Inventory and optional
  counters remain. Activity is never written to a log file.
- **Window counters**: off by default. After unlock, shows uptime, completed
  actions and failed opens before that unlock. Lock, closing/restarting the app
  or reboot resets them. Failures include file errors; other app processes and
  previous sessions are invisible. Inventory counts are always displayed.
- **Welcome block**: optional plain text/ASCII art in the activity header, up to
  16 lines / 2048 UTF-8 bytes. No terminal commands are executed.
- **Removable message files**: off by default. Restricts message import/export
  in the app, not system mounting or vault selection. See [SANDBOX.md](SANDBOX.md).
- **Requests from other Qubes**: off by default. An unlocked vault can approve
  signing/decryption requests individually. Separate named-client dom0 policy is
  required; the setting does not create it. See [QUBES.md](QUBES.md).

**Save converted copy…** creates a separate encrypted age v1 or KDBX 4.1 file,
preserving the source. In both directions, advanced-protection companion records
are not copied; configure those separately in the destination. Other preferences,
workflows, keys, identities and saved documents are preserved. See
[KDBX_COMPATIBILITY.md](KDBX_COMPATIBILITY.md).

**Password and vault protection** has a master switch, an explicit warning and
individual emergency/dummy/inactivity-deletion controls. All default off. Details
and limitations are in [VAULT_PROTECTION.md](VAULT_PROTECTION.md). These settings
and their outcomes are excluded from session activity.

The older encrypted-notes field is preserved during saves/conversion. Recover
its protected Notes in KeePassXC's `Vault notes and settings` entry, or `data.notes`
in authenticated age JSON. It is not exported to an ordinary file automatically.
Current saved documents are managed on **Saved notes**.

Private-key passwords are requested only when needed, including empty passwords
for imported packets that use one. They are not cached between operations. New
passwords have no enforced minimum and a 128-Unicode-character limit; strength
indicators help estimate guessability without establishing a security guarantee.
