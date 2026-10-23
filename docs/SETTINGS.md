# Settings

Unlock a vault, then select the **Settings** navigation button or **Settings → Preferences**. Per-vault preferences stay inside its
age/KDBX encryption and are copied during conversion. They apply after unlock;
the locked landing screen uses the default light theme.

- **Automatic inactivity locking**: off by default, including older vaults that
  have not opted in. Enable it and use the slider from 1 to 60 minutes.
- **Lock on focus loss**: off by default. You can switch to a password manager
  without an immediate lock. It is independent of inactivity locking.
- **Lock on desktop lock / suspend / Qubes host-lock requests**: off by default.
  Guest signals and a configured Qubes lock service can request lock when enabled.
- **Clear text copied from PGPCrypt**: off by default. Its slider runs from 5
  seconds to 30 minutes. Clipboard/primary-selection changes restart or cancel
  their respective timer. A timer only clears content still owned by PGPCrypt;
  a later copy from another application is left alone. When enabled, manual
  lock also clears owned clipboard content because the UI process then exits.
  Clipboard managers, other qubes and operating-system history may retain copies.
- **Remember recent vaults on this device**: on by default. Stores up to five
  paths outside vault encryption for one-click access to the password screen.
  Disabling clears the paths and stops recording them; no passwords are saved.
  This preference is per-device, separate from encrypted per-vault settings.
- **Theme**: Light, Warm light, Dark, Nord, Solarized light or Solarized dark,
  saved per vault and applied after unlock. The older Solarized setting keeps
  its dark appearance.
- **Requests from other Qubes**: off by default. Lets an unlocked vault receive
  signing/decryption requests, with local approval for each request. A separate
  named-client policy in dom0 is required. Decrypted text goes back to the
  approved qube. Enabling this setting does not create that policy. See
  [Qubes setup](QUBES.md).

**Settings → Save converted vault copy…** writes a separate encrypted destination
with a confirmed password and preserves the original. The Preferences dialog
also links to conversion. Conversion and timeout controls no longer occupy the
main workspace.

The four pages are Keys, Notepad, Identities and Settings. Profiles and saved
Notepad documents are described in [WORKSPACE.md](WORKSPACE.md). The **Password and vault protection** section has a master control and warning
before the individual emergency password, dummy password and inactivity-deletion
options can be enabled. All start off. See [the exact behavior and limits](VAULT_PROTECTION.md). The removed encrypted-notes page stored
its text under the vault password, not an OpenPGP recipient key. Existing notes
are preserved during saves and conversion. To recover older notes, reveal the
`Notes` field on the KDBX `Vault notes and settings` entry in KeePassXC, or recover
`data.notes` from the age JSON using `age --decrypt` in a private environment.
The application does not erase or migrate them into ordinary plaintext files.

Notepad prompts for a private-key password only when a matching signing or
decryption secret needs it. Empty/unprotected keys proceed without a prompt.
Passwords are not cached between operations. A wrong password can be retried or
cancelled without putting plaintext into the result editor.
