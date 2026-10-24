# Profiles and saved documents

The workspace has five navigation buttons: **Keys**, **Notepad**, **Identities**,
**Saved notes** and **Vault settings**. All data described here stays inside the encrypted age/KDBX
vault, except files deliberately imported/exported, recent-vault paths, and
optional protection companion records described separately.

## Profiles

**All** shows every key and saved document. The **+** tab creates a named profile.
Profiles are categories: one key can belong to several, and a profile can be empty.
Newly generated or imported keys join the selected profile automatically.
The Identities overview lists every identity with key and document counts.
Selecting a row shows editable details alongside it and associated keys below.
Use **Identities** to edit name, username, email, website and private notes,
or change key membership. Creating an identity starts with those fields and
includes a compact table for optionally assigning existing keys.
Selecting an identity groups its associated keys first; column sorting applies
within the associated and other-key groups. Search and status filters narrow
the table. All key tables share identity, fingerprint, material, status,
algorithm, creation, expiry and usage columns, with sortable, resizable headers. Deleting a
profile keeps its keys and documents; its documents become unassigned and remain
visible under All.

The selected profile filters Keys, Notepad recipients, signing choices and the
saved-document browser. Hidden recipients are not retained as an invisible
selection, and an unavailable default signer is not substituted. Decryption and
verification also use keys in the selected profile; select All to search the
whole vault. A signature from a key outside the profile cannot be verified there.

Profiles do not have separate passwords or memory isolation. Unlocking the vault
unlocks all its contents; use separate vault files when separate confidentiality
boundaries are needed. Profile names, membership and document metadata are all
encrypted at rest.

## Notepad documents

**Save output to vault** stores the output as a named encrypted document. The
input can also be saved explicitly. Use the built-in document browser to load a
saved document into the input, or delete a saved document. Loading does not change
the saved copy. Save updates the opened document by its stable ID; Save as new
creates a separate document. New documents start as `untitled`; duplicate titles
within a profile receive numbered suffixes. Properties changes a saved
document's title or profile without changing its contents. The browser shows
profiles and timestamps, supports search and sortable columns, and distinguishes
documents with the same title in different profiles. Editing text, pasting, importing or running crypto does not save
automatically. Save explicitly to retain changes before locking or closing.

**Import text file** reads an ordinary UTF-8 file into the input. It is stored
inside the vault only after an explicit vault save. **Export output** writes an
ordinary file outside the vault and asks before writing readable output. These
are separate actions. Earlier PGPCrypt versions saved Notepad files only to the
external filesystem; those files are not silently imported by this upgrade.

Saved text may be plaintext or an armored OpenPGP artifact. The vault password
protects either while the vault is locked. Saving plaintext in the vault does
not sign it or encrypt it to an OpenPGP recipient. The app accepts text rather
than binary attachments: imported messages and stored documents are at most
4 MiB each, new Encrypt/Sign plaintext is at most 1 MiB, and the entire vault
payload remains limited to 16 MiB.

**Replace with clipboard** replaces the entire input. **Copy all** copies the output.
Optional clipboard expiry follows the existing ownership rules; it cannot erase
copies kept by clipboard managers or other Qubes.

## Verification

The output panel and status bar show the verified signing certificate's identity,
certificate key ID and full fingerprint. The message editor contains only the verified text,
so copying/saving/reprocessing it does not insert interface labels. Verification
authenticates the signature, not the person's real-world identity. Compare the
full fingerprint over a trusted channel.

## Portable recovery

age schema 9 stores `data.profiles` and `data.documents`. KDBX settings schema 8
stores profiles in protected `PGPCrypt.Profiles` JSON and actual identity
groups. Each group contains an Identity details entry, its documents and
references to canonical keys. Identity fields map to ordinary UserName, Email,
URL and Notes for direct reading/editing in KeePassXC; the group name is the
identity name. Overlapping memberships reference one canonical key instead of
storing multiple copies of its secret packets. Each saved document is a
normal KeePass entry with its title and protected `Notes` content. It can be read
and copied in KeePassXC without PGPCrypt. Both conversion directions preserve
profiles, membership and saved documents. Older PGPCrypt versions reject the new
schemas; keep a backup before upgrading.

## Recent vaults on this device

Landing-page recent entries open that vault's password screen in one click.
Only a successful open/create adds an entry; no password or contents are saved.
Remembering is on by default. Disable **Remember recent vaults on this device**
in Vault settings to clear stored paths and stop recording them.

This is an explicit exception to keeping vault information inside encryption:
up to five local vault paths are stored outside the vault in a private file
under the per-user state directory. A filename/path may itself reveal an identity
or project name. Disabling removes the current record's paths, not filesystem
snapshots/backups of that record. Qt's automatic file-dialog history remains
disabled; this is a separate PGPCrypt feature.

## Notepad windows and activity

Notepad stays embedded by default. Enable **Open Notepad in its own window** in
Vault settings to detach it. Existing explicit preferences are preserved. Both layouts use the same editor, controls,
profile selection and worker session. Moving between layouts does not copy
unsaved text or create another file writer. Main-window key/profile edits
refresh those same controls. Lock closes session windows and discards unsaved
text and the activity view.

The terminal-style activity panel stays in memory with severity filters, colors,
a 200-event limit, Clear and optional periodic clearing. It records operation
results, public key names/fingerprints, file basenames, document titles, ordinary
setting changes and bounded troubleshooting reasons. It strips control/format
characters from these fields. It never records message bodies, credentials,
full paths, raw worker errors, Qubes peers or advanced-protection configuration
and outcomes. Public metadata is visible while unlocked; lock clears the panel.
It is a troubleshooting aid, not a durable audit trail or proof of storage events.

The header always displays cached counts of keys, subkeys, identities, notes and
workflows. Updating it does not scan the database each second. Optional window
counters show unlocked duration, completed actions and failed opens before the
successful unlock. They reset on lock (which replaces the UI process), closing
or restarting the app, and reboot. They cannot see other processes or earlier
sessions. A failed open may mean a missing/unreadable file as well as a wrong
password. Encrypted preferences become available only after a successful unlock,
so these optional counters appear then. Clear resets activity entries, not counters.
An optional encrypted welcome block supports up to 16 lines / 2048 UTF-8 bytes of
plain text, including ASCII art; it is never executed as terminal commands.

Right-click key rows for public-key/fingerprint/value copying and the existing
key-management actions. Private-key display still uses verified authentication.
Verification also opens a PASS/FAIL result with aligned verified-signer and
stored-certificate fields; matching a stored key does not establish its owner's
real-world identity. Failed verification returns no authenticated message text
or trusted signer metadata and clears the previous result.

## Alpha12 workspace

Saved notes is a separate navigation page with search, properties, profile moves,
delete and open actions. The editor keeps the eight most recently modified
notes for its selected profile; Load and Save remain available there. All
appearance/security preferences are inline on the scrollable Vault settings
page. Ruby light/dark, Hacker green and Cyberpunk themes are available.

Starting with alpha13, the launcher runs directly without a sandbox. Recent
paths persist on this device unless disabled, and desktop lock/suspend hooks
can receive the session’s signals. See [SANDBOX.md](SANDBOX.md) for retained
protections and deferred isolation options. Activity can clear periodically to Ready;
optional window counters do not provide durable login history.

## Chaining Notepad operations

After Sign, use **Encrypt output** to encrypt the signed message without copying.
After Decrypt, use **Verify output** to inspect the verified signer when the
message was signed. Decrypt already checks embedded signatures: this action
reopens the authenticated result only while Output remains exactly unchanged.
It never treats unsigned plaintext as verified. For other signed output it
performs normal verification. Failed actions do not overwrite the original
Output with an intermediate result or leave an old verification badge.

Reusable manual workflows are described in [WORKFLOWS.md](WORKFLOWS.md).
