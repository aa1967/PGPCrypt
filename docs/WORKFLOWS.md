# Manual Notepad workflows

Alpha14 supports reusable, explicitly started text pipelines. Choose a workflow,
**From Input** or **From Output**, then **Run workflow**. The selected profile,
signing key and checked recipients are captured at the start. Ordinary password
dialogs still appear when necessary. Controls stay disabled between steps so
selection changes and incoming Qubes operations cannot interleave with a run.
Lock remains available and ends the session.

Built-ins:

| Workflow | Steps | Required selection |
| --- | --- | --- |
| Sign then encrypt | Sign → Encrypt | Private signing key and checked encryption recipients |
| Decrypt and verify | Decrypt → Verify | A profile containing the decryption/verification keys |

**Edit workflows…** creates, renames, deletes and reorders steps. At most 32
presets, each with a unique 1–80-character name and 1–8 steps, are accepted.
Only Sign, Encrypt, Decrypt and Verify are allowed. A sequence still needs to
make sense for its input: verification of unsigned text fails, for example.
There are no shell commands, scripts, stored passwords, file writes, network
actions or background triggers in presets.

Each step receives the preceding result. Only the final successful result is
published; nothing is saved to the vault or filesystem automatically. A failed
step stops the run and clears any previous verification badge. A run from Output
retains its original Output on failure. A run from Input clears Output instead
of leaving a stale result. No intermediate decrypted text is published on a
later verification failure. The activity panel identifies the workflow, step,
public key and fixed reason where available, never text or credentials.

Decrypt already validates signatures encountered in an encrypted message.
Verify can reuse that authenticated result while the exact resulting text is
unchanged. The UI binds public signer metadata to a SHA-256 digest of Output;
any text change invalidates it. This allows Decrypt → Verify to display the
verified signer even when decryption has already consumed the signature packet.
Unsigned plaintext never obtains this verification state. Otherwise Verify
performs normal worker verification.

Presets are encrypted in age schema 9 / KDBX settings schema 8 preferences,
and survive conversion. KeePassXC can reveal/copy the protected JSON; it does
not execute these workflows. Older vaults receive the two defaults on load;
users may delete all workflows without them being silently restored.

## Investigated: profile/key/tag associations

Associations and automatic triggers are **not implemented** in alpha14. The
manual release establishes a narrow execution model first. A future design can
offer suggestions from a selected profile/key without executing anything until
the user reviews recipients, signer, source, steps and output destination.

Use stable random workflow IDs for associations, and certificate fingerprints
and stable profile IDs for targets. Names are editable labels, not identifiers.
Define precedence explicitly (session choice, key preference, profile preference),
and ask on conflicting key/profile suggestions rather than silently selecting
a signer or recipient. Deleting a target must remove dangling references.

Tags could be private organizational labels with reusable suggestions. KeePass
defines an ordinary entry `Tags` field, making it a useful compatibility candidate;
lossless keepass-rs/KeePassXC round trips, case rules, separators and shared-key
references need validation before adoption. A key shared by several profiles
should retain one canonical private-key entry. Tags and associations must remain
inside encryption and must never encode passwords or bypass approval dialogs.

Event-triggered/background execution would need a separate threat model, preview
and cancellation design. Profiles are organizational categories, not isolation
boundaries. None of this research enables extra permissions or remote execution.

References: [KeePass XML structure](https://keepass.info/help/kb/kdbx.html),
[Kleopatra commands](https://invent.kde.org/pim/kleopatra/-/tree/master/src/commands),
and [PGPCrypt key/subkey behavior](KEY_MANAGEMENT.md).
