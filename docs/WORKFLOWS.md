# Automation and batch workflows

Use **Automation** in the sidebar to create, rename, reorder or delete workflows,
then **Save workflows**. Each workflow has 1–32 ordered Sign, Verify, Encrypt or
Decrypt steps. There are at most 32 workflows. Presets stay inside vault encryption
and survive age/KDBX conversion. KeePassXC can reveal/copy the protected preferences
JSON; it does not execute workflows. Old string-only steps remain readable.

## Keys can change between steps

Each step chooses **Notepad selection** or **Choose specific keys**:

- Notepad selection captures the current profile, signing key and checked recipients
  when Execute is clicked. Decrypt/Verify use that profile's available keys.
- Specific keys selects 1–16 certificates from the complete vault, across identities.
  Sign signs the same message with every selected signing key. Encrypt targets all
  selected recipients; any matching private recipient can decrypt.
- Decrypt tries only the selected private keys. Embedded signatures are checked
  against the vault's public keys. A following Verify step can restrict the accepted
  signers further.
- Verify accepts signatures only from its selected certificates. **Require all**
  requires a valid signature from every selected key. Missing or invalid signatures
  fail the step and release no successful-result payload.

For example: Sign with A and B → Encrypt for C → Decrypt with C → Verify A and B,
requiring both. Protected keys are prompted individually, including keys with
separate passwords. Passwords are not stored in presets or cached across steps/jobs.
Missing/unusable keys stop the run; no substitute is silently selected.

## Execute from Notepad

Notepad has side-by-side Input and Output panels. Each has Sign, Verify, Encrypt
and Decrypt above it. Input actions write their result to Output; Output actions
process the current Output in place and leave Input unchanged. Paste replaces
Input; Copy all copies Output. A failed Output action preserves its source and
clears any stale verification badge.

Choose a saved workflow, then **Input**, **Output** or **Batch files…**, and click
**Execute**. Runs are manual: no scripts, shell commands, network actions, event
triggers or remote workflow execution are supported. Selection controls and incoming
Qubes operations cannot interleave with a run. Lock ends the session.

Only a final successful workflow result is published. A failed step stops that job,
without publishing intermediate decrypted text. Decrypt already authenticates embedded
signatures. A subsequent Verify may reuse that authenticated result when the exact
text, selected certificates and required signers match. Output changes invalidate
its stored digest-bound public signer metadata. Unsigned plaintext never acquires
verification state. Otherwise Verify performs normal worker verification.

## Batch files and names

Choose up to 64 UTF-8 text or armored PGP message files, with at most 64 MiB total
input. Each input is an independent job. Individual message files are at most 4 MiB;
Sign/Encrypt plaintext input remains at most 1 MiB. Arbitrary binary files are not
supported in this release. Input files are read directly into memory, never copied
into plaintext temporary input files.

Batch setup shows an editable destination filename for every input. Choose an
existing destination folder and either edit names individually or use:

| Token | Value |
| --- | --- |
| `{stem}` | Input basename without its last extension |
| `{name}` | Complete input basename |
| `{ext}` | Input extension without the dot |
| `{index}` | Job number, starting at 1 |
| `{workflow}` | Workflow name, with spaces/path separators replaced by underscores |

Patterns are encrypted with the preset; selected input paths and destination folders
are session-only. Generated tokens are substituted once so filenames cannot inject
more tokens. Output names cannot contain folders or control/format characters.
Review every destination before **Execute batch**. Only a final Encrypt step produces
encrypted output; Sign/Verify/Decrypt outputs can be readable outside vault encryption.
The setup screen explains this before execution.

Each successful job saves through a private 0600 file in the destination directory.
The complete file is synced, then published with an atomic no-overwrite link and a
directory sync. Existing files, symbolic links and the open vault/support filenames
are refused, including if a file appears after preview. A failed write never replaces
an existing destination. Process/OS crashes can leave a private temporary output;
readable exports are outside vault confidentiality and filesystem copies may persist.
Removable-media policy applies both in the picker and on opened file/directory devices.

Each finished job opens a separate result window with its source, destination and
status, Copy all, Save another copy and verified-signer details when applicable.
Cryptographic failure shows no intermediate plaintext or trusted signer metadata.
If crypto succeeded but saving failed, the authenticated final result remains in
that window for recovery with Save another copy. Already completed files are not
rolled back when a later job fails.

**Continue with other files when a job fails** defaults on. A password-dialog
cancellation stops the remaining batch. Result windows offer **Stop after current
job**; the current job can finish and remaining files are skipped. Lock kills the
worker, closes/clears result windows and discards queued work; earlier exported
files remain. To limit retained data, the queue pauses at 16 open result windows
or its 32 MiB UTF-8 result budget. Save unsaved results and close windows to resume.
This is a result-data budget, not a bound on total Qt/library memory usage.

## Portability and boundaries

Age payload schema 10 / KDBX settings schema 9 add structured key selections and
output patterns. Older supported vaults remain readable; older PGPCrypt versions
reject these new schemas. Keep a backup before upgrading. Canonical armored keys
and identity groups remain unchanged. Fingerprints are stable references; removing
a referenced certificate leaves a recoverable preset that must be repaired before
execution rather than preventing the vault from opening.

Profile/key/tag associations and automatic triggers remain future work. KeePass has
an ordinary Tags field and keepass-rs 0.17.0 maps it to Entry.tags, but an application
schema, stable workflow IDs, conflict/precedence rules and lossless external-edit
round trips need validation before implementing associations. Profiles organize keys;
they are not separate confidentiality boundaries.

References: [KDBX format](https://keepass.info/help/kb/kdbx.html),
[keepass-rs tag mapping](https://github.com/sseemayer/keepass-rs/blob/v0.17.0/src/format/xml_db/entry.rs),
and [key management](KEY_MANAGEMENT.md).
