# UI security and lifecycle

The active desktop is **C++ / Qt6 Widgets**, backed by a separate Rust worker.
See [the reference review](REFERENCE_REVIEW.md) for evidence from KeePassXC,
KGpg, and Kleopatra. The former egui harness and its dependencies have been removed.

## Process boundary

The supervisor has no widgets, passphrases, vault paths, or contents. It starts
a session UI, which starts a Rust worker through private stdin/stdout pipes.
Passwords are never command-line arguments. The worker owns the unlocked vault
and runs crypto. It returns selected metadata, public exports, notes, and
operation results. Private-key export is an explicit confirmed action. The UI
identifies private packets without password protection before displaying them;
private-key passwords are optional. Revocation exports require confirmation. Pasted private-key
imports necessarily pass through GUI text and IPC buffers; this exception must
not be mistaken for worker-only private-key custody.

One bounded request is accepted at a time and response IDs must match. KDF and
crypto work does not block the Qt event loop. Lock remains available during
work and cancels it by terminating the worker.

On lock, worker termination is confirmed before the UI exits. The supervisor
starts a fresh locked UI process. Closing exits without restarting. Worker EOF
also drops the vault; Linux parent-death signals terminate descendants if their
parent dies. This reduces lingering live state after lock/crash. It does not
erase swap, hibernation, prior captures, clipboard copies, or filesystem snapshots.
It is not a sandbox against the UI while unlocked.

## GUI controls

- Plaintext uses QPlainTextEdit; undo/redo is disabled and HTML is not rendered.
- Password entries use password mode and sensitive/no-prediction input hints.
- No saved window state or plaintext document autosave. The optional recent-vault
  feature stores up to five paths outside encryption in private local state; it
  is on by default and can be disabled/cleared in Settings. Passwords are never
  saved. The file
  browser uses Qt widgets instead of native/portal dialogs. Per-user QSettings
  paths point at `/dev/null` (a non-directory), preventing QtProject.conf history
  and last-directory writes; this affects this process only.
- New vaults default to `~/vault.pgpcrypt.age`. Relative paths and `~/` expand
  under the current user's home, independently of the launch directory.
- Vault creation always requires matching password/passphrase confirmation. A
  debounced local libzxcvbn estimate recognizes common passwords and patterns;
  it makes no strength guarantee, and no password is sent to a service. New
  creation fields accept up to 256 UTF-16 code units; opening preserves the
  previous 32767-code-unit limit for existing vaults.
- Opt-in inactivity/focus/session rules request lock. All are off until enabled
  in Settings. Best-effort logind lock/
  suspend and freedesktop screensaver signal subscriptions are wired.
- Notepad message files are explicitly opened/saved via the same nonpersistent
  Qt browser. Input is bounded UTF-8 text, and saves use a private mode-0600
  same-directory temporary file, fsync and atomic rename. Readable output
  requires confirmation; saving does not put the file inside the vault.
- UI and worker disable core dumps and Linux process dumpability.
- Lock deliberately discards unsaved text. The notes page is removed; old saved
  notes remain in the encrypted container.

Qt strings, input methods, accessibility, rendering caches, clipboard backends,
and QProcess serialization can still allocate copies. Clearing a widget is not
a secure wipe. Qt is selected for native integration and mature APIs, not a
memory-erasure guarantee. Native session signals still need validation under
real Debian GNOME/Plasma sessions; headless tests do not establish that behavior.

## Validation

Worker tests exercise create/open, locked-operation rejection, certificate
merge, public-only export, encryption/decryption, signing/verification, notes,
wrong passwords, malformed/bounded IPC, EOF, lock termination, and parent death.
The Qt offscreen test exercises actual UI worker callbacks through the main
workflow. A supervisor test verifies a different UI PID after lock. These are
functional checks, not evidence of complete memory erasure.

## Historical egui findings

Source inspection of egui/epaint 0.37.0 identified undo history containing normal
String copies and cached text layouts. These are retention concerns for this
threat model, not a list of demonstrated CVEs. The same scrutiny applies to Qt.
The old harness is removed; the same memory-lifecycle scrutiny still applies to Qt.

## Notepad controls (alpha6)

Recipients, signing-key selection, optional key-password entry and all text
operations are on Notepad. The encrypted vault stores the default signing
fingerprint; it is restored on unlock and preserved through format conversion.
Explicit recipient selections and one-operation signing choices stay in process
memory. Private-key generation/password changes accept empty or short values,
with matching confirmation. Vault password rules are separate.

## Alpha7 interaction and Qubes RPC

Settings holds timeouts, clipboard clearing, themes and conversion. Passwords
are prompted on demand and are never cached between operations. Local subkey
creation uses the primary private key to certify the binding.

Opt-in Qubes RPC exposes only versioned signing/decryption and a dom0-only
lock request. Per-request GUI approval precedes crypto. The helper constrains
input size, EOF deadline, service/operation binding and allowed JSON fields.
Same-UID Unix socket peers and private runtime directories are checked, but
the whole guest/user account remains trusted. See QUBES.md for dom0 policy,
limits, cancellation behavior and remaining real-Qubes validation.
