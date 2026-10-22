# UI security and lifecycle

The active desktop is **C++ / Qt6 Widgets**, backed by a separate Rust worker.
See [the reference review](REFERENCE_REVIEW.md) for evidence from KeePassXC,
KGpg, and Kleopatra. The former egui harness and its dependencies have been removed.

## Process boundary

The supervisor has no widgets, passphrases, vault paths, or contents. It starts
a session UI, which starts a Rust worker through private stdin/stdout pipes.
Passwords are never command-line arguments. The worker owns the unlocked vault
and runs crypto. It returns selected metadata, public exports, notes, and
operation results. Private-key export is an explicit user action and requires every secret packet
to be passphrase encrypted. Revocation exports require an explicit confirmation. Pasted private-key
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
- No saved window state, recent-vault list, or plaintext autosave. Vault paths
  are entered directly to avoid native file-dialog history persistence.
- Idle, focus loss, and event-loop gaps request lock. Best-effort logind lock/
  suspend and freedesktop screensaver signal subscriptions are wired.
- UI and worker disable core dumps and Linux process dumpability.
- Lock deliberately discards unsaved text and notes.

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
