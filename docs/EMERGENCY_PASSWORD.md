# Emergency destruction password

This optional feature overwrites the selected vault file with cryptographically
random bytes when its separate emergency password is entered at PGPCrypt's
normal unlock prompt. It keeps the file's exact byte length and returns a generic
damaged/unreadable-vault error. **It destroys this copy and is not an unlock or
recovery password.** Configure it only after understanding the limits below.

## Configure and disable

Unlock normally, enable the master control in **Vault settings → Password and vault
protection**, accept its warning, then check **Emergency destruction password**, enter and
confirm a distinct password (up to 128 characters), and accept the destructive
opt-in. No minimum is enforced; use the strength indicator as guidance. Uncheck
the option or master to erase its configuration. Re-enabling requires fresh setup. The normal vault password
or dummy password cannot be used as the emergency password. No real vault is destroyed by enabling
the option; destruction happens only if the emergency password is later entered
at unlock.

The app needs adjacent `<vault>.pgpcrypt-protection` and
`<vault>.pgpcrypt-emergency` companion files. The emergency record contains
a random salt, a fixed-cost Argon2id v1.3 verifier (64 MiB, 3 passes, 1 lane) and a
SHA-256 binding to the current ciphertext. It contains no PGP identities, keys or
plaintext passwords, but **its presence reveals that the feature is configured**
and its verifier permits offline guessing. Prefer a long, independently chosen
password. Do not assume the feature itself is hidden.

PGPCrypt updates the binding after its own saves. An outside edit, mismatched
record, unsafe file path or missing companion prevents triggering. KeePassXC
saves therefore disarm it until configured again after normal unlock. Reconfigure the
option after moving or externally editing the vault. A conversion
does not arm the new destination; configure that copy separately if desired.
Other software, including KeePassXC and the age command, does not recognize the
emergency password. Do not rely on it when the companion file is absent.

The separate dummy and inactivity options, their interaction and the master
control are explained in [VAULT_PROTECTION.md](VAULT_PROTECTION.md). Inactivity
expiry, if overdue, takes priority over all entered passwords.

## What it does and cannot promise

The trigger acquires the vault lock and checks a regular owned file, its binding
and file identity before writing. It refuses symbolic links and multiple hard
links. Random replacement bytes are prepared before the first write, and the app
writes exactly the existing length, syncs the file, and ends the worker. An I/O
failure can leave a partially overwritten file; a successful filesystem call is
not evidence that all physical copies were erased.

**Same size does not conceal destruction.** Format headers disappear; hashes,
timestamps, filesystem history and the companion file can reveal changes. This
is not plausible deniability, guaranteed protection during coercion, or a claim
that a corruption explanation will be believed.

SSD wear levelling, copy-on-write storage, Qubes snapshots/saved VM state,
backups and other copies can retain the old encrypted vault. This feature does
not erase those copies, published keys, exported messages or data retained by
other applications. In-place overwrite also cannot provide an atomic all-or-old
result during a crash or power failure. Test the workflow only on a disposable
copy, and choose a recovery policy deliberately: backups preserve recovery but
also preserve data beyond this trigger's reach.
