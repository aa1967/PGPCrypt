# Password and vault protection

These optional features are **off by default**. Unlock normally, select Vault settings,
then enable the master control in **Password and vault protection** and accept
its warning. Enabling the master alone does not configure any individual option.
Each option has its own checkbox. Checking it permits setup; saving a new
password or interval activates that option. The master overrides all three.
Unchecking an option disables it and removes its configuration. Unchecking
the master disables all options and removes their configurations. Re-enabling
starts fresh and never restores an old password or interval.
If cleanup fails, the master remains off; check the reported file permissions.

## Emergency destruction password

A separate, confirmed password entered at the normal unlock screen overwrites
this vault copy with cryptographic random bytes at its exact existing length.
It reports a generic damaged/unreadable-vault error and ends the worker.
New passwords have no minimum and a maximum of 128 Unicode characters.
The strength indicator is advice, not an enforced complexity rule. The password
must differ from the normal and dummy passwords; reuse is checked against
salted verifiers even if their ciphertext binding has become stale.
Resetting an option replaces its verifier without requesting the old password.
Fields always open blank and settings show no configured/armed status. See [EMERGENCY_PASSWORD.md](EMERGENCY_PASSWORD.md).

## Dummy password

A separate, confirmed password opens an **empty, read-only view**. The real vault
is not decrypted, modified or replaced. Keys, profiles, saved documents and old
notes are absent. Editing/saving keys, documents, profiles or vault settings is
disabled; there is no persistent writable decoy database. Lock and use the normal
password to access the real vault again.

The read-only behavior, database size, companion records and other forensic
evidence can reveal this feature. It does not provide plausible deniability or
guarantee safety during coercion. Configure it with a strong password distinct
from the normal and destruction passwords. It requires PGPCrypt and the matching
companion files; other software will not accept it.

## Delete after inactivity

Choose a count and unit: days, weeks, months of **30 days**, or years of **365
days**, up to 100 years total. Configuration starts a new interval. A successful
normal unlock in PGPCrypt resets the interval; failed passwords and dummy views
do not. Saving while already unlocked refreshes the ciphertext binding, not the
last-unlock time.

Once overdue, the **next PGPCrypt unlock attempt**, with any password, overwrites
this copy before decrypting it. This includes an attempt using the dummy
password. There is no background deletion job and nothing happens merely because
the file is sitting unused. A warning and explicit acknowledgment are required
before enabling this destructive option.

The policy depends on the local clock. A clock moved forward can cause early
destruction; a clock moved backward can delay enforcement. Successful normal
unlocks never shorten the recorded deadline merely because the clock went back.
Other applications do not update or enforce this policy. It is not cryptographic
expiration, a trusted clock, or a protection against someone who can remove the
companion files or use another OpenPGP/KeePass application.

## Companion records and recovery limits

| Adjacent file suffix | Contents |
| --- | --- |
| `.pgpcrypt-protection` | Master and per-option enabled/disabled flags |
| `.pgpcrypt-emergency` | Salted emergency-password verifier and ciphertext binding |
| `.pgpcrypt-dummy` | Salted dummy-password verifier and ciphertext binding |
| `.pgpcrypt-expiry` | Inactivity interval, last normal unlock, deadline and ciphertext binding |

Records are owned mode-0600 regular files. Password verifiers use fixed Argon2id
v1.3 parameters (64 MiB, 3 passes, 1 lane) with fresh salts and separate purpose
domains. Binding uses SHA-256 of the ciphertext. These records contain no PGP
keys, identities or plaintext passwords, but are outside vault encryption:
they reveal configured features, permit offline password guessing, and the
expiry record reveals timestamps. Keep long, independently chosen passwords.

Missing, malformed, unsafe or mismatched records disarm the relevant behavior.
PGPCrypt refreshes bindings after its own saves. External saves, including in
KeePassXC, disarm records until the relevant options are reconfigured after a
normal unlock. Conversion leaves these options off for the destination; it
does not copy the records. New vault creation refuses a name with existing
protection companions, preventing accidental reuse of stale configuration.

Same-length random overwrite does **not** hide destruction. Format headers,
hashes, timestamps and filesystem history can expose it. SSD wear levelling,
copy-on-write storage, Qubes snapshots/saved VM state, backups and external
exports may retain copies. An I/O error or power loss can leave the original or
a partly overwritten file. No physical-erasure, forensic-concealment or rollback
guarantee is made. Test only on disposable vaults and choose your backup policy
deliberately; recovery copies are also copies these features cannot erase.
