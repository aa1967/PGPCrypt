# KDBX multi-keyslot design review

Status: design review, 24 October 2026. None of these new multi-keyslot
formats is implemented or an established KDBX feature. The supplied
`kdbx_multi_keyslot_specs.md` is a proposal, not an implementation specification.
Its sandboxing/importer suggestions do not override project decisions; in
particular this work does not reintroduce Bubblewrap.

## Recommendation

For the requested one-prompt base-plus-suffix experience, develop a corrected
**Option 3**, with Option 2 available as a two-step way to open the same file.
Keep an ordinary, writable outer KDBX for the decoy and an independently
authenticated, encrypted inner vault attachment for the real workspace.
Use standard KDBX for the inner database where practical, with a documented
extraction/recovery utility. Standard age remains a useful independent export
and existing-vault format. Do not silently convert or remove either format.

This meets the preference for no public custom-header extension. It does not
provide a claim of plausible deniability. A knowledgeable examiner can inspect
the attachment after obtaining the base password, recognize the application's
format, compare earlier copies, or observe unlocked RAM and UI behavior.

If independent passwords with one prompt become a requirement, corrected
Option 4 is possible but adds public routing metadata, credential-wrapping
complexity and interoperability obligations. It is not needed for Option 3.

| Proposal | Feasibility | Main tradeoff |
| --- | --- | --- |
| 1. Custom outer wrapper | Technically possible, substantial new format | Loses direct KeePassXC opening and adds our own critical storage protocol. Random padding does not make a recognized format deniable. |
| 2. Outer KDBX plus encrypted attachment, two prompts | Feasible; a useful recovery/opening mode | Outer password plus independent inner password. Use a dedicated password dialog; a normal search field is unsuitable for secrets. |
| 3. Same attachment with base-plus-suffix, one prompt | Preferred for the requested UX, after corrections | Revealing the base leaves the suffix as the remaining secret. Define the split without hidden external configuration. |
| 4. Public custom-data routing slots | Feasible only after fixing the credential model and wire layout | Public extension is identifiable. External editors must preserve it, and password/KDF changes require careful handling. |

## Password model

Example role structure: `base`, `base::real-suffix`, `base::wipe-suffix`.
The application must support the user's chosen full strings and never silently
strip, trim, normalize Unicode, or change case beyond the explicitly selected
split rule. For a first version, use one documented fixed delimiter, prohibit
ambiguous base delimiters during creation, and retain direct full-password
opening for ordinary databases. Do not search every possible prefix: that
causes unpredictable behavior and expensive repeated KDF work. Define how a
wrong suffix fails without accidentally entering the writable decoy.

The suffix must carry its own strength after disclosure of the base. Increasing
the base's length or complexity does not improve that conditional security.
The document's 3–4 uniformly random Diceware words are approximately 39–52 bits,
not a universal assurance that cracking is infeasible. Human-chosen words and
predictable `!pgp`/`!wip` suffixes can be far weaker. Offer generation of, for
example, six or more independent random words or sixteen or more random
alphanumeric characters, with an estimate and no claim of a fixed safe lifetime.
A higher target can be selected for higher-value data. Measure the unknown
suffix as well as the full input in the strength UI. Do not introduce a hidden
password minimum.

Independent full credentials remain possible with Option 2 or corrected Option
4. People may choose related passwords there too; the same conditional-entropy
warning applies. All configured role credentials must differ, and the wipe
slot must never contain the real vault's decryption key. The base holder can
already delete or damage the attachment; a wipe password is a convenient
application action, not protection against destructive access by that holder.

## Corrections required in the supplied specification

1. **KDBX cipher construction.** Standard KDBX 4 uses AES-256-CBC or ChaCha20
   with KDBX's separate SHA-256/HMAC authentication machinery. It does not
   encrypt the outer database with ChaCha20-Poly1305. Keep our existing
   AES-256/HMAC/Argon2id profile. AEAD for a new inner wrapping layer is a
   distinct protocol. RFC 8439 covers ChaCha20-Poly1305, not XChaCha20 as a
   finalized RFC variant.
2. **Public header field.** `PublicCustomData` is **12 / 0x0C**, not 13 / 0x0D.
   Binary inner-header attachments are field 3. Use a truthful project namespace,
   not another plugin's name such as `KeeChallenge.SlotData`.
3. **Slot lengths.** The first illustrated secret is 64 serialized bytes.
   With a 16-byte AEAD tag, 32-byte salt and 12-byte nonce, that is **124 bytes**,
   not the proposed 140 unless 16 explicit additional bytes are specified.
   The illustrated `WrappedDualKeySlot` contains **104 bytes**, not 96; with
   those salt/nonce/tag choices it needs **164 bytes** per slot. XChaCha20 uses
   a different nonce length. Every layout needs one consistent table and vectors.
4. **Serialization.** `repr(C)` is not a portable file format. Specify explicit
   little-endian encoding, versions, sizes, domains, nonce generation, AEAD
   associated data, slot/payload binding, checked bounds and integrity failures.
   Authenticate action/offset/length/expiry before using them. Cross-slot and
   cross-vault substitution must fail without ever authorizing destruction.
5. **Missing payload protocol.** A master key alone does not specify payload
   encryption. Define authenticated payload framing, fresh nonces on saves,
   padding placement, inner-format versioning, password rotation, slot updates,
   duplicate matches and interrupted writes. Do not publish a hand-assembled
   crypto format as production-ready merely because its primitives are sound.
6. **Option 4's outer credential mismatch.** Its random `outer_kdbx_passkey`
   does not explain how stock KeePassXC can simultaneously unlock the outer
   database using the user's ordinary decoy password. Routing slots must wrap
   the actual decoy credential, or an exactly specified equivalent composite
   key supported by the library. The current keepass-rs public key API does not
   accept an already-transformed KDBX master key. Do not double-hash or inject a
   transformed key as though it were a password. Outer header HMAC must verify
   before changing the file, even when a public slot decrypted successfully.
7. **Wipe role key separation.** Both proposed common slot structs would put a
   payload/inner key into the wipe slot. A wipe credential must authorize its
   limited action without disclosing the real key. Define how Option 1 finds
   the randomly positioned real slot and obtains decoy access; its loop cannot
   infer the roles of still-encrypted slots. Prefer explicit bounded targets
   authenticated under the wipe credential.
8. **Expiry behavior.** The written `now >= expiry` condition erases an expiry
   of zero, although zero is described as “never.” More broadly, a deadline in
   a decrypted slot is not the current feature of checking inactivity before
   decryption. Local clocks can move, copies can roll back, and KeePassXC will
   not enforce PGPCrypt policy. Specify these as different capabilities.
9. **Resource limits and timing.** Always testing all slots can reduce an early
   match timing signal; it does not make outer unlock, real unlock and wiping
   constant-time. Bound untrusted KDF parameters, slot counts, parser lengths
   and aggregate memory/time before any work. Sequential derivations can still
   be slow in a small Qubes guest. The fixed 128/256 KiB attachment examples
   are too small for many existing key/note collections (current payload limit
   is 16 MiB). Define capacity/growth rules and what size leakage remains.
10. **History and durable writes.** Deleting/replacing one attachment reference
    can leave the old binary referenced by entry history or the recycle bin.
    Purge all managed references and unused copies in the newly written file;
    verify the resulting database before reporting completion. Crash-safe
    atomic replacement preserves availability but can leave old ciphertext
    blocks. Equal attachment length does not guarantee equal outer file size,
    identical layout, or absence of forensic evidence. Backups, Qubes snapshots,
    COW filesystems, saved VM memory and SSD copies remain outside erasure claims.

## Compatibility and recovery requirements

The current application intentionally rejects attachments and public custom
header fields instead of silently dropping unsupported content. keepass-rs
0.17.0 has attachment and public-custom-data APIs, so a new bounded profile is
possible; it requires changes to our preflight, XML validation, preservation,
resource limits, and save/conversion behavior. Its KDBX writing support remains
experimental upstream. Ordinary KDBX compatibility alone is not validation of
our multi-role protocol.

Test stock KeePassXC opening, editing, adding entries, changing the outer
password/KDF, saving, history restoration, export, attachment extraction and
round-tripping unknown fields. A base-password change also changes a
base-plus-suffix full credential: it must deliberately rewrap every configured
role, not silently strand the inner vault or retain an unwanted old route.
KeePassXC cannot update PGPCrypt's role credentials automatically. Loss or
external modification of routing data must never trigger a destructive action.

Provide a standalone, documented recovery path that requires no running GUI:
extract the attachment using KeePassXC, unwrap with the real credential using
the documented utility/specification, then open the recovered standard inner
KDBX. Stock KeePassXC opens only the outer decoy directly; it does not implement
PGPCrypt role selection, wipe or expiry. The portable real recovery file must
contain all keys, identities, notes and automation settings supported today.

Neither an outer decoy nor an inner real session should disclose its role in
ordinary status/activity output. A writable decoy needs complete, independent
save semantics, including preserving unknown or disabled inner data. The
existing read-only dummy view is not this feature and remains unchanged until
a separately implemented migration exists.

## Real-world comparisons

* **KeePassXC/KeePass:** production examples of standard KDBX encryption,
  authenticated headers/blocks, attachments and history. Their ordinary
  password/keyfile composite credential combines factors; it is not multiple
  independent OR-style role passwords. Nested encrypted attachments reuse
  supported storage, but their presence is inspectable after outer unlock.
* **LUKS2/cryptsetup:** a mature example of alternative password slots wrapping
  a volume key and of cryptographic keyslot erasure. Ordinary bound slots open
  the same volume. It supplies neither per-password decoy databases nor assured
  destruction of header backups and previously captured copies.
* **VeraCrypt hidden volumes:** an example of distinct headers/passwords and
  carefully controlled reserved space. The project documents restrictions and
  leakage risks, including outer-volume writes that can damage hidden data.
  A visible KDBX attachment is not equivalent to a VeraCrypt hidden volume;
  disguising its filename does not inherit that design's security properties.

These examples support using established formats and libraries. None is an
off-the-shelf validation of the supplied custom role-slot protocol. Correct
the design and obtain independent cryptographic review before presenting it
as a dependable duress mechanism.

## Sources checked

* [KeePassXC header field IDs](https://github.com/keepassxreboot/keepassxc/blob/2.7.10/src/format/KeePass2.h)
* [KeePassXC KDBX4 writer, including history attachments](https://github.com/keepassxreboot/keepassxc/blob/2.7.10/src/format/Kdbx4Writer.cpp)
* [KeePassXC KDBX4 authenticated reader](https://github.com/keepassxreboot/keepassxc/blob/2.7.10/src/format/Kdbx4Reader.cpp)
* [KeePassXC composite-key implementation](https://github.com/keepassxreboot/keepassxc/blob/2.7.10/src/keys/CompositeKey.cpp)
* [keepass-rs 0.17.0 API/source](https://docs.rs/keepass/0.17.0/keepass/)
* [VeraCrypt hidden-volume documentation](https://github.com/veracrypt/VeraCrypt/blob/master/doc/html/en/Hidden%20Volume.html)
* [cryptsetup FAQ](https://gitlab.com/cryptsetup/cryptsetup/-/wikis/FrequentlyAskedQuestions)
