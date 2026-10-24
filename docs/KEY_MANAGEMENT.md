# OpenPGP keys

Use **Keys → New key → Create key**. A name or pseudonym is
required. Email and public comment are optional. The comment is part of the
exported identity; keep private annotations in encrypted vault notes instead.

## Algorithms and layout

| Choice | Key material | Layout |
| --- | --- | --- |
| Ed25519 / Cv25519 (default) | Ed25519 signatures, Cv25519 encryption | Primary and separate subkeys |
| RSA | 2048 or 4096 bits (creation menu) | Single RSA key, or primary plus RSA signing/encryption subkeys (RSA/RSA) |
| NIST curves | P-256, P-384 or P-521 ECDSA/ECDH | Primary and separate subkeys |

Creation uses Sequoia's OpenSSL backend and an RFC 4880 compatible certificate
profile, without enabling obsolete hash algorithms or weakening StandardPolicy.
RSA-1024 creation is deliberately rejected because its security is inadequate
for new keys. Sequoia's certificate builder does not offer DSA/ElGamal generation;
these legacy choices are not advertised as supported. Existing certificates may
be imported, but use remains subject to the library's algorithm support and
security policy. Import does not guarantee a legacy key will be usable.

Choose certification, signing, encryption of communications, encryption of
storage, and authentication independently where the layout supports it. The
RSA single-key layout allows any nonempty combination, including signing only.
The subkey layout keeps certification on the primary key; at most one signing/
authentication subkey and one encryption subkey are added as selected. A
certification-only identity has no subkeys. The primary key must certify subkey
bindings. Authentication flags do not imply an SSH-agent integration or client
authentication workflow in this version. Certification flags likewise do not
provide a GUI for signing other people's identities yet.

## Expiry and protection

Expiry is off by default. Enable it to choose a future UTC date/time. The selected validity applies to the primary and its subkeys.
The key details display the expiry, algorithm and advertised capabilities.
Editing an existing certificate's expiry is not implemented yet.

Private-key passwords are optional and have no minimum length. Leave both
creation password fields blank to generate a key without a separate password;
otherwise confirmation must match. The vault still encrypts all stored key
material. A password you choose also protects exported private-key packets.
When a signing or decryption key needs its password, a dialog asks for it.
Unprotected keys proceed directly; imported keys encrypted with an empty password
can use an empty answer. Passwords are not cached between operations.

**Set / change / remove key password…** adds or changes a key password, or removes
it when both new fields are blank. Encrypted packets must first unlock with
the current password; an error leaves the vault unchanged. This changes neither
the vault password nor older exports/backups. **Show private key** explicitly
confirms export and identifies unprotected packets before displaying them.
Public export never includes secret packets.

## Notepad and default key

All text-operation controls are on **Notepad**: recipient checkboxes, signing
key selector, Encrypt, Decrypt, Sign, Verify, Open message, Save output and Clear.
The key manager handles key creation/import, inspection and backups.

Select a valid private signing key on the notepad and click **Use signing key
as default**. The choice is encrypted with the vault, restored after unlocking,
and preserved in age/KDBX conversions. **Clear default** removes the saved
choice. You can select another signer for one operation without changing the
default. An expired, revoked or unavailable default is not silently replaced by
another key. Decryption finds matching private keys automatically; encryption
always uses the recipients explicitly checked on the notepad.

## Emergency revocation certificates

Creation also saves Sequoia's revocation certificate in the encrypted vault,
atomically with the new key. Select the key and use **Show revocation
certificate** to copy a backup. It does not revoke the certificate
inside the vault. An imported key without a stored ticket requires its primary
private key to produce a ticket. If its packets are password protected, the
key manager prompts for that password directly.

Anyone possessing the revocation certificate can invalidate the key. Store it
privately and separately from the vault so it is available if the vault or
private key is lost. To revoke a published key, import the ticket into an
OpenPGP tool that holds the public certificate and publish the resulting revoked
public certificate. A revocation does not decrypt old messages or revoke copies
that other people never update.

## Automatic locking

Automatic locking is off by default. **Vault settings** offers optional
inactivity locking (1–60 minutes), focus-loss locking, and desktop/suspend/Qubes
host-lock integration. Lock ends both worker and unlocked UI processes; unsaved
text is discarded. See [Settings](SETTINGS.md) for clipboard clearing and themes.
Native desktop and Qubes host-lock delivery still need real-system validation.

## Creating and opening a vault

The start screen offers Create vault, Open vault, and Quit. Create pre-fills
`~/vault.pgpcrypt.age`, always requires matching password/passphrase fields, and
shows a local zxcvbn strength estimate while typing. There is no enforced minimum; new passwords have a 128-Unicode-character limit. Open uses a file browser and requests
only the existing vault's password/passphrase. Browse also selects a different
save location. Recent vaults can open the password screen directly; disable
remembering in Settings to clear their local paths. Qt file-dialog history
remains disabled.

## Subkey plans (alpha14)

Select a key on **Keys**, then **Manage subkeys…**. The inspector
shows primary/subkey fingerprints, algorithms, capabilities, expiration and
status. Public-only certificates can be inspected; adding a subkey requires the
primary private key and certification capability.

For new keys, enable the optional **Custom subkey plan** in the creation dialog.
Add up to 16 rows with separate purpose (Encryption, Signing or Authentication),
algorithm (Cv25519/Ed25519, RSA 2048/4096 or NIST curves) and expiry. This replaces
the automatically selected subkeys, leaving certification on the primary key.
Without a custom plan, the selected capability checkboxes retain their normal
behavior. Custom plans do not apply to the single-RSA-key layout.

For an existing key, choose **Add subkeys…** in its inspector and build the same
kind of plan. Adding requires a valid certification-capable primary private key;
a public-only certificate or subkey-only secret export cannot certify bindings.
Each expiry must be in the future and cannot exceed the primary key's lifetime.
A finite-lived primary requires finite-lived new subkeys. The new-subkey password
is optional and applies to every row in that batch. A separate prompt requests
the primary key password if needed; passwords are not saved in a plan.

A whole batch is validated and generated before a single atomic vault save.
A failed row leaves the stored certificate unchanged. Existing packets, primary
fingerprint, identity and revocation ticket remain intact.

Export and distribute the updated public certificate so other OpenPGP software
can use the new subkey. Separate subkey revocation and expiry editing are not
implemented in this version. Bulk private-key password changes still need a
password that unlocks all protected packets; differently protected subkeys may
require another OpenPGP tool for password maintenance.

The workflow references [Kleopatra's Add Subkey command](https://github.com/KDE/kleopatra/blob/master/src/commands/addsubkeycommand.cpp): select a certificate,
choose purpose/algorithm/expiry, then certify with the primary secret. PGPCrypt
uses Sequoia's KeyBuilder/SubkeyBuilder rather than a system GnuPG home.

## Signing and message files (alpha8)

**Sign** creates readable cleartext signatures (`BEGIN PGP SIGNED MESSAGE`).
The text remains public. Earlier versions used opaque signed messages with a
`PGP MESSAGE` wrapper; these are also signatures and remain verifiable here.
**Verify** reports the full signing certificate fingerprint only after successful
verification. Compare fingerprints over a trusted channel; valid self-signatures
on a key do not establish its owner's real identity.

Cleartext signing follows OpenPGP text rules: line endings and trailing spaces
can be normalized. Use another established OpenPGP tool for detached signatures
on files whose exact bytes must be preserved; that file workflow is not yet
implemented here.

Notepad now separates **Save to vault** from external **Import/Export**.
Saved documents live inside vault encryption and appear in its document browser;
opening an external file only loads text until an explicit save. See
[the workspace guide](WORKSPACE.md) for profiles, verification labels and files.

For certificates containing several signing keys, unprotected usable signing
secrets are tried first; otherwise the supplied password is tried against usable
signing keys. A protected primary does not force a prompt when an unprotected
signing subkey is available. Certificate-only and encryption-only keys cannot
sign. Oversized imported password-derivation work is refused before derivation.

## Clipboard import

**Paste, clear clipboard and import** reads the clipboard once, clears it
immediately and imports the captured armor into the selected profile. On failure
the pasted text remains available in the import editor for correction. Public
imports merge with an existing certificate without discarding its secret material.
Clipboard managers and copies transferred to another Qube cannot be recalled.
