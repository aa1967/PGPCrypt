# OpenPGP keys

Use **Keys & identities → New identity → Create key**. A name or pseudonym is
required. Email and public comment are optional. The comment is part of the
exported identity; keep private annotations in encrypted vault notes instead.

## Algorithms and layout

| Choice | Key material | Layout |
| --- | --- | --- |
| Ed25519 / Cv25519 (default) | Ed25519 signatures, Cv25519 encryption | Primary and separate subkeys |
| RSA | 2048, 3072 or 4096 bits | Single RSA key, or primary plus RSA signing/encryption subkeys (RSA/RSA) |
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

The default expiry is two years from creation. Choose a future UTC date/time or
disable expiry. The selected validity applies to the primary and its subkeys.
The key details display the expiry, algorithm and advertised capabilities.
Editing an existing certificate's expiry is not implemented yet.

New keys require a separate private-key passphrase of at least 16 characters.
Sequoia encrypts all secret packets before they are saved inside the encrypted
vault. Use that key passphrase in the text workspace for signing/decryption.
The vault passphrase and private-key passphrase have separate roles; neither can
be reset. Long, randomly generated passphrases are preferable to predictable text.

**Protect / change key passphrase** protects an unencrypted imported key or
changes the protection on an existing key. All encrypted packets must unlock
with the supplied current passphrase; an error leaves the vault unchanged.
It does not change the vault password or re-encrypt older exports/backups.
**Show protected private key** exports only certificates whose secret packets
are all encrypted. Unprotected private-key export is deliberately unavailable.
Public export never contains secret packets.

## Emergency revocation certificates

Creation also saves Sequoia's revocation certificate in the encrypted vault,
atomically with the new key. Select the key and use **Show revocation
certificate** to copy an offline backup. It does not revoke the certificate
inside the vault. An imported key without a stored ticket requires its primary
private key and passphrase to produce a ticket; enter that passphrase in the
text workspace before returning to the key table.

Anyone possessing the revocation certificate can invalidate the key. Store it
privately and separately from the vault so it is available if the vault or
private key is lost. To revoke a published key, import the ticket into an
OpenPGP tool that holds the public certificate and publish the resulting revoked
public certificate. A revocation does not decrypt old messages or revoke copies
that other people never update.

## Automatic locking

The session locks after five idle minutes by default. Choose 1, 2, 5, 10, 15,
30 or 60 minutes and click **Save timeout**. The setting is encrypted in the
vault and restored at unlock. Focus loss, desktop lock, suspend signals, and
large timer gaps also lock the session. Lock kills the worker, ends the GUI
session and starts a fresh locked GUI; unsaved text is discarded. Native desktop
lock/suspend integration still requires real GNOME/Plasma validation.

## Creating and opening a vault

The start screen offers Create vault, Open vault, and Quit. Create pre-fills
`~/vault.pgpcrypt.age`, always requires matching password/passphrase fields, and
shows a local zxcvbn strength estimate while typing. A minimum of 16 characters
still applies regardless of the estimate. Open uses a file browser and requests
only the existing vault's password/passphrase. Browse also selects a different
save location. No recent-vault list or Qt file-dialog history is saved.
