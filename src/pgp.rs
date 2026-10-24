//! In-process OpenPGP: never uses GNUPGHOME, an agent, or the network.
use anyhow::{Context, Result, bail, ensure};
use openpgp::{
    Cert, KeyHandle,
    crypto::{S2K, SessionKey},
    packet::{
        Key,
        key::{KeyRole, SecretKeyMaterial, SecretParts},
    },
    parse::{Parse, stream::*},
    policy::StandardPolicy,
    serialize::{Serialize, stream::*},
    types::{KeyFlags, ReasonForRevocation, SymmetricAlgorithm},
};
use sequoia_openpgp as openpgp;
use serde::Deserialize;
use std::io::{Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MAX_TEXT: usize = 1024 * 1024;
const MAX_OUTPUT: usize = 4 * MAX_TEXT;

// Imported secret packets are untrusted. In particular, an Argon2 S2K can
// otherwise request terabytes of memory before a password is even checked.
// Match the KDBX reader's per-derivation ceiling: 256 MiB, 10 passes, 4 lanes.
// Limit aggregate work as well when a certificate contains many secret keys.
const MAX_SECRET_UNLOCKS: usize = 16;
const MAX_ARGON2_MEMORY_EXPONENT: u8 = 18; // 2^18 KiB = 256 MiB.
const MAX_ARGON2_PASSES: u8 = 10;
const MAX_ARGON2_LANES: u8 = 4;
const MAX_ARGON2_KIB_PASSES: u64 = (1 << MAX_ARGON2_MEMORY_EXPONENT) * MAX_ARGON2_PASSES as u64;
const MAX_ITERATED_HASH_BYTES: u32 = 0x3e00000; // Largest standard encoded count.

struct SecretUnlockBudget {
    remaining: usize,
    argon2_kib_passes: u64,
}

impl Default for SecretUnlockBudget {
    fn default() -> Self {
        Self {
            remaining: MAX_SECRET_UNLOCKS,
            argon2_kib_passes: MAX_ARGON2_KIB_PASSES,
        }
    }
}

impl SecretUnlockBudget {
    #[allow(deprecated)] // Legacy S2Ks may be read; newly protected keys use library defaults.
    fn charge(&mut self, s2k: &S2K) -> Result<()> {
        ensure!(
            self.remaining > 0,
            "Too many private-key unlock attempts in one operation"
        );
        let argon2_cost = match s2k {
            S2K::Argon2 { t, p, m, .. } => {
                ensure!(
                    (1..=MAX_ARGON2_PASSES).contains(t)
                        && (1..=MAX_ARGON2_LANES).contains(p)
                        && (3..=MAX_ARGON2_MEMORY_EXPONENT).contains(m)
                        && (1u64 << *m) >= 8 * u64::from(*p),
                    "Private-key Argon2 parameters exceed supported resource limits"
                );
                (1u64 << *m) * u64::from(*t)
            }
            S2K::Iterated {
                hash, hash_bytes, ..
            } => {
                ensure!(hash.is_supported(), "Unsupported private-key password hash");
                ensure!(
                    *hash_bytes <= MAX_ITERATED_HASH_BYTES,
                    "Private-key S2K work exceeds supported resource limits"
                );
                0
            }
            S2K::Salted { hash, .. } | S2K::Simple { hash } => {
                ensure!(hash.is_supported(), "Unsupported private-key password hash");
                0
            }
            S2K::Implicit => 0,
            _ => bail!("Unsupported private-key password derivation method"),
        };
        ensure!(
            argon2_cost <= self.argon2_kib_passes,
            "Combined private-key Argon2 work exceeds supported resource limits"
        );
        self.remaining -= 1;
        self.argon2_kib_passes -= argon2_cost;
        Ok(())
    }

    fn unlock<R: KeyRole>(
        &mut self,
        key: Key<SecretParts, R>,
        password: &str,
    ) -> Result<Key<SecretParts, R>> {
        if let SecretKeyMaterial::Encrypted(encrypted) = key.secret() {
            ensure!(
                encrypted.algo().is_supported(),
                "Unsupported private-key protection cipher"
            );
            ensure!(
                encrypted.aead_algo().is_none_or(|algo| algo.is_supported()),
                "Unsupported private-key protection mode"
            );
            self.charge(encrypted.s2k())?;
            // An empty password is valid for imported keys protected with one.
            // Only an actual failed unlock asks the UI to prompt or retry.
            key.decrypt_secret(&password.into())
                .map_err(|_| PasswordRequired.into())
        } else {
            Ok(key)
        }
    }
}

pub fn parse(bytes: &[u8]) -> Result<Cert> {
    ensure!(
        bytes.len() <= MAX_TEXT,
        "Key exceeds the 1 MiB import limit"
    );
    Cert::from_bytes(bytes).context("Could not parse one OpenPGP certificate")
}

pub fn encode(cert: &Cert) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    cert.as_tsk().serialize(&mut *bytes)?;
    Ok(bytes)
}

pub fn generate(identity: &str) -> Result<Cert> {
    ensure!(
        !identity.trim().is_empty() && identity.len() <= 256,
        "Enter an identity of at most 256 bytes"
    );
    // Advertise the GnuPG 2.4-compatible message profile. Modern curves and
    // policy remain enabled; this does not enable SHA-1 document signatures.
    let (cert, _revocation) = openpgp::cert::CertBuilder::general_purpose(Some(identity))
        .set_profile(openpgp::Profile::RFC4880)?
        .set_cipher_suite(openpgp::cert::CipherSuite::Cv25519)
        .set_features(openpgp::types::Features::empty().set_seipdv1())?
        .generate()?;
    Ok(cert)
}

/// Untrusted worker input. Explicit algorithm allowlist; never relax policy to
/// generate obsolete RSA-1024 or DSA/ElGamal keys.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct KeyOptions {
    pub name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub comment: String,
    pub algorithm: String,
    pub layout: String,
    pub signing: bool,
    pub certification: bool,
    pub transport_encryption: bool,
    pub storage_encryption: bool,
    #[serde(default)]
    pub authentication: bool,
    /// Absolute UTC Unix seconds, or null for no expiry.
    pub expires_at: Option<u64>,
}

pub fn generate_with_options(options: &KeyOptions, password: &str) -> Result<(Cert, String)> {
    use openpgp::cert::{CertBuilder, CipherSuite};
    crate::password::validate_new_password(password)?;
    let name = options.name.trim();
    let email = options.email.trim();
    let comment = options.comment.trim();
    ensure!(
        !name.is_empty() && name.len() <= 128,
        "Enter a name or pseudonym of at most 128 bytes"
    );
    ensure!(
        email.len() <= 254 && comment.len() <= 256,
        "Email or comment is too long"
    );
    ensure!(
        [name, email, comment].iter().all(|s| !s
            .chars()
            .any(|c| c.is_control() || matches!(c, '\u{fffe}' | '\u{ffff}'))),
        "Identity fields cannot contain control characters or invalid XML characters"
    );
    // Without an address, construct the conventional name/comment form without
    // introducing a fake or required email address.
    let userid = if email.is_empty() {
        ensure!(
            !name.contains(['<', '>', '(', ')']) && !comment.contains(['(', ')']),
            "Use a name/comment without address delimiters"
        );
        openpgp::packet::UserID::from(if comment.is_empty() {
            name.to_owned()
        } else {
            format!("{name} ({comment})")
        })
    } else {
        openpgp::packet::UserID::from_address(
            Some(name),
            (!comment.is_empty()).then_some(comment),
            email,
        )?
    };
    let suite = match options.algorithm.as_str() {
        "cv25519" => CipherSuite::Cv25519,
        "rsa2048" => CipherSuite::RSA2k,
        "rsa3072" => CipherSuite::RSA3k,
        "rsa4096" => CipherSuite::RSA4k,
        "p256" => CipherSuite::P256,
        "p384" => CipherSuite::P384,
        "p521" => CipherSuite::P521,
        _ => {
            bail!("Unsupported key algorithm; RSA-1024 and DSA/ElGamal generation are unavailable")
        }
    };
    suite.is_supported()?;
    let single = match options.layout.as_str() {
        "single" => {
            ensure!(
                options.algorithm.starts_with("rsa"),
                "A combined single key requires RSA"
            );
            true
        }
        "subkeys" => false,
        _ => bail!("Unsupported key layout"),
    };
    ensure!(
        options.signing
            || options.certification
            || options.transport_encryption
            || options.storage_encryption
            || options.authentication,
        "Select at least one key capability"
    );
    // Sequoia needs a certification-capable primary when issuing subkey
    // bindings. A single RSA key may have any nonempty capability combination.
    ensure!(
        single || options.certification,
        "A certificate with subkeys needs primary certification capability"
    );
    let now = SystemTime::now();
    let validity = options
        .expires_at
        .map(|seconds| -> Result<Duration> {
            let expiration = UNIX_EPOCH
                .checked_add(Duration::from_secs(seconds))
                .context("Invalid expiry date")?;
            let duration = expiration
                .duration_since(now)
                .context("Expiry must be in the future")?;
            ensure!(
                duration.as_secs() >= 60 && duration.as_secs() <= u32::MAX as u64,
                "Expiry must be at least a minute in the future and within the OpenPGP limit"
            );
            Ok(duration)
        })
        .transpose()?;
    let mut primary = KeyFlags::empty();
    if options.certification {
        primary = primary.set_certification();
    }
    let mut signing = KeyFlags::empty();
    if options.signing {
        signing = signing.set_signing();
    }
    if options.authentication {
        signing = signing.set_authentication();
    }
    let mut encryption = KeyFlags::empty();
    if options.transport_encryption {
        encryption = encryption.set_transport_encryption();
    }
    if options.storage_encryption {
        encryption = encryption.set_storage_encryption();
    }
    if single {
        primary = &(&primary | &signing) | &encryption;
    }
    let mut builder = CertBuilder::new()
        .set_profile(openpgp::Profile::RFC4880)?
        .set_cipher_suite(suite)
        .set_creation_time(now)
        .set_primary_key_flags(primary)
        .set_validity_period(validity)
        .set_features(openpgp::types::Features::empty().set_seipdv1())?
        .set_password((!password.is_empty()).then(|| password.into()))
        .add_userid(userid);
    if !single {
        if options.signing || options.authentication {
            builder = builder.add_subkey(signing, None, None);
        }
        if options.transport_encryption || options.storage_encryption {
            builder = builder.add_subkey(encryption, None, None);
        }
    }
    let (cert, revocation) = builder.generate()?;
    let ticket = revocation_armor(revocation)?;
    Ok((cert, ticket))
}

fn revocation_armor(signature: openpgp::packet::Signature) -> Result<String> {
    let mut bytes = Vec::new();
    let mut armor = openpgp::armor::Writer::new(&mut bytes, openpgp::armor::Kind::PublicKey)?;
    openpgp::Packet::Signature(signature).serialize(&mut armor)?;
    armor.finalize()?;
    Ok(String::from_utf8(bytes)?)
}

pub fn revocation_ticket(cert: &Cert, password: &str) -> Result<String> {
    let key = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .context("The primary private key is required to create a revocation certificate")?;
    let key = SecretUnlockBudget::default().unlock(key, password)?;
    let signature = openpgp::cert::CertRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::Unspecified, b"Emergency revocation")?
        .build(&mut key.into_keypair()?, cert, None)?;
    revocation_armor(signature)
}

/// Export only already protected secret packets. Unprotected imports remain
/// usable within the vault, but cannot accidentally be copied out in plaintext.
pub fn protected_private_armor(cert: &Cert) -> Result<Zeroizing<String>> {
    ensure!(cert.is_tsk(), "Selected key has no private material");
    ensure!(
        cert.keys()
            .secret()
            .all(|ka| ka.key().secret().is_encrypted()),
        "Private export requires all secret packets to be passphrase protected"
    );
    private_armor(cert)
}

/// Used only for explicit private export; an empty key password means that
/// copied secret packets have no protection beyond their destination storage.
pub fn private_armor(cert: &Cert) -> Result<Zeroizing<String>> {
    ensure!(cert.is_tsk(), "Selected key has no private material");
    let mut bytes = Zeroizing::new(Vec::new());
    cert.as_tsk().armored().serialize(&mut *bytes)?;
    Ok(Zeroizing::new(std::str::from_utf8(&bytes)?.to_owned()))
}

/// Require successful authentication of every encrypted secret packet before
/// displaying or exporting a certificate. Decrypt only temporary clones for
/// this check: the exported certificate retains its original packet protection.
/// Certificates containing unprotected packets also need the caller's separate
/// vault-password check before they can leave the encrypted vault.
pub fn authenticated_private_armor(cert: &Cert, password: &str) -> Result<Zeroizing<String>> {
    ensure!(cert.is_tsk(), "Selected key has no private material");
    let mut budget = SecretUnlockBudget::default();
    for ka in cert.keys().secret() {
        if ka.key().secret().is_encrypted() {
            // Do not accept a usable signing subkey as authorization for other
            // secret packets which may carry different passwords.
            let unlocked = budget.unlock(ka.key().clone(), password)?;
            drop(unlocked);
        }
    }
    private_armor(cert)
}

pub fn protect_private_key(cert: &Cert, old_password: &str, new_password: &str) -> Result<Cert> {
    crate::password::validate_new_password(new_password)?;
    ensure!(cert.is_tsk(), "Selected key has no private material");
    let mut packets = Vec::new();
    let mut budget = SecretUnlockBudget::default();
    for ka in cert.keys().secret() {
        let primary = ka.key().fingerprint() == cert.fingerprint();
        let mut key = budget.unlock(ka.key().clone(), old_password).context(
            "Could not unlock a secret key packet; check the current password/passphrase",
        )?;
        if !new_password.is_empty() {
            key = key.encrypt_secret(&new_password.into())?;
        }
        packets.push(if primary {
            openpgp::Packet::from(key.role_into_primary())
        } else {
            openpgp::Packet::from(key.role_into_subordinate())
        });
    }
    Ok(cert
        .clone()
        .insert_packets_merge(packets, |_old, new| Ok(new))?
        .0)
}

pub fn public_armor(cert: &Cert) -> Result<String> {
    let mut bytes = Vec::new();
    cert.armored().serialize(&mut bytes)?;
    Ok(String::from_utf8(bytes)?)
}

pub fn encrypt(text: &str, certs: &[Cert]) -> Result<String> {
    bounded(text)?;
    ensure!(!certs.is_empty(), "Select at least one recipient");
    let policy = StandardPolicy::new();
    let mut recipients = Vec::new();
    for cert in certs {
        validate_for_new_operation(cert, &policy)?;
        let keys: Vec<_> = cert
            .keys()
            .with_policy(&policy, None)
            .supported()
            .alive()
            .revoked(false)
            .filter(|ka| {
                ka.key_flags()
                    .is_some_and(|f| f.for_transport_encryption() || f.for_storage_encryption())
            })
            .collect();
        ensure!(!keys.is_empty(), "Recipient has no valid encryption key");
        recipients.extend(keys);
    }
    let mut output = Vec::new();
    let message = Armorer::new(Message::new(&mut output)).build()?;
    let message = Encryptor::for_recipients(message, recipients)
        .symmetric_algo(SymmetricAlgorithm::AES256)
        .build()?;
    let mut literal = LiteralWriter::new(message).build()?;
    literal.write_all(text.as_bytes())?;
    literal.finalize()?;
    Ok(String::from_utf8(output)?)
}

#[derive(Debug)]
pub struct PasswordRequired;
impl std::fmt::Display for PasswordRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Private-key password/passphrase required or incorrect")
    }
}
impl std::error::Error for PasswordRequired {}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct SubkeyOptions {
    pub algorithm: String,
    pub purpose: String,
    pub expires_at: Option<u64>,
}
/// All generated packets stay in memory until the caller commits the complete
/// certificate. A later invalid row therefore cannot leave a partial save.
pub fn add_subkeys(
    cert: &Cert,
    plan: &[SubkeyOptions],
    primary_password: &str,
    subkey_password: &str,
) -> Result<Cert> {
    ensure!(
        (1..=16).contains(&plan.len()),
        "Choose 1–16 subkeys per batch"
    );
    let mut updated = cert.clone();
    let mut budget = SecretUnlockBudget::default();
    for options in plan {
        updated = add_subkey_with_budget(
            &updated,
            options,
            primary_password,
            subkey_password,
            &mut budget,
        )?;
    }
    Ok(updated)
}

pub fn add_subkey(
    cert: &Cert,
    options: &SubkeyOptions,
    primary_password: &str,
    subkey_password: &str,
) -> Result<Cert> {
    add_subkey_with_budget(
        cert,
        options,
        primary_password,
        subkey_password,
        &mut SecretUnlockBudget::default(),
    )
}

fn add_subkey_with_budget(
    cert: &Cert,
    options: &SubkeyOptions,
    primary_password: &str,
    subkey_password: &str,
    budget: &mut SecretUnlockBudget,
) -> Result<Cert> {
    use openpgp::cert::{CipherSuite, KeyBuilder};
    crate::password::validate_new_password(subkey_password)?;
    let policy = StandardPolicy::new();
    validate_for_new_operation(cert, &policy)?;
    let valid = cert.with_policy(&policy, None)?;
    ensure!(
        valid.primary_key().for_certification(),
        "Primary key must support certification"
    );
    let primary = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .context("Primary private key required to certify a new subkey")?;
    let primary = budget.unlock(primary, primary_password)?;
    let suite = match options.algorithm.as_str() {
        "cv25519" => CipherSuite::Cv25519,
        "rsa2048" => CipherSuite::RSA2k,
        "rsa3072" => CipherSuite::RSA3k,
        "rsa4096" => CipherSuite::RSA4k,
        "p256" => CipherSuite::P256,
        "p384" => CipherSuite::P384,
        "p521" => CipherSuite::P521,
        _ => bail!("Unsupported subkey algorithm"),
    };
    let flags = match options.purpose.as_str() {
        "sign" => KeyFlags::empty().set_signing(),
        "encrypt" => KeyFlags::empty()
            .set_transport_encryption()
            .set_storage_encryption(),
        "authenticate" => KeyFlags::empty().set_authentication(),
        _ => bail!("Unsupported subkey purpose"),
    };
    let expiry = options
        .expires_at
        .map(|seconds| -> Result<SystemTime> {
            let time = UNIX_EPOCH
                .checked_add(Duration::from_secs(seconds))
                .context("Invalid subkey expiry")?;
            ensure!(
                time.duration_since(SystemTime::now())?.as_secs() >= 60,
                "Choose an expiry at least one minute in the future"
            );
            if let Some(primary_expiry) = valid.primary_key().key_expiration_time() {
                ensure!(
                    time <= primary_expiry,
                    "Subkey expiry must not exceed primary key expiry"
                );
            }
            Ok(time)
        })
        .transpose()?;
    ensure!(
        expiry.is_some() || valid.primary_key().key_expiration_time().is_none(),
        "Choose a subkey expiry within the primary key lifetime"
    );
    let result = KeyBuilder::new(flags)
        .set_creation_time(SystemTime::now())
        .set_cipher_suite(suite)
        .set_password((!subkey_password.is_empty()).then(|| subkey_password.into()))
        .subkey(valid)?
        .set_primary_key_signer(primary.into_keypair()?)
        .set_key_expiration_time(expiry)?
        .attach_cert()?;
    ensure!(
        result.fingerprint() == cert.fingerprint(),
        "Primary fingerprint changed unexpectedly"
    );
    Ok(result)
}

#[derive(Clone, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct KeyPassword {
    pub fingerprint: String,
    pub password: String,
}
fn key_password<'a>(passwords: &'a [KeyPassword], fingerprint: &str, fallback: &'a str) -> &'a str {
    passwords
        .iter()
        .find(|entry| entry.fingerprint == fingerprint)
        .map_or(fallback, |entry| entry.password.as_str())
}

#[derive(Debug)]
pub struct KeyPasswordHint(pub String);
impl std::fmt::Display for KeyPasswordHint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Unlock key {}", self.0)
    }
}
impl std::error::Error for KeyPasswordHint {}

fn signing_pair(
    cert: &Cert,
    password: &str,
    budget: &mut SecretUnlockBudget,
) -> Result<openpgp::crypto::KeyPair> {
    let policy = StandardPolicy::new();
    validate_for_new_operation(cert, &policy)?;
    let mut keys: Vec<_> = cert
        .keys()
        .with_policy(&policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_signing()
        .secret()
        .collect();
    ensure!(!keys.is_empty(), "Selected key has no valid signing secret");
    if password.is_empty() {
        // A certificate can mix protected and unprotected subkeys. Do not ask
        // for an unrelated password when an eligible signing key needs none.
        keys.sort_by_key(|ka| ka.key().secret().is_encrypted());
    }
    let mut password_required = false;
    let mut unusable = None;
    for candidate in keys {
        let key = match budget.unlock(candidate.key().clone(), password) {
            Ok(key) => key,
            Err(error) if error.is::<PasswordRequired>() => {
                password_required = true;
                continue;
            }
            Err(error) => {
                if unusable.is_none() {
                    unusable = Some(error);
                }
                continue;
            }
        };
        return key.into_keypair();
    }
    if password_required {
        return Err(PasswordRequired.into());
    }
    Err(unusable.context("Selected key has no usable signing secret")?)
}

pub fn sign(text: &str, cert: &Cert, password: &str) -> Result<String> {
    sign_many(text, std::slice::from_ref(cert), password, &[])
}
pub fn sign_many(
    text: &str,
    certs: &[Cert],
    password: &str,
    passwords: &[KeyPassword],
) -> Result<String> {
    bounded(text)?;
    ensure!((1..=16).contains(&certs.len()), "Choose 1–16 signing keys");
    let mut budget = SecretUnlockBudget::default();
    let mut pairs = Vec::new();
    for cert in certs {
        let fp = cert.fingerprint().to_hex();
        pairs.push(
            signing_pair(cert, key_password(passwords, &fp, password), &mut budget)
                .with_context(|| KeyPasswordHint(fp))?,
        );
    }
    let mut output = Vec::new();
    let mut pairs = pairs.into_iter();
    let mut builder = Signer::new(
        Message::new(&mut output),
        pairs.next().context("Missing signing key")?,
    )?;
    for pair in pairs {
        builder = builder.add_signer(pair)?;
    }
    let mut message = builder.cleartext().build()?;
    message.write_all(text.as_bytes())?;
    message.finalize()?;
    Ok(String::from_utf8(output)?)
}

fn bounded(text: &str) -> Result<()> {
    ensure!(text.len() <= MAX_TEXT, "Plaintext exceeds 1 MiB");
    Ok(())
}

fn bounded_message(text: &str) -> Result<()> {
    // ASCII armor and signature framing can make our own 1 MiB plaintext
    // exceed 1 MiB. Retain a separate bounded allowance for imported messages.
    ensure!(text.len() <= MAX_OUTPUT, "OpenPGP message exceeds 4 MiB");
    Ok(())
}

fn validate_for_new_operation(cert: &Cert, policy: &StandardPolicy) -> Result<()> {
    let cert = cert.with_policy(policy, None)?;
    cert.alive()?;
    ensure!(
        !matches!(
            cert.revocation_status(),
            openpgp::types::RevocationStatus::Revoked(_)
        ),
        "Certificate has been revoked"
    );
    Ok(())
}

pub struct Opened {
    pub text: Zeroizing<String>,
    pub signers: Vec<String>,
    pub decryption_keys: Vec<String>,
}

struct Helper {
    certs: Vec<Cert>,
    password: Zeroizing<String>,
    require_signature: bool,
    signers: Vec<String>,
    decryption_keys: Vec<String>,
    decryption_filter: Vec<String>,
    key_passwords: Vec<KeyPassword>,
    unlock_budget: SecretUnlockBudget,
}

impl VerificationHelper for Helper {
    fn get_certs(&mut self, _: &[KeyHandle]) -> Result<Vec<Cert>> {
        Ok(self.certs.clone())
    }
    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        for layer in structure.iter() {
            if let MessageLayer::SignatureGroup { results } = layer {
                ensure!(!results.is_empty(), "Empty signature group");
                for result in results {
                    match result {
                        Ok(good) => self.signers.push(good.ka.cert().fingerprint().to_hex()),
                        Err(_) => bail!(
                            "Signature is invalid, unsupported, expired, or its public key is missing"
                        ),
                    }
                }
            }
        }
        ensure!(
            !self.require_signature || !self.signers.is_empty(),
            "No valid signature found"
        );
        Ok(())
    }
}

impl DecryptionHelper for Helper {
    fn decrypt(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> Result<Option<Cert>> {
        let policy = StandardPolicy::new();
        let mut password_required = false;
        let mut unusable = None;
        let mut needed_key = None;
        for cert in &self.certs {
            let fingerprint = cert.fingerprint().to_hex();
            if !self.decryption_filter.is_empty() && !self.decryption_filter.contains(&fingerprint)
            {
                continue;
            }
            for ka in cert
                .keys()
                .secret()
                .with_policy(&policy, None)
                .supported()
                .filter(|ka| {
                    ka.key_flags()
                        .is_some_and(|f| f.for_transport_encryption() || f.for_storage_encryption())
                })
            {
                let key = ka.key().clone();
                if !pkesks.iter().any(|p| {
                    p.recipient()
                        .is_none_or(|recipient| recipient.aliases(key.key_handle()))
                }) {
                    continue;
                }
                let key = match self.unlock_budget.unlock(
                    key,
                    key_password(&self.key_passwords, &fingerprint, self.password.as_str()),
                ) {
                    Ok(key) => key,
                    Err(error) if error.is::<PasswordRequired>() => {
                        password_required = true;
                        if needed_key.is_none() {
                            needed_key = Some(fingerprint.clone());
                        }
                        continue;
                    }
                    Err(error) => {
                        if unusable.is_none() {
                            unusable = Some(error);
                        }
                        continue;
                    }
                };
                let mut pair = key.into_keypair()?;
                for pkesk in pkesks {
                    if let Some((algo, session_key)) = pkesk.decrypt(&mut pair, sym_algo)
                        && decrypt(algo, &session_key)
                    {
                        self.decryption_keys.push(cert.fingerprint().to_hex());
                        return Ok(Some(cert.clone()));
                    }
                }
            }
        }
        if password_required {
            return Err(anyhow::Error::new(PasswordRequired)
                .context(KeyPasswordHint(needed_key.unwrap_or_default())));
        }
        if let Some(error) = unusable {
            return Err(error);
        }
        bail!(
            "No usable decryption key; check key passphrase, expiration, and imported secret keys"
        )
    }
}

fn read_authenticated(reader: &mut impl Read) -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take((MAX_OUTPUT + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_OUTPUT,
        "Decoded text exceeds the 4 MiB limit"
    );
    // The caller receives nothing on any read/authentication error.
    Ok(Zeroizing::new(
        std::str::from_utf8(&bytes)
            .context("Output is binary; text only in this version")?
            .to_owned(),
    ))
}

pub fn decrypt(text: &str, certs: Vec<Cert>, password: &str) -> Result<Opened> {
    decrypt_selected(text, certs, password, &[], &[])
}
pub fn decrypt_selected(
    text: &str,
    certs: Vec<Cert>,
    password: &str,
    allowed: &[String],
    passwords: &[KeyPassword],
) -> Result<Opened> {
    bounded_message(text)?;
    let helper = Helper {
        certs,
        password: Zeroizing::new(password.into()),
        require_signature: false,
        signers: vec![],
        decryption_keys: vec![],
        decryption_filter: allowed.to_vec(),
        key_passwords: passwords.to_vec(),
        unlock_budget: SecretUnlockBudget::default(),
    };
    let policy = StandardPolicy::new();
    let mut reader = DecryptorBuilder::from_bytes(text)?.with_policy(&policy, None, helper)?;
    let text = read_authenticated(&mut reader)?;
    let signers = reader.helper_ref().signers.clone();
    let decryption_keys = reader.helper_ref().decryption_keys.clone();
    Ok(Opened {
        text,
        signers,
        decryption_keys,
    })
}

pub fn verify(text: &str, certs: Vec<Cert>) -> Result<Opened> {
    bounded_message(text)?;
    let helper = Helper {
        certs,
        password: Zeroizing::new(String::new()),
        require_signature: true,
        signers: vec![],
        decryption_keys: vec![],
        decryption_filter: vec![],
        key_passwords: Vec::new(),
        unlock_budget: SecretUnlockBudget::default(),
    };
    let policy = StandardPolicy::new();
    let mut reader = VerifierBuilder::from_bytes(text)?.with_policy(&policy, None, helper)?;
    let text = read_authenticated(&mut reader)?;
    let signers = reader.helper_ref().signers.clone();
    let decryption_keys = reader.helper_ref().decryption_keys.clone();
    Ok(Opened {
        text,
        signers,
        decryption_keys,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(algorithm: &str, layout: &str) -> KeyOptions {
        KeyOptions {
            name: "Key options fixture".into(),
            email: String::new(),
            comment: "Optional public comment".into(),
            algorithm: algorithm.into(),
            layout: layout.into(),
            signing: true,
            certification: true,
            transport_encryption: true,
            storage_encryption: true,
            authentication: false,
            expires_at: Some(
                (SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
                    + Duration::from_secs(86400))
                .as_secs(),
            ),
        }
    }

    #[test]
    fn configurable_generation_protection_expiry_and_revocation() -> Result<()> {
        const PASSWORD: &str = "disposable configurable key password";
        let settings = options("cv25519", "subkeys");
        let (cert, ticket) = generate_with_options(&settings, PASSWORD)?;
        assert_eq!(cert.keys().count(), 3);
        assert!(
            cert.keys()
                .secret()
                .all(|ka| ka.key().secret().is_encrypted())
        );
        assert!(
            cert.with_policy(&StandardPolicy::new(), None)?
                .primary_key()
                .key_expiration_time()
                .is_some()
        );
        assert!(!public_armor(&cert)?.contains("PRIVATE KEY"));
        assert_eq!(cert.userids().next().unwrap().userid().email()?, None);
        let revoked = cert
            .clone()
            .insert_packets(openpgp::Packet::from_bytes(ticket.as_bytes())?)?
            .0;
        assert!(matches!(
            revoked.revocation_status(&StandardPolicy::new(), None),
            openpgp::types::RevocationStatus::Revoked(_)
        ));
        assert!(sign("message", &cert, "wrong").is_err());
        let changed = protect_private_key(&cert, PASSWORD, "replacement private key passphrase")?;
        assert!(sign("message", &changed, PASSWORD).is_err());
        let signed = sign("message", &changed, "replacement private key passphrase")?;
        assert_eq!(verify(&signed, vec![changed])?.text.as_str(), "message");
        Ok(())
    }

    #[test]
    fn rsa_single_key_and_storage_only_subkey() -> Result<()> {
        const PASSWORD: &str = "disposable capabilities passphrase";
        let mut single = options("rsa2048", "single");
        single.certification = false;
        single.transport_encryption = false;
        single.storage_encryption = false;
        let (cert, _) = generate_with_options(&single, PASSWORD)?;
        assert_eq!(cert.keys().count(), 1);
        assert!(encrypt("message", std::slice::from_ref(&cert)).is_err());
        sign("message", &cert, PASSWORD)?;
        let mut storage = options("p256", "subkeys");
        storage.signing = false;
        storage.transport_encryption = false;
        let (cert, _) = generate_with_options(&storage, PASSWORD)?;
        assert!(sign("message", &cert, PASSWORD).is_err());
        let message = encrypt("storage message", std::slice::from_ref(&cert))?;
        assert_eq!(
            decrypt(&message, vec![cert], PASSWORD)?.text.as_str(),
            "storage message"
        );
        Ok(())
    }

    #[test]
    fn rejects_weak_algorithms_and_past_expiry() {
        let mut settings = options("rsa1024", "single");
        assert!(generate_with_options(&settings, "disposable key passphrase").is_err());
        settings.algorithm = "dsa_elgamal".into();
        assert!(generate_with_options(&settings, "disposable key passphrase").is_err());
        settings.algorithm = "rsa2048".into();
        settings.expires_at = Some(1);
        assert!(generate_with_options(&settings, "disposable key passphrase").is_err());
    }

    #[test]
    fn new_key_identity_fields_reject_nonportable_xml_characters() {
        for invalid in ['\u{fffe}', '\u{ffff}'] {
            let mut settings = options("cv25519", "subkeys");
            settings.name.push(invalid);
            assert!(generate_with_options(&settings, "").is_err());
            settings = options("cv25519", "subkeys");
            settings.email = format!("fixture{invalid}@example.invalid");
            assert!(generate_with_options(&settings, "").is_err());
            settings = options("cv25519", "subkeys");
            settings.comment.push(invalid);
            assert!(generate_with_options(&settings, "").is_err());
        }
    }

    #[test]
    fn optional_and_short_key_passwords_support_crypto_and_removal() -> Result<()> {
        for password in ["", "x"] {
            let (cert, _) = generate_with_options(&options("cv25519", "subkeys"), password)?;
            assert!(
                cert.keys()
                    .secret()
                    .all(|ka| ka.key().secret().is_encrypted() != password.is_empty())
            );
            let encrypted = encrypt("optional password fixture", std::slice::from_ref(&cert))?;
            assert_eq!(
                decrypt(&encrypted, vec![cert.clone()], password)?
                    .text
                    .as_str(),
                "optional password fixture"
            );
            let signed = sign("signature fixture", &cert, password)?;
            assert_eq!(
                verify(&signed, vec![cert.clone()])?.text.as_str(),
                "signature fixture"
            );
            let short = protect_private_key(&cert, password, "a")?;
            assert!(sign("fixture", &short, "wrong").is_err());
            let plain = protect_private_key(&short, "a", "")?;
            assert!(
                plain
                    .keys()
                    .secret()
                    .all(|ka| !ka.key().secret().is_encrypted())
            );
            sign("fixture", &plain, "")?;
            assert_eq!(
                decrypt(&encrypted, vec![plain.clone()], "")?.text.as_str(),
                "optional password fixture"
            );
            assert!(private_armor(&plain)?.contains("BEGIN PGP PRIVATE KEY BLOCK"));
            assert!(protected_private_armor(&plain).is_err());
        }
        Ok(())
    }

    #[test]
    fn private_export_authenticates_all_secret_packets_without_changing_protection() -> Result<()> {
        let mut settings = options("cv25519", "subkeys");
        settings.expires_at = None;
        let (cert, _) = generate_with_options(&settings, "export password")?;
        let before = encode(&cert)?;
        for password in ["", "wrong"] {
            let error = authenticated_private_armor(&cert, password).unwrap_err();
            assert!(error.is::<PasswordRequired>());
        }
        let exported = authenticated_private_armor(&cert, "export password")?;
        let parsed = parse(exported.as_bytes())?;
        assert_eq!(encode(&parsed)?.as_slice(), before.as_slice());
        assert_eq!(encode(&cert)?.as_slice(), before.as_slice());
        assert!(
            parsed
                .keys()
                .secret()
                .all(|ka| ka.key().secret().is_encrypted())
        );
        assert!(sign("exported fixture", &parsed, "wrong").is_err());
        sign("exported fixture", &parsed, "export password")?;

        // A password which unlocks a single signing packet must not authorize
        // export of primary/encryption packets carrying another password.
        let mixed = add_subkey(
            &cert,
            &SubkeyOptions {
                algorithm: "cv25519".into(),
                purpose: "sign".into(),
                expires_at: None,
            },
            "export password",
            "different subkey password",
        )?;
        assert!(
            authenticated_private_armor(&mixed, "export password")
                .unwrap_err()
                .is::<PasswordRequired>()
        );
        assert!(
            authenticated_private_armor(&mixed, "different subkey password")
                .unwrap_err()
                .is::<PasswordRequired>()
        );
        Ok(())
    }

    #[test]
    fn new_key_password_character_limit_preserves_legacy_unlocking() -> Result<()> {
        let settings = options("cv25519", "subkeys");
        let allowed = "é".repeat(128);
        let too_long = "é".repeat(129);
        assert!(generate_with_options(&settings, &too_long).is_err());
        let (cert, _) = generate_with_options(&settings, &allowed)?;
        assert!(protect_private_key(&cert, &allowed, &too_long).is_err());
        assert!(
            add_subkey(
                &cert,
                &SubkeyOptions {
                    algorithm: "cv25519".into(),
                    purpose: "sign".into(),
                    expires_at: None,
                },
                &allowed,
                &too_long,
            )
            .is_err()
        );
        // Existing imported packets may exceed the new creation limit. Such
        // passwords must remain valid for signing, export and replacement.
        let long_legacy_password = "legacy".repeat(32);
        let (legacy, _) =
            openpgp::cert::CertBuilder::general_purpose(Some("Legacy password fixture"))
                .set_password(Some(long_legacy_password.clone().into()))
                .generate()?;
        sign("legacy fixture", &legacy, &long_legacy_password)?;
        authenticated_private_armor(&legacy, &long_legacy_password)?;
        let replaced = protect_private_key(&legacy, &long_legacy_password, "x")?;
        sign("replacement fixture", &replaced, "x")?;
        Ok(())
    }

    #[test]
    fn signing_is_readable_cleartext_and_rejects_tampering() -> Result<()> {
        let cert = generate("Cleartext signing fixture")?;
        let input = "Readable UTF-8 — text\t \n-dash escaped line\nlast line  \t\n";
        let signed = sign(input, &cert, "")?;
        assert!(signed.starts_with("-----BEGIN PGP SIGNED MESSAGE-----\n"));
        assert!(signed.contains("Readable UTF-8 — text\n"));
        assert!(signed.contains("\n- -dash escaped line\n"));
        assert!(signed.contains("-----BEGIN PGP SIGNATURE-----"));
        assert!(!signed.contains("-----BEGIN PGP MESSAGE-----"));
        // RFC 9580's cleartext framework ignores trailing spaces/tabs. The
        // generated armor preserves this input's final LF; a separate test
        // below covers input without a final LF. This is not byte-preserving.
        let verified = verify(&signed, vec![cert.clone()])?;
        assert_eq!(
            verified.text.as_str(),
            "Readable UTF-8 — text\n-dash escaped line\nlast line\n"
        );
        assert_eq!(verified.signers, [cert.fingerprint().to_hex()]);
        assert!(
            verify(
                &signed.replace("last line", "changed line"),
                vec![cert.clone()]
            )
            .is_err()
        );
        assert_eq!(
            verify(&sign("no newline", &cert, "")?, vec![cert])?
                .text
                .as_str(),
            "no newline"
        );
        Ok(())
    }

    #[test]
    fn legacy_opaque_signatures_remain_verifiable_without_losing_bytes() -> Result<()> {
        let cert = generate("Opaque signature fixture")?;
        let policy = StandardPolicy::new();
        let key = cert
            .keys()
            .secret()
            .with_policy(&policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_signing()
            .next()
            .context("Fixture signing key missing")?
            .key()
            .clone()
            .into_keypair()?;
        let input = "Opaque signatures preserve trailing bytes \t\n";
        let mut bytes = Vec::new();
        let message = Armorer::new(Message::new(&mut bytes)).build()?;
        let message = Signer::new(message, key)?.build()?;
        let mut literal = LiteralWriter::new(message).build()?;
        literal.write_all(input.as_bytes())?;
        literal.finalize()?;
        let signed = String::from_utf8(bytes)?;
        assert!(signed.starts_with("-----BEGIN PGP MESSAGE-----"));
        assert_eq!(verify(&signed, vec![cert])?.text.as_str(), input);
        Ok(())
    }

    #[test]
    fn largest_plaintext_outputs_can_be_opened_again() -> Result<()> {
        let cert = generate("Message size regression fixture")?;
        let plaintext = "x".repeat(MAX_TEXT);
        let encrypted = encrypt(&plaintext, std::slice::from_ref(&cert))?;
        assert!(encrypted.len() > MAX_TEXT && encrypted.len() <= MAX_OUTPUT);
        assert_eq!(
            decrypt(&encrypted, vec![cert.clone()], "")?.text.as_str(),
            plaintext
        );
        let signed = sign(&plaintext, &cert, "")?;
        assert!(signed.len() > MAX_TEXT && signed.len() <= MAX_OUTPUT);
        assert_eq!(
            verify(&signed, vec![cert.clone()])?.text.as_str(),
            plaintext
        );
        assert!(sign(&(plaintext.clone() + "x"), &cert, "").is_err());
        assert!(encrypt(&(plaintext + "x"), std::slice::from_ref(&cert)).is_err());
        let oversized = "x".repeat(MAX_OUTPUT + 1);
        assert!(decrypt(&oversized, vec![cert.clone()], "").is_err());
        assert!(verify(&oversized, vec![cert]).is_err());
        Ok(())
    }

    #[test]
    fn mixed_signing_subkeys_only_prompt_when_no_candidate_unlocks() -> Result<()> {
        let mut settings = options("cv25519", "subkeys");
        settings.expires_at = None;
        let (cert, _) = generate_with_options(&settings, "original")?;
        let subkey = SubkeyOptions {
            algorithm: "cv25519".into(),
            purpose: "sign".into(),
            expires_at: None,
        };
        let passwordless = add_subkey(&cert, &subkey, "original", "")?;
        assert!(
            passwordless
                .keys()
                .secret()
                .any(|ka| ka.key().secret().is_encrypted())
        );
        assert!(
            passwordless
                .keys()
                .secret()
                .any(|ka| !ka.key().secret().is_encrypted())
        );
        let signed = sign("mixed passwordless signing", &passwordless, "")?;
        assert_eq!(
            verify(&signed, vec![passwordless])?.text.as_str(),
            "mixed passwordless signing"
        );

        let protected = add_subkey(&cert, &subkey, "original", "different")?;
        let error = sign("mixed protected signing", &protected, "wrong").unwrap_err();
        assert!(error.is::<PasswordRequired>());
        let signed = sign("mixed protected signing", &protected, "different")?;
        assert_eq!(
            verify(&signed, vec![protected])?.text.as_str(),
            "mixed protected signing"
        );
        let error = revocation_ticket(&cert, "wrong").unwrap_err();
        assert!(error.is::<PasswordRequired>());
        assert!(revocation_ticket(&cert, "original")?.contains("BEGIN PGP PUBLIC KEY BLOCK"));
        Ok(())
    }

    #[test]
    fn imported_empty_password_and_s2k_work_limits() -> Result<()> {
        use openpgp::packet::key::Encrypted;
        use openpgp::types::AEADAlgorithm;
        let cert = generate("Imported key protection fixture")?;
        let key = cert.primary_key().key().clone().parts_into_secret()?;
        // Some external tools can encrypt packets with an empty password;
        // this is distinct from our choice to generate an unprotected packet.
        let encrypted = key.clone().encrypt_secret(&"".into())?;
        assert!(encrypted.secret().is_encrypted());
        let empty_password_cert = cert
            .clone()
            .insert_packets_merge(openpgp::Packet::from(encrypted.clone()), |_old, new| {
                Ok(new)
            })?
            .0;
        assert!(
            parse(authenticated_private_armor(&empty_password_cert, "")?.as_bytes())?
                .primary_key()
                .key()
                .parts_as_secret()?
                .secret()
                .is_encrypted()
        );
        assert!(
            !SecretUnlockBudget::default()
                .unlock(encrypted, "")?
                .secret()
                .is_encrypted()
        );

        // Fake ciphertext cannot reach derivation: reject its hostile S2K
        // before a huge allocation, and report a resource error, not a prompt.
        let mut hostile = key;
        *hostile.secret_mut() = SecretKeyMaterial::Encrypted(Encrypted::new_aead(
            S2K::Argon2 {
                salt: [0; 16],
                t: 1,
                p: 1,
                m: 31,
            },
            SymmetricAlgorithm::AES256,
            AEADAlgorithm::OCB,
            vec![0; 15].into_boxed_slice(),
            vec![0; 32].into_boxed_slice(),
        ));
        let error = SecretUnlockBudget::default()
            .unlock(hostile, "")
            .unwrap_err();
        assert!(!error.is::<PasswordRequired>());
        assert!(error.to_string().contains("resource limits"));

        for (t, p, m) in [(11, 1, 16), (1, 5, 16), (1, 1, 19)] {
            assert!(
                SecretUnlockBudget::default()
                    .charge(&S2K::Argon2 {
                        salt: [0; 16],
                        t,
                        p,
                        m
                    })
                    .is_err()
            );
        }
        let expensive = S2K::Argon2 {
            salt: [0; 16],
            t: 10,
            p: 4,
            m: 18,
        };
        let mut budget = SecretUnlockBudget::default();
        budget.charge(&expensive)?;
        assert!(budget.charge(&expensive).is_err());
        let mut budget = SecretUnlockBudget::default();
        for _ in 0..MAX_SECRET_UNLOCKS {
            budget.charge(&S2K::default())?;
        }
        assert!(budget.charge(&S2K::default()).is_err());
        Ok(())
    }

    #[test]
    fn protected_keys_and_modern_profile() -> Result<()> {
        let (cert, _) = openpgp::cert::CertBuilder::general_purpose(Some("Protected fixture"))
            .set_profile(openpgp::Profile::RFC9580)?
            .set_password(Some("inner test passphrase".into()))
            .generate()?;
        let ciphertext = encrypt("modern protected-key message", std::slice::from_ref(&cert))?;
        assert!(decrypt(&ciphertext, vec![cert.clone()], "wrong").is_err());
        assert_eq!(
            decrypt(&ciphertext, vec![cert.clone()], "inner test passphrase")?
                .text
                .as_str(),
            "modern protected-key message"
        );
        assert!(sign("signed", &cert, "wrong").is_err());
        let signed = sign("signed", &cert, "inner test passphrase")?;
        assert_eq!(verify(&signed, vec![cert])?.text.as_str(), "signed");
        Ok(())
    }

    #[test]
    fn expired_and_revoked_keys_are_not_used_for_new_operations() -> Result<()> {
        use std::time::{Duration, SystemTime};
        let (expired, _) = openpgp::cert::CertBuilder::general_purpose(Some("Expired fixture"))
            .set_creation_time(SystemTime::now() - Duration::from_secs(86400))
            .set_validity_period(Duration::from_secs(60))
            .generate()?;
        assert!(encrypt("message", std::slice::from_ref(&expired)).is_err());
        assert!(sign("message", &expired, "").is_err());
        let (cert, revocation) =
            openpgp::cert::CertBuilder::general_purpose(Some("Revoked fixture")).generate()?;
        let revoked = cert.insert_packets(revocation)?.0;
        assert!(encrypt("message", std::slice::from_ref(&revoked)).is_err());
        assert!(sign("message", &revoked, "").is_err());
        Ok(())
    }

    #[test]
    fn encryption_signatures_and_wrong_keys() -> Result<()> {
        let alice = generate("Alice Test <alice@example.invalid>")?;
        let bob = generate("Bob Test <bob@example.invalid>")?;
        let input = "Private note — UTF-8 supported\n";
        let ciphertext = encrypt(input, &[alice.clone(), bob.clone()])?;
        assert!(!ciphertext.contains("Private note"));
        assert_eq!(
            decrypt(&ciphertext, vec![alice.clone()], "")?.text.as_str(),
            input
        );
        assert_eq!(
            decrypt(&ciphertext, vec![bob.clone()], "")?.text.as_str(),
            input
        );
        let stranger = generate("Stranger")?;
        assert!(decrypt(&ciphertext, vec![stranger], "").is_err());
        let public = Cert::from_bytes(public_armor(&alice)?.as_bytes())?;
        assert!(
            !public.is_tsk(),
            "public export must contain no secret keys"
        );
        assert!(decrypt(&ciphertext, vec![public.clone()], "").is_err());
        let signed = sign(input, &alice, "")?;
        let verified = verify(&signed, vec![public])?;
        assert_eq!(verified.text.as_str(), input);
        assert_eq!(verified.signers, [alice.fingerprint().to_hex()]);
        assert!(verify(&signed, vec![bob]).is_err());
        assert!(verify(input, vec![alice.clone()]).is_err());
        assert!(decrypt(&ciphertext[..ciphertext.len() / 2], vec![alice], "").is_err());
        Ok(())
    }
}
