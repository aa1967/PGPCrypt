//! In-process OpenPGP: never uses GNUPGHOME, an agent, or the network.
use anyhow::{Context, Result, bail, ensure};
use openpgp::{
    Cert, KeyHandle,
    crypto::SessionKey,
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
        [name, email, comment]
            .iter()
            .all(|s| !s.chars().any(char::is_control)),
        "Identity fields cannot contain control characters"
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
    let mut key = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .context("The primary private key is required to create a revocation certificate")?;
    if key.secret().is_encrypted() {
        key = key
            .decrypt_secret(&password.into())
            .context("Could not unlock primary key")?;
    }
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

pub fn protect_private_key(cert: &Cert, old_password: &str, new_password: &str) -> Result<Cert> {
    ensure!(cert.is_tsk(), "Selected key has no private material");
    let mut packets = Vec::new();
    for ka in cert.keys().secret() {
        let primary = ka.key().fingerprint() == cert.fingerprint();
        let mut key = ka.key().clone();
        if key.secret().is_encrypted() {
            key = key
                .decrypt_secret(&old_password.into())
                .context("Could not unlock a secret key packet; check the current passphrase")?;
        }
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

pub fn sign(text: &str, cert: &Cert, password: &str) -> Result<String> {
    bounded(text)?;
    let policy = StandardPolicy::new();
    validate_for_new_operation(cert, &policy)?;
    let key = cert
        .keys()
        .with_policy(&policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_signing()
        .secret()
        .next()
        .context("Selected key has no valid signing secret")?;
    let mut key = key.key().clone();
    if key.secret().is_encrypted() {
        key = key
            .decrypt_secret(&password.into())
            .context("Could not unlock signing key")?;
    }
    let mut output = Vec::new();
    let message = Armorer::new(Message::new(&mut output)).build()?;
    let message = Signer::new(message, key.into_keypair()?)?.build()?;
    let mut literal = LiteralWriter::new(message).build()?;
    literal.write_all(text.as_bytes())?;
    literal.finalize()?;
    Ok(String::from_utf8(output)?)
}

fn bounded(text: &str) -> Result<()> {
    ensure!(
        text.len() <= MAX_TEXT,
        "Text exceeds the 1 MiB prototype limit"
    );
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
}

struct Helper {
    certs: Vec<Cert>,
    password: Zeroizing<String>,
    require_signature: bool,
    signers: Vec<String>,
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
        for cert in &self.certs {
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
                let mut key = ka.key().clone();
                if key.secret().is_encrypted() {
                    key = match key.decrypt_secret(&self.password.as_str().into()) {
                        Ok(key) => key,
                        Err(_) => continue,
                    };
                }
                let mut pair = key.into_keypair()?;
                for pkesk in pkesks {
                    if let Some((algo, session_key)) = pkesk.decrypt(&mut pair, sym_algo)
                        && decrypt(algo, &session_key)
                    {
                        return Ok(Some(cert.clone()));
                    }
                }
            }
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
    bounded(text)?;
    let helper = Helper {
        certs,
        password: Zeroizing::new(password.into()),
        require_signature: false,
        signers: vec![],
    };
    let policy = StandardPolicy::new();
    let mut reader = DecryptorBuilder::from_bytes(text)?.with_policy(&policy, None, helper)?;
    let text = read_authenticated(&mut reader)?;
    let signers = reader.helper_ref().signers.clone();
    Ok(Opened { text, signers })
}

pub fn verify(text: &str, certs: Vec<Cert>) -> Result<Opened> {
    bounded(text)?;
    let helper = Helper {
        certs,
        password: Zeroizing::new(String::new()),
        require_signature: true,
        signers: vec![],
    };
    let policy = StandardPolicy::new();
    let mut reader = VerifierBuilder::from_bytes(text)?.with_policy(&policy, None, helper)?;
    let text = read_authenticated(&mut reader)?;
    let signers = reader.helper_ref().signers.clone();
    Ok(Opened { text, signers })
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
