//! In-process OpenPGP: never uses GNUPGHOME, an agent, or the network.
use anyhow::{Context, Result, bail, ensure};
use openpgp::{
    Cert, KeyHandle,
    crypto::SessionKey,
    parse::{Parse, stream::*},
    policy::StandardPolicy,
    serialize::{Serialize, stream::*},
    types::SymmetricAlgorithm,
};
use sequoia_openpgp as openpgp;
use std::io::{Read, Write};
use zeroize::Zeroizing;

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
            .for_transport_encryption()
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
                .for_transport_encryption()
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
                    if let Some((algo, session_key)) = pkesk.decrypt(&mut pair, sym_algo) {
                        if decrypt(algo, &session_key) {
                            return Ok(Some(cert.clone()));
                        }
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
