//! Bounded, private stdin/stdout protocol for the native desktop session.
//! There is no listening socket or credential argument. Private export is an
//! explicit UI action, with disclosure of any unprotected secret packets.
use crate::{
    pgp,
    vault::{RevocationTicket, Vault, VaultFormat},
};
use anyhow::{Context, Result, bail, ensure};
use sequoia_openpgp::cert::amalgamation::ValidAmalgamation;
use sequoia_openpgp::{Cert, policy::StandardPolicy, types::RevocationStatus};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    io::{BufRead, Read, Write},
    path::Path,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const MAX_FRAME: usize = 8 * 1024 * 1024;

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: u64,
    pub op: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub new_password: String,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default)]
    pub recipients: Vec<String>,
    #[serde(default)]
    pub key_options: Option<pgp::KeyOptions>,
    #[serde(default)]
    pub idle_timeout_seconds: Option<u32>,
    #[serde(default)]
    pub default_signing_key: Option<String>,
    #[serde(default)]
    pub preferences: Option<crate::vault::Preferences>,
    #[serde(default)]
    pub subkey_options: Option<pgp::SubkeyOptions>,
}

#[derive(Default)]
pub struct Session {
    vault: Option<Vault>,
}

impl Session {
    fn vault(&self) -> Result<&Vault> {
        self.vault.as_ref().context("Vault is locked")
    }

    fn certs(&self) -> Result<Vec<Cert>> {
        self.vault()?
            .data
            .certificates
            .iter()
            .map(|bytes| pgp::parse(bytes))
            .collect()
    }

    fn store(&mut self, cert: Cert) -> Result<()> {
        let vault = self.vault.as_mut().context("Vault is locked")?;
        let mut position = None;
        let mut merged = cert;
        for (i, bytes) in vault.data.certificates.iter().enumerate() {
            let old = pgp::parse(bytes)?;
            if old.fingerprint() == merged.fingerprint() {
                position = Some(i);
                merged = old.merge_public_and_secret(merged)?;
                break;
            }
        }
        let encoded = pgp::encode(&merged)?;
        if let Some(i) = position {
            let old = Zeroizing::new(std::mem::replace(
                &mut vault.data.certificates[i],
                encoded.to_vec(),
            ));
            if let Err(error) = vault.save() {
                vault.data.certificates[i].zeroize();
                vault.data.certificates[i] = old.to_vec();
                return Err(error);
            }
        } else {
            vault.data.certificates.push(encoded.to_vec());
            if let Err(error) = vault.save() {
                if let Some(mut bytes) = vault.data.certificates.pop() {
                    bytes.zeroize();
                }
                return Err(error);
            }
        }
        Ok(())
    }

    pub fn handle(&mut self, request: &Request) -> Result<Value> {
        match request.op.as_str() {
            "status" => Ok(json!({"unlocked": self.vault.is_some()})),
            "create" | "open" => {
                ensure!(self.vault.is_none(), "Lock the current vault first");
                self.vault = Some(if request.op == "create" {
                    Vault::create_format(
                        Path::new(&request.path),
                        &request.password,
                        VaultFormat::parse(&request.format)?,
                    )?
                } else {
                    Vault::open(Path::new(&request.path), &request.password)?
                });
                Ok(
                    json!({"unlocked":true,"format":self.vault()?.format().name(),"idle_timeout_seconds":self.vault()?.data.idle_timeout_seconds,"default_signing_key":self.vault()?.data.default_signing_key,"preferences":self.vault()?.data.preferences}),
                )
            }
            "convert_copy" => {
                self.vault()?.convert_copy(
                    Path::new(&request.path),
                    &request.password,
                    VaultFormat::parse(&request.format)?,
                )?;
                Ok(json!({"saved":true,"source_unchanged":true}))
            }
            "lock" => {
                self.vault = None;
                Ok(json!({"unlocked":false}))
            }
            "list" => {
                let policy = StandardPolicy::new();
                let vault = self.vault()?;
                let certs = self.certs()?;
                let keys: Vec<_> = certs.iter().map(|cert| {
                    let status = match cert.with_policy(&policy, None) {
                        Ok(valid) if matches!(valid.revocation_status(), RevocationStatus::Revoked(_)) => "Revoked",
                        Ok(valid) if valid.alive().is_err() => "Expired / not yet valid",
                        Ok(_) => "Valid",
                        Err(_) => "Unsupported / invalid",
                    };
                    json!({"fingerprint":cert.fingerprint().to_hex(),
                        // Only show identities with a current valid self-binding.
                        // This still does not establish the owner's real identity.
                        "identities":cert.with_policy(&policy,None).ok().map(|valid|valid.userids().revoked(false).map(|u|String::from_utf8_lossy(u.userid().value()).into_owned()).collect::<Vec<_>>()).unwrap_or_default(),
                        "has_secret":cert.is_tsk(), "status":status,
                        "has_revocation":vault.data.revocations.iter().any(|r|r.fingerprint==cert.fingerprint().to_hex()),
                        "secret_protected":cert.is_tsk() && cert.keys().secret().all(|ka|ka.key().secret().is_encrypted()),
                        "secret_any_protected":cert.keys().secret().any(|ka|ka.key().secret().is_encrypted()),
                        "primary_secret_protected":cert.primary_key().key().optional_secret().is_some_and(|s|s.is_encrypted()),
                        "signing_password_required":cert.keys().secret().with_policy(&policy,None).supported().alive().revoked(false).for_signing().all(|ka|ka.key().secret().is_encrypted()),
                        "algorithm":cert.primary_key().key().pk_algo().to_string(),
                        "expires_at":cert.with_policy(&policy,None).ok().and_then(|c| c.primary_key().key_expiration_time()).and_then(|t|t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d|d.as_secs()),
                        "capabilities":cert.keys().with_policy(&policy,None).supported().filter_map(|ka|ka.key_flags()).map(|f|format!("{f:?}")).collect::<Vec<_>>(),
                        "can_encrypt":status == "Valid" && cert.keys().with_policy(&policy,None).supported().alive().revoked(false).any(|ka|ka.key_flags().is_some_and(|flags| flags.for_transport_encryption() || flags.for_storage_encryption())),
                        "can_sign":status == "Valid" && cert.keys().secret().with_policy(&policy,None).supported().alive().revoked(false).for_signing().next().is_some()})
                }).collect();
                Ok(
                    json!({"keys":keys,"default_signing_key":self.vault()?.data.default_signing_key}),
                )
            }
            "generate" => {
                self.vault()?;
                let options = request
                    .key_options
                    .as_ref()
                    .context("Key options are required")?;
                let (cert, armor) = pgp::generate_with_options(options, &request.password)?;
                let fingerprint = cert.fingerprint().to_hex();
                // A generated key and its emergency ticket commit in one snapshot.
                let vault = self.vault.as_mut().context("Vault is locked")?;
                vault.data.certificates.push(pgp::encode(&cert)?.to_vec());
                vault.data.revocations.push(RevocationTicket {
                    fingerprint: fingerprint.clone(),
                    armor,
                });
                if let Err(error) = vault.save() {
                    if let Some(mut bytes) = vault.data.certificates.pop() {
                        bytes.zeroize();
                    }
                    vault.data.revocations.pop();
                    return Err(error);
                }
                Ok(json!({"saved":true,"fingerprint":fingerprint}))
            }
            "import" => {
                self.vault()?;
                self.store(pgp::parse(request.text.as_bytes())?)?;
                Ok(json!({"saved":true}))
            }
            "public_export" => {
                let cert = self
                    .certs()?
                    .into_iter()
                    .find(|c| c.fingerprint().to_hex() == request.fingerprint)
                    .context("Select a key")?;
                Ok(json!({"text":pgp::public_armor(&cert)?}))
            }
            "protected_private_export" => {
                let cert = self
                    .certs()?
                    .into_iter()
                    .find(|c| c.fingerprint().to_hex() == request.fingerprint)
                    .context("Select a private key")?;
                Ok(json!({"text":pgp::protected_private_armor(&cert)?.as_str()}))
            }
            "subkeys" => {
                let cert = self
                    .certs()?
                    .into_iter()
                    .find(|c| c.fingerprint().to_hex() == request.fingerprint)
                    .context("Select a key")?;
                let policy = StandardPolicy::new();
                let keys:Vec<_>=cert.keys().with_policy(&policy,None).map(|ka|json!({
                    "primary":ka.key().fingerprint()==cert.fingerprint(),"fingerprint":ka.key().fingerprint().to_hex(),
                    "algorithm":ka.key().pk_algo().to_string(),"secret":ka.key().has_secret(),
                    "capabilities":format!("{:?}",ka.key_flags()),"expires_at":ka.key_expiration_time().and_then(|t|t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d|d.as_secs()),
                    "status":if matches!(ka.revocation_status(),RevocationStatus::Revoked(_)) {"Revoked"} else if ka.alive().is_err() {"Expired / not yet valid"} else {"Valid"}
                })).collect();
                Ok(json!({"keys":keys}))
            }
            "add_subkey" => {
                let cert = self
                    .certs()?
                    .into_iter()
                    .find(|c| c.fingerprint().to_hex() == request.fingerprint)
                    .context("Select a private key")?;
                let updated = pgp::add_subkey(
                    &cert,
                    request
                        .subkey_options
                        .as_ref()
                        .context("Subkey options required")?,
                    &request.password,
                    &request.new_password,
                )?;
                self.store(updated)?;
                Ok(json!({"saved":true}))
            }
            "private_export" => {
                let cert = self
                    .certs()?
                    .into_iter()
                    .find(|c| c.fingerprint().to_hex() == request.fingerprint)
                    .context("Select a private key")?;
                Ok(
                    json!({"text":pgp::private_armor(&cert)?.as_str(),"protected":cert.keys().secret().all(|ka|ka.key().secret().is_encrypted())}),
                )
            }
            "protect_private_key" => {
                let cert = self
                    .certs()?
                    .into_iter()
                    .find(|c| c.fingerprint().to_hex() == request.fingerprint)
                    .context("Select a private key")?;
                let protected =
                    pgp::protect_private_key(&cert, &request.password, &request.new_password)?;
                let vault = self.vault.as_mut().context("Vault is locked")?;
                let position = vault
                    .data
                    .certificates
                    .iter()
                    .position(|bytes| {
                        pgp::parse(bytes).is_ok_and(|c| c.fingerprint() == protected.fingerprint())
                    })
                    .context("Key is missing")?;
                let old = Zeroizing::new(std::mem::replace(
                    &mut vault.data.certificates[position],
                    pgp::encode(&protected)?.to_vec(),
                ));
                if let Err(error) = vault.save() {
                    vault.data.certificates[position].zeroize();
                    vault.data.certificates[position] = old.to_vec();
                    return Err(error);
                }
                Ok(json!({"saved":true}))
            }
            "revocation_export" => {
                if let Some(ticket) = self
                    .vault()?
                    .data
                    .revocations
                    .iter()
                    .find(|r| r.fingerprint == request.fingerprint)
                {
                    return Ok(json!({"text":ticket.armor}));
                }
                let cert = self
                    .certs()?
                    .into_iter()
                    .find(|c| c.fingerprint().to_hex() == request.fingerprint)
                    .context("Select a private key")?;
                Ok(json!({"text":pgp::revocation_ticket(&cert,&request.password)?}))
            }
            "settings_set" => {
                ensure!(
                    request.idle_timeout_seconds.is_some()
                        || request.default_signing_key.is_some()
                        || request.preferences.is_some(),
                    "Choose a setting to save"
                );
                if let Some(seconds) = request.idle_timeout_seconds {
                    ensure!(
                        (60..=3600).contains(&seconds),
                        "Idle timeout must be between 1 and 60 minutes"
                    );
                }
                if let Some(fp) = request
                    .default_signing_key
                    .as_ref()
                    .filter(|fp| !fp.is_empty())
                {
                    let cert = self
                        .certs()?
                        .into_iter()
                        .find(|c| c.fingerprint().to_hex() == *fp)
                        .context("Choose an available private signing key")?;
                    let policy = StandardPolicy::new();
                    let valid = cert.with_policy(&policy, None)?;
                    valid.alive()?;
                    ensure!(
                        !matches!(valid.revocation_status(), RevocationStatus::Revoked(_))
                            && cert
                                .keys()
                                .secret()
                                .with_policy(&policy, None)
                                .supported()
                                .alive()
                                .revoked(false)
                                .for_signing()
                                .next()
                                .is_some(),
                        "Choose a valid private signing key"
                    );
                }
                if let Some(preferences) = &request.preferences {
                    preferences.validate()?;
                }
                let vault = self.vault.as_mut().context("Vault is locked")?;
                let old_preferences = vault.data.preferences.clone();
                let old_timeout = vault.data.idle_timeout_seconds;
                let old_default = Zeroizing::new(vault.data.default_signing_key.clone());
                if let Some(seconds) = request.idle_timeout_seconds {
                    vault.data.idle_timeout_seconds = seconds;
                }
                if let Some(preferences) = &request.preferences {
                    vault.data.preferences = preferences.clone();
                }
                if let Some(fp) = &request.default_signing_key {
                    vault.data.default_signing_key = fp.clone();
                }
                if let Err(error) = vault.save() {
                    vault.data.preferences = old_preferences;
                    vault.data.idle_timeout_seconds = old_timeout;
                    vault.data.default_signing_key.zeroize();
                    vault.data.default_signing_key = old_default.to_string();
                    return Err(error);
                }
                Ok(
                    json!({"saved":true,"idle_timeout_seconds":vault.data.idle_timeout_seconds,"default_signing_key":vault.data.default_signing_key,"preferences":vault.data.preferences}),
                )
            }
            "encrypt" => {
                let all = self.certs()?;
                ensure!(
                    !request.recipients.is_empty(),
                    "Select recipients on the notepad"
                );
                ensure!(
                    request
                        .recipients
                        .iter()
                        .all(|fp| all.iter().any(|c| c.fingerprint().to_hex() == *fp)),
                    "Unknown recipient selected"
                );
                let selected: Vec<_> = all
                    .into_iter()
                    .filter(|c| request.recipients.contains(&c.fingerprint().to_hex()))
                    .collect();
                Ok(json!({"text":pgp::encrypt(&request.text, &selected)?}))
            }
            "sign" => {
                let fingerprint = if request.fingerprint.is_empty() {
                    &self.vault()?.data.default_signing_key
                } else {
                    &request.fingerprint
                };
                let cert = self
                    .certs()?
                    .into_iter()
                    .find(|c| c.fingerprint().to_hex() == *fingerprint)
                    .context("Choose a signing key")?;
                Ok(json!({"text":pgp::sign(&request.text,&cert,&request.password)?}))
            }
            "decrypt" | "verify" => {
                let opened = if request.op == "decrypt" {
                    pgp::decrypt(&request.text, self.certs()?, &request.password)?
                } else {
                    pgp::verify(&request.text, self.certs()?)?
                };
                Ok(json!({"text":opened.text.as_str(),"signers":opened.signers}))
            }
            "notes_get" => Ok(json!({"text":self.vault()?.data.notes})),
            "notes_set" => {
                ensure!(
                    request.text.len() <= pgp::MAX_TEXT,
                    "Notes exceed the 1 MiB limit"
                );
                let vault = self.vault.as_mut().context("Vault is locked")?;
                let old = Zeroizing::new(std::mem::replace(
                    &mut vault.data.notes,
                    request.text.clone(),
                ));
                if let Err(error) = vault.save() {
                    vault.data.notes.zeroize();
                    vault.data.notes = old.to_string();
                    return Err(error);
                }
                Ok(json!({"saved":true}))
            }
            _ => bail!("Unknown operation"),
        }
    }
}

pub fn run(mut input: impl BufRead, mut output: impl Write) -> Result<()> {
    let mut session = Session::default();
    loop {
        let mut frame = Zeroizing::new(Vec::new());
        let count = Read::by_ref(&mut input)
            .take((MAX_FRAME + 1) as u64)
            .read_until(b'\n', &mut frame)?;
        if count == 0 {
            return Ok(());
        }
        ensure!(
            count <= MAX_FRAME && frame.last() == Some(&b'\n'),
            "Invalid IPC frame"
        );
        let request: Request = serde_json::from_slice(&frame).context("Invalid IPC request")?;
        let result = match session.handle(&request) {
            Ok(data) => json!({"id":request.id,"ok":true,"data":data}),
            Err(error) => {
                let code = if error
                    .chain()
                    .any(|cause| cause.is::<crate::vault::SaveCommitted>())
                {
                    // A rename succeeded, but directory durability could not be
                    // confirmed. Discard any rollback state: only reopening the
                    // file can establish what is on disk.
                    session.vault = None;
                    "vault_reopen_required"
                } else if error
                    .chain()
                    .any(|cause| cause.is::<pgp::PasswordRequired>())
                {
                    "password_required"
                } else {
                    "operation_failed"
                };
                json!({"id":request.id,"ok":false,"error":format!("{error:#}"),"code":code})
            }
        };
        let bytes = Zeroizing::new(serde_json::to_vec(&result)?);
        ensure!(bytes.len() < MAX_FRAME, "IPC response too large");
        output.write_all(&bytes)?;
        output.write_all(b"\n")?;
        output.flush()?;
        if request.op == "lock" {
            return Ok(());
        }
    }
}
