//! Bounded, private stdin/stdout protocol for the native desktop session.
//! There is no listening socket or credential argument. Private export requires
//! encrypted secret packets and an explicit user action.
use crate::{
    pgp,
    vault::{RevocationTicket, Vault, VaultFormat},
};
use anyhow::{Context, Result, bail, ensure};
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
                    json!({"unlocked":true,"format":self.vault()?.format().name(),"idle_timeout_seconds":self.vault()?.data.idle_timeout_seconds}),
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
                let certs = self.certs()?;
                let keys: Vec<_> = certs.iter().map(|cert| {
                    let status = match cert.with_policy(&policy, None) {
                        Ok(valid) if matches!(valid.revocation_status(), RevocationStatus::Revoked(_)) => "Revoked",
                        Ok(valid) if valid.alive().is_err() => "Expired / not yet valid",
                        Ok(_) => "Valid",
                        Err(_) => "Unsupported / invalid",
                    };
                    json!({"fingerprint":cert.fingerprint().to_hex(),
                        "identities":cert.userids().map(|u|String::from_utf8_lossy(u.userid().value()).into_owned()).collect::<Vec<_>>(),
                        "has_secret":cert.is_tsk(), "status":status,
                        "algorithm":cert.primary_key().key().pk_algo().to_string(),
                        "expires_at":cert.with_policy(&policy,None).ok().and_then(|c| c.primary_key().key_expiration_time()).and_then(|t|t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d|d.as_secs()),
                        "capabilities":cert.keys().with_policy(&policy,None).supported().filter_map(|ka|ka.key_flags()).map(|f|format!("{f:?}")).collect::<Vec<_>>(),
                        "can_encrypt":status == "Valid" && cert.keys().with_policy(&policy,None).supported().alive().revoked(false).any(|ka|ka.key_flags().is_some_and(|flags| flags.for_transport_encryption() || flags.for_storage_encryption())),
                        "can_sign":status == "Valid" && cert.keys().secret().with_policy(&policy,None).supported().alive().revoked(false).for_signing().next().is_some()})
                }).collect();
                Ok(json!({"keys":keys}))
            }
            "generate" => {
                self.vault()?;
                let options = request
                    .key_options
                    .as_ref()
                    .context("Key options and a private-key passphrase are required")?;
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
                let seconds = request
                    .idle_timeout_seconds
                    .context("Choose an idle timeout")?;
                ensure!(
                    (60..=3600).contains(&seconds),
                    "Idle timeout must be between 1 and 60 minutes"
                );
                let vault = self.vault.as_mut().context("Vault is locked")?;
                let old = std::mem::replace(&mut vault.data.idle_timeout_seconds, seconds);
                if let Err(error) = vault.save() {
                    vault.data.idle_timeout_seconds = old;
                    return Err(error);
                }
                Ok(json!({"saved":true,"idle_timeout_seconds":seconds}))
            }
            "encrypt" => {
                let all = self.certs()?;
                ensure!(
                    !request.recipients.is_empty(),
                    "Select recipients in the Keys table"
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
                let cert = self
                    .certs()?
                    .into_iter()
                    .find(|c| c.fingerprint().to_hex() == request.fingerprint)
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
            Err(error) => json!({"id":request.id,"ok":false,"error":format!("{error:#}")}),
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
