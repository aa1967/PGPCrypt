//! Bounded, private stdin/stdout protocol for the native desktop session.
//! There is no listening socket or credential argument. Private export is an
//! explicit UI action, with disclosure of any unprotected secret packets.
use crate::{
    pgp,
    vault::{Profile, RevocationTicket, Vault, VaultData, VaultFormat, workspace_id},
};
use anyhow::{Context, Result, bail, ensure};
use sequoia_openpgp::cert::amalgamation::ValidAmalgamation;
use sequoia_openpgp::{Cert, policy::StandardPolicy, types::RevocationStatus};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    io::{BufRead, Read, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// A valid 4 MiB document can double when JSON escapes whitespace/quotes.
// Leave room for the envelope without changing the smaller Qubes protocol.
pub const MAX_FRAME: usize = 10 * 1024 * 1024;

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
    pub vault_password: String,
    #[serde(default)]
    pub protection_option: String,
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
    #[serde(default)]
    pub profile_id: String,
    #[serde(default)]
    pub profile_name: String,
    #[serde(default)]
    pub profile_username: Option<String>,
    #[serde(default)]
    pub profile_email: Option<String>,
    #[serde(default)]
    pub profile_url: Option<String>,
    #[serde(default)]
    pub profile_notes: Option<String>,
    #[serde(default)]
    pub profile_fingerprints: Vec<String>,
    #[serde(default)]
    pub document_id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub expiry_count: Option<u32>,
    #[serde(default)]
    pub expiry_unit: String,
}

#[derive(Debug)]
struct VaultAuthRequired;
impl std::fmt::Display for VaultAuthRequired {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("Confirm the vault password/passphrase before exporting unprotected private key packets")
    }
}
impl std::error::Error for VaultAuthRequired {}

/// Verification failure deliberately carries no user-controlled parser text
/// or candidate identities. A failed operation must not imply a trusted match.
#[derive(Debug)]
struct VerificationFailed;
impl std::fmt::Display for VerificationFailed {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("Signature verification failed: the message is invalid, changed, unsupported, or no matching key is available in this profile")
    }
}
impl std::error::Error for VerificationFailed {}

#[derive(Default)]
pub struct Session {
    vault: Option<Vault>,
}

impl Session {
    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

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

    fn certs_for_profile(&self, id: &str) -> Result<Vec<Cert>> {
        let mut certs = self.certs()?;
        if !id.is_empty() {
            let profile = self
                .vault()?
                .data
                .profiles
                .iter()
                .find(|profile| profile.id == id)
                .context("Profile no longer exists")?;
            certs.retain(|cert| profile.fingerprints.contains(&cert.fingerprint().to_hex()));
        }
        Ok(certs)
    }

    fn change_workspace<T>(
        &mut self,
        change: impl FnOnce(&mut VaultData) -> Result<T>,
    ) -> Result<T> {
        let vault = self.vault.as_mut().context("Vault is locked")?;
        let old = vault.data.clone();
        let result = change(&mut vault.data).and_then(|result| vault.save().map(|_| result));
        if result.is_err() {
            vault.data = old;
        }
        result
    }

    fn profile_document_counts(data: &VaultData) -> Value {
        let mut counts = serde_json::Map::new();
        counts.insert(String::new(), json!(0u64));
        for profile in &data.profiles {
            counts.insert(profile.id.clone(), json!(0u64));
        }
        for document in &data.documents {
            let count = counts
                .entry(document.profile_id.clone())
                .or_insert(json!(0u64));
            *count = json!(count.as_u64().unwrap_or(0) + 1);
        }
        Value::Object(counts)
    }

    fn add_profile_member(data: &mut VaultData, id: &str, fingerprint: &str) -> Result<()> {
        if !id.is_empty() {
            let profile = data
                .profiles
                .iter_mut()
                .find(|p| p.id == id)
                .context("Profile no longer exists")?;
            if !profile.fingerprints.iter().any(|fp| fp == fingerprint) {
                profile.fingerprints.push(fingerprint.to_owned());
            }
        }
        Ok(())
    }

    fn store(&mut self, cert: Cert, profile_id: &str) -> Result<()> {
        let vault = self.vault()?;
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
        let fingerprint = merged.fingerprint().to_hex();
        self.change_workspace(|data| {
            Self::add_profile_member(data, profile_id, &fingerprint)?;
            if let Some(i) = position {
                data.certificates[i].zeroize();
                data.certificates[i] = encoded.to_vec();
            } else {
                data.certificates.push(encoded.to_vec());
            }
            Ok(())
        })
    }

    pub fn handle(&mut self, request: &Request) -> Result<Value> {
        if self.vault.as_ref().is_some_and(Vault::is_read_only) {
            ensure!(
                matches!(
                    request.op.as_str(),
                    "status"
                        | "list"
                        | "profiles_list"
                        | "documents_list"
                        | "document_get"
                        | "public_export"
                        | "private_export"
                        | "protected_private_export"
                        | "subkeys"
                        | "encrypt"
                        | "sign"
                        | "decrypt"
                        | "verify"
                        | "notes_get"
                        | "lock"
                ),
                "Vault is read-only"
            );
        }
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
                    let path = crate::vault::resolve(Path::new(&request.path))?;
                    if crate::expiry::check_and_destroy_if_expired(&path, Self::unix_now())? {
                        return Err(crate::duress::DestructionTriggered.into());
                    }
                    if crate::duress::check_and_destroy(&path, &request.password)? {
                        return Err(crate::duress::DestructionTriggered.into());
                    }
                    if crate::duress::dummy_matches(&path, &request.password)? {
                        Vault::open_empty_read_only(&path)?
                    } else {
                        Vault::open(&path, &request.password)?
                    }
                });
                let protection_warning = if request.op == "open"
                    && !self.vault()?.is_read_only()
                    && self.vault()?.record_normal_open(Self::unix_now()).is_err()
                {
                    "Inactivity protection could not be refreshed. Check Vault settings before relying on its deadline."
                } else {
                    ""
                };
                Ok(
                    json!({"unlocked":true,"read_only":self.vault()?.is_read_only(),"protection_warning":protection_warning,"format":self.vault()?.format().name(),"idle_timeout_seconds":self.vault()?.data.idle_timeout_seconds,"default_signing_key":self.vault()?.data.default_signing_key,"preferences":self.vault()?.data.preferences}),
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
            "emergency_status" => match self.vault()?.emergency_status() {
                Ok(status) => Ok(serde_json::to_value(status)?),
                Err(_) => Ok(json!({"configured":true,"armed":false,"unavailable":true})),
            },
            "protection_status" => {
                let options = self.vault()?.protection_options()?;
                Ok(json!({"enabled":self.vault()?.protection_enabled()?,
                    "dummy_enabled":options.dummy,"emergency_enabled":options.emergency,"expiry_enabled":options.expiry}))
            }
            "protection_option_enable" | "protection_option_disable" => {
                let kind = match request.protection_option.as_str() {
                    "dummy" => crate::protection::OptionKind::Dummy,
                    "emergency" => crate::protection::OptionKind::Emergency,
                    "expiry" => crate::protection::OptionKind::Expiry,
                    _ => bail!("Choose a vault protection option"),
                };
                self.vault()?
                    .protection_set_option(kind, request.op == "protection_option_enable")?;
                Ok(json!({"saved":true}))
            }
            "protection_enable" => {
                self.vault()?.protection_enable()?;
                Ok(json!({"enabled":true}))
            }
            "protection_disable" => {
                self.vault()?.protection_disable()?;
                Ok(json!({"enabled":false}))
            }
            "expiry_status" => match self.vault()?.expiry_status() {
                Ok(status) => Ok(serde_json::to_value(status)?),
                Err(_) => Ok(json!({"configured":true,"armed":false,"unavailable":true})),
            },
            "expiry_set" => {
                self.vault()?.expiry_configure(
                    request
                        .expiry_count
                        .context("Choose an inactivity interval")?,
                    &request.expiry_unit,
                    Self::unix_now(),
                )?;
                Ok(json!({"configured":true,"armed":true}))
            }
            "expiry_disable" => {
                self.vault()?.expiry_disable()?;
                Ok(json!({"configured":false,"armed":false}))
            }
            "emergency_set" => {
                self.vault()?.emergency_configure(&request.new_password)?;
                Ok(json!({"configured":true,"armed":true}))
            }
            "emergency_disable" => {
                self.vault()?.emergency_disable()?;
                Ok(json!({"configured":false,"armed":false}))
            }
            "dummy_status" => match self.vault()?.dummy_status() {
                Ok(status) => Ok(serde_json::to_value(status)?),
                Err(_) => Ok(json!({"configured":true,"armed":false,"unavailable":true})),
            },
            "dummy_set" => {
                self.vault()?.dummy_configure(&request.new_password)?;
                Ok(json!({"configured":true,"armed":true}))
            }
            "dummy_disable" => {
                self.vault()?.dummy_disable()?;
                Ok(json!({"configured":false,"armed":false}))
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
                        "created_at":cert.primary_key().key().creation_time().duration_since(UNIX_EPOCH).map(|d|d.as_secs()).unwrap_or(0),
                        "expires_at":cert.with_policy(&policy,None).ok().and_then(|c| c.primary_key().key_expiration_time()).and_then(|t|t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d|d.as_secs()),
                        "capabilities":cert.keys().with_policy(&policy,None).supported().filter_map(|ka|ka.key_flags()).map(|f|format!("{f:?}")).collect::<Vec<_>>(),
                        "can_encrypt":status == "Valid" && cert.keys().with_policy(&policy,None).supported().alive().revoked(false).any(|ka|ka.key_flags().is_some_and(|flags| flags.for_transport_encryption() || flags.for_storage_encryption())),
                        "can_sign":status == "Valid" && cert.keys().secret().with_policy(&policy,None).supported().alive().revoked(false).for_signing().next().is_some()})
                }).collect();
                Ok(
                    json!({"keys":keys,"profiles":vault.data.profiles,"profile_document_counts":Self::profile_document_counts(&vault.data),"default_signing_key":self.vault()?.data.default_signing_key}),
                )
            }
            "profiles_list" => Ok(json!({"profiles":self.vault()?.data.profiles})),
            "profile_save" => {
                let id = if request.profile_id.is_empty() {
                    workspace_id()?
                } else {
                    request.profile_id.clone()
                };
                self.change_workspace(|data| {
                    let previous = data.profiles.iter().find(|profile| profile.id == id);
                    let profile = Profile {
                        id: id.clone(),
                        name: request.profile_name.trim().to_owned(),
                        username: request.profile_username.clone().unwrap_or_else(|| {
                            previous.map(|p| p.username.clone()).unwrap_or_default()
                        }),
                        email: request.profile_email.clone().unwrap_or_else(|| {
                            previous.map(|p| p.email.clone()).unwrap_or_default()
                        }),
                        url: request
                            .profile_url
                            .clone()
                            .unwrap_or_else(|| previous.map(|p| p.url.clone()).unwrap_or_default()),
                        notes: request.profile_notes.clone().unwrap_or_else(|| {
                            previous.map(|p| p.notes.clone()).unwrap_or_default()
                        }),
                        fingerprints: request.profile_fingerprints.clone(),
                    };
                    if request.profile_id.is_empty() {
                        data.profiles.push(profile);
                    } else {
                        let old = data
                            .profiles
                            .iter_mut()
                            .find(|profile| profile.id == id)
                            .context("Profile no longer exists")?;
                        *old = profile;
                    }
                    Ok(())
                })?;
                Ok(json!({"saved":true,"id":id}))
            }
            "profile_delete" => {
                ensure!(!request.profile_id.is_empty(), "All cannot be deleted");
                self.change_workspace(|data| data.remove_profile(&request.profile_id))?;
                Ok(json!({"saved":true}))
            }
            "documents_list" => {
                let data = &self.vault()?.data;
                ensure!(
                    request.profile_id.is_empty()
                        || data
                            .profiles
                            .iter()
                            .any(|profile| profile.id == request.profile_id),
                    "Profile no longer exists"
                );
                let documents=data.documents.iter().filter(|document|request.profile_id.is_empty() || document.profile_id==request.profile_id).map(|document|json!({"id":document.id,"title":document.title,"profile_id":document.profile_id,"created_at":document.created_at,"updated_at":document.updated_at})).collect::<Vec<_>>();
                Ok(
                    json!({"documents":documents,"profile_document_counts":Self::profile_document_counts(data)}),
                )
            }
            "document_get" => {
                let document = self
                    .vault()?
                    .data
                    .documents
                    .iter()
                    .find(|document| {
                        document.id == request.document_id
                            && (request.profile_id.is_empty()
                                || document.profile_id == request.profile_id)
                    })
                    .context("Document is not in this profile")?;
                Ok(
                    json!({"id":document.id,"title":document.title,"text":document.text,"profile_id":document.profile_id,"created_at":document.created_at,"updated_at":document.updated_at}),
                )
            }
            "document_save" | "document_properties" => {
                ensure!(
                    request.op != "document_properties" || !request.document_id.is_empty(),
                    "Choose a saved document"
                );
                let now = Self::unix_now();
                let document = self.change_workspace(|data| {
                    data.save_document(
                        &request.document_id,
                        &request.title,
                        &request.profile_id,
                        (request.op == "document_save").then_some(request.text.as_str()),
                        now,
                    )
                })?;
                Ok(
                    json!({"saved":true,"id":document.id,"title":document.title,"profile_id":document.profile_id,
                    "created_at":document.created_at,"updated_at":document.updated_at}),
                )
            }
            "document_delete" => {
                self.change_workspace(|data| {
                    let index = data
                        .documents
                        .iter()
                        .position(|document| {
                            document.id == request.document_id
                                && (request.profile_id.is_empty()
                                    || document.profile_id == request.profile_id)
                        })
                        .context("Document is not in this profile")?;
                    data.documents.remove(index);
                    Ok(())
                })?;
                Ok(json!({"saved":true}))
            }
            "generate" => {
                self.vault()?;
                let options = request
                    .key_options
                    .as_ref()
                    .context("Key options are required")?;
                let (cert, armor) = pgp::generate_with_options(options, &request.password)?;
                let fingerprint = cert.fingerprint().to_hex();
                // Key, recovery ticket and selected-profile membership commit together.
                let encoded = pgp::encode(&cert)?;
                self.change_workspace(|data| {
                    Self::add_profile_member(data, &request.profile_id, &fingerprint)?;
                    data.certificates.push(encoded.to_vec());
                    data.revocations.push(RevocationTicket {
                        fingerprint: fingerprint.clone(),
                        armor,
                    });
                    Ok(())
                })?;
                Ok(json!({"saved":true,"fingerprint":fingerprint}))
            }
            "import" => {
                self.vault()?;
                self.store(pgp::parse(request.text.as_bytes())?, &request.profile_id)?;
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
                self.store(updated, "")?;
                Ok(json!({"saved":true}))
            }
            "private_export" | "protected_private_export" => {
                let cert = self
                    .certs()?
                    .into_iter()
                    .find(|c| c.fingerprint().to_hex() == request.fingerprint)
                    .context("Select a private key")?;
                ensure!(cert.is_tsk(), "This certificate has no private key packets");
                let protected = cert
                    .keys()
                    .secret()
                    .all(|ka| ka.key().secret().is_encrypted());
                if request.op == "protected_private_export" {
                    ensure!(
                        protected,
                        "Some private key packets are unprotected; use explicit private export"
                    );
                }
                if !protected && !self.vault()?.authenticate_password(&request.vault_password) {
                    return Err(VaultAuthRequired.into());
                }
                Ok(
                    json!({"text":pgp::authenticated_private_armor(&cert,&request.password)?.as_str(),"protected":protected}),
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
                let all = self.certs_for_profile(&request.profile_id)?;
                ensure!(
                    !request.recipients.is_empty(),
                    "Select recipients on the notepad"
                );
                ensure!(
                    request
                        .recipients
                        .iter()
                        .all(|fp| all.iter().any(|c| c.fingerprint().to_hex() == *fp)),
                    "Recipient is not in this profile"
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
                    .certs_for_profile(&request.profile_id)?
                    .into_iter()
                    .find(|c| c.fingerprint().to_hex() == *fingerprint)
                    .context("Choose a signing key")?;
                Ok(json!({"text":pgp::sign(&request.text,&cert,&request.password)?}))
            }
            "decrypt" | "verify" => {
                let certs = self.certs_for_profile(&request.profile_id)?;
                let opened = if request.op == "decrypt" {
                    pgp::decrypt(&request.text, certs.clone(), &request.password)?
                } else {
                    pgp::verify(&request.text, certs.clone()).map_err(|_| VerificationFailed)?
                };
                let policy = StandardPolicy::new();
                let signer_details=opened.signers.iter().map(|fingerprint| {
                    let identities=certs.iter().find(|cert|cert.fingerprint().to_hex()==*fingerprint).and_then(|cert|cert.with_policy(&policy,None).ok()).map(|valid|valid.userids().revoked(false).map(|userid|String::from_utf8_lossy(userid.userid().value()).into_owned()).collect::<Vec<_>>()).unwrap_or_default();
                    json!({"fingerprint":fingerprint,"key_id":fingerprint.get(fingerprint.len().saturating_sub(16)..).unwrap_or(fingerprint),"identities":identities})
                }).collect::<Vec<_>>();
                Ok(
                    json!({"text":opened.text.as_str(),"signers":opened.signers,"signer_details":signer_details}),
                )
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
        let mut stop_after_reply = false;
        let result = match session.handle(&request) {
            Ok(data) => json!({"id":request.id,"ok":true,"data":data}),
            Err(error) => {
                stop_after_reply = error
                    .chain()
                    .any(|cause| cause.is::<crate::duress::DestructionTriggered>());
                if stop_after_reply {
                    session.vault = None;
                }
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
                } else if error.chain().any(|cause| cause.is::<VerificationFailed>()) {
                    "verification_failed"
                } else if error.chain().any(|cause| cause.is::<VaultAuthRequired>()) {
                    "vault_auth_required"
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
        if request.op == "lock" || stop_after_reply {
            return Ok(());
        }
    }
}
