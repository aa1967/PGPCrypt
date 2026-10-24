//! Portable KDBX 4.1 persistence through keepass-rs, with a bounded profile.
//! Header inspection here only enforces resource/feature limits; the library
//! performs all encryption, key derivation and authentication.
use crate::{
    pgp,
    vault::{Document, MAX_SIZE, Profile, RevocationTicket, VaultData},
};
use anyhow::{Context, Result, bail, ensure};
use keepass::{
    Database, DatabaseKey,
    config::{CompressionConfig, DatabaseVersion, KdfConfig},
    db::{CustomDataItem, CustomDataValue, Entry, Group, GroupId},
};
use quick_xml::{Reader, events::Event};
use std::{
    collections::{HashMap, HashSet},
    io::Write,
};
use zeroize::Zeroizing;

pub const MAGIC: &[u8] = &[0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5];
const MARKER: &str = "PGPCrypt.Type";
const SCHEMA: &str = "PGPCrypt.Schema";
const GROUP: &str = "PGPCrypt";
const PROFILE_ID: &str = "PGPCrypt.ProfileId";

fn number(bytes: &[u8]) -> Result<u64> {
    match bytes.len() {
        4 => Ok(u32::from_le_bytes(bytes.try_into()?) as u64),
        8 => Ok(u64::from_le_bytes(bytes.try_into()?)),
        _ => bail!("Invalid KDBX integer width"),
    }
}
fn take<'a>(input: &mut &'a [u8], count: usize) -> Result<&'a [u8]> {
    ensure!(count <= input.len(), "Truncated KDBX header");
    let (value, rest) = input.split_at(count);
    *input = rest;
    Ok(value)
}

pub fn preflight(bytes: &[u8]) -> Result<()> {
    ensure!(bytes.starts_with(MAGIC), "Not a KDBX vault");
    let mut input = bytes.get(8..).context("Truncated KDBX")?;
    ensure!(
        matches!(take(&mut input, 4)?, [0 | 1, 0, 4, 0]),
        "Only KDBX 4.0 and 4.1 are supported"
    );
    let mut fields = HashMap::new();
    loop {
        ensure!(bytes.len() - input.len() < 65536, "Oversized KDBX header");
        let id = take(&mut input, 1)?[0];
        let size = number(take(&mut input, 4)?)? as usize;
        ensure!(size <= 4096, "Oversized KDBX header field");
        let value = take(&mut input, size)?;
        ensure!(
            fields.insert(id, value).is_none(),
            "Duplicate KDBX header field"
        );
        if id == 0 {
            break;
        }
        ensure!(
            matches!(id, 2 | 3 | 4 | 7 | 11),
            "Unsupported KDBX header field (comments/public custom data are not supported)"
        );
    }
    ensure!(
        fields.get(&3) == Some(&&[0, 0, 0, 0][..]),
        "Compressed KDBX is not supported: disable database compression in KeePassXC before opening"
    );
    ensure!(
        fields.get(&2)
            == Some(
                &&[
                    0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a,
                    0xfc, 0x5a, 0xff
                ][..]
            ),
        "Only AES-256 KDBX is supported"
    );
    // Require a complete, uniquely terminated block stream; keepass-rs stops at
    // its first end block. Authentication of every block still belongs to it.
    let mut blocks = input;
    take(&mut blocks, 64)?; // header SHA-256 and HMAC
    loop {
        take(&mut blocks, 32)?;
        let length = number(take(&mut blocks, 4)?)? as usize;
        take(&mut blocks, length)?;
        if length == 0 {
            ensure!(blocks.is_empty(), "Trailing KDBX ciphertext");
            break;
        }
    }
    let mut dictionary = *fields.get(&11).context("Missing KDBX KDF")?;
    ensure!(
        take(&mut dictionary, 2)? == [0, 1],
        "Unsupported KDBX KDF dictionary"
    );
    let mut kdf = HashMap::new();
    loop {
        let kind = take(&mut dictionary, 1)?[0];
        if kind == 0 {
            ensure!(dictionary.is_empty(), "Trailing KDF data");
            break;
        }
        let length = number(take(&mut dictionary, 4)?)? as usize;
        let key = take(&mut dictionary, length)?;
        let length = number(take(&mut dictionary, 4)?)? as usize;
        let value = take(&mut dictionary, length)?;
        ensure!(
            kdf.insert(key, (kind, value)).is_none(),
            "Duplicate KDF field"
        );
    }
    ensure!(kdf.len() == 6, "Unsupported KDBX KDF fields");
    ensure!(
        kdf.get(&b"$UUID"[..])
            == Some(&(
                0x42,
                &[
                    0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6,
                    0xf0, 0xa1, 0xe6
                ][..]
            )),
        "Only Argon2id KDBX is supported"
    );
    for (key, kind, width, low, high) in [
        (b"M", 5, 8, 64 * 1024 * 1024, 256 * 1024 * 1024),
        (b"I", 5, 8, 1, 10),
        (b"P", 4, 4, 1, 4),
        (b"V", 4, 4, 0x13, 0x13),
    ] {
        let (actual, value) = kdf.get(&key[..]).context("Missing Argon2id parameter")?;
        ensure!(
            *actual == kind && value.len() == width,
            "Invalid Argon2id parameter type"
        );
        ensure!(
            (low..=high).contains(&number(value)?),
            "Argon2id parameters outside supported resource limits"
        );
    }
    let (kind, salt) = kdf.get(&b"S"[..]).context("Missing Argon2id salt")?;
    ensure!(
        *kind == 0x42 && salt.len() == 32,
        "Unsupported Argon2id salt"
    );
    Ok(())
}

// Reject unknown XML constructs rather than silently dropping plugin/future
// fields on save. Attachments are intentionally unsupported in this first profile.
fn validate_xml(xml: &[u8]) -> Result<()> {
    ensure!(xml.len() <= MAX_SIZE, "KDBX XML exceeds 16 MiB");
    let mut reader = Reader::from_reader(xml);
    let mut stack: Vec<String> = Vec::new();
    loop {
        let event = reader.read_event()?;
        let is_start = matches!(&event, Event::Start(_));
        match event {
            Event::Start(ref tag) | Event::Empty(ref tag) => {
                let parent = stack.last().map(|s| s.as_str()).unwrap_or("");
                let child = tag.name();
                let allowed = match parent {
                    "" => "KeePassFile",
                    "KeePassFile" => "Meta Root",
                    "Root" => "Group DeletedObjects",
                    "Meta" => {
                        "Generator DatabaseName DatabaseNameChanged DatabaseDescription DatabaseDescriptionChanged DefaultUserName DefaultUserNameChanged MaintenanceHistoryDays Color MasterKeyChanged MasterKeyChangeRec MasterKeyChangeForce MemoryProtection RecycleBinEnabled RecycleBinUUID RecycleBinChanged EntryTemplatesGroup EntryTemplatesGroupChanged LastSelectedGroup LastTopVisibleGroup HistoryMaxItems HistoryMaxSize SettingsChanged CustomData CustomIcons Binaries"
                    }
                    "MemoryProtection" => {
                        "ProtectTitle ProtectUserName ProtectPassword ProtectURL ProtectNotes"
                    }
                    "Group" => {
                        "UUID Name Notes Tags IconID Times IsExpanded DefaultAutoTypeSequence EnableAutoType EnableSearching LastTopVisibleEntry CustomData PreviousParentGroup Group Entry"
                    }
                    "Entry" => {
                        "UUID IconID ForegroundColor BackgroundColor OverrideURL Tags Times String AutoType History CustomData QualityCheck PreviousParentGroup"
                    }
                    "Times" => {
                        "CreationTime LastModificationTime LastAccessTime ExpiryTime Expires UsageCount LocationChanged"
                    }
                    "String" => "Key Value",
                    "History" => "Entry",
                    "AutoType" => "Enabled DataTransferObfuscation DefaultSequence Association",
                    "Association" => "Window KeystrokeSequence",
                    "CustomData" => "Item",
                    "Item" => "Key Value LastModificationTime",
                    "DeletedObjects" => "DeletedObject",
                    "DeletedObject" => "UUID DeletionTime",
                    _ => "",
                };
                ensure!(
                    allowed
                        .split(' ')
                        .any(|name| !name.is_empty() && name == child.as_ref()),
                    "Unsupported KDBX XML field; open this file in KeePassXC to recover its contents"
                );
                for attr in tag.attributes() {
                    let attr = attr?;
                    ensure!(
                        parent == "String"
                            && child.as_ref() == "Value"
                            && attr.key.as_ref() == "Protected"
                            && matches!(attr.value.as_ref(), "True" | "False"),
                        "Unsupported KDBX XML attribute"
                    );
                }
                if is_start {
                    stack.push(child.as_ref().to_owned());
                }
                ensure!(stack.len() <= 32, "KDBX XML nesting exceeds limit");
            }
            Event::End(_) => {
                stack.pop().context("Invalid XML nesting")?;
            }
            Event::Eof => break,
            Event::DocType(_) | Event::PI(_) => bail!("Unsupported KDBX XML declaration"),
            _ => {}
        }
    }
    ensure!(stack.is_empty(), "Invalid XML nesting");
    Ok(())
}

pub fn open(bytes: &[u8], password: &str) -> Result<(VaultData, Database)> {
    preflight(bytes)?;
    let xml = Zeroizing::new(
        Database::get_xml(&mut &bytes[..], DatabaseKey::new().with_password(password))
            .context("Could not authenticate KDBX (password-only unlock supported)")?,
    );
    validate_xml(&xml)?;
    let db = Database::parse(bytes, DatabaseKey::new().with_password(password))?;
    ensure!(
        db.num_attachments() == 0 && db.num_custom_icons() == 0,
        "KDBX attachments/icons are not supported"
    );
    let root = db.root();
    ensure!(
        root.groups().filter(|g| g.name == GROUP).count() == 1,
        "Expected exactly one PGPCrypt group"
    );
    let group = root
        .groups()
        .find(|g| g.name == GROUP)
        .context("No PGPCrypt group in this KDBX; use KeePassXC to copy keys manually")?;
    let settings_ids = group
        .entries()
        .filter(|entry| entry.get(MARKER) == Some("settings"))
        .map(|entry| entry.id())
        .collect::<Vec<_>>();
    ensure!(
        settings_ids.len() == 1,
        "Missing or duplicate PGPCrypt settings"
    );
    let settings = db
        .entry(settings_ids[0])
        .context("Missing settings entry")?;
    let schema = settings
        .get(SCHEMA)
        .context("Missing settings schema")?
        .parse::<u32>()?;
    ensure!(
        (1..=8).contains(&schema),
        "Unsupported PGPCrypt KDBX settings schema"
    );
    let mut data = VaultData::default();
    data.default_signing_key = settings
        .get("PGPCrypt.DefaultSigningKey")
        .unwrap_or_default()
        .to_owned();
    data.preferences = settings
        .get("PGPCrypt.Preferences")
        .map(serde_json::from_str)
        .transpose()?
        .unwrap_or_default();
    data.preferences.validate()?;
    data.profiles = settings
        .get("PGPCrypt.Profiles")
        .map(serde_json::from_str)
        .transpose()?
        .unwrap_or_default();
    data.notes = settings.get("Notes").unwrap_or_default().to_owned();
    data.idle_timeout_seconds = settings
        .get("PGPCrypt.IdleTimeoutSeconds")
        .context("Missing timeout")?
        .parse()?;

    let mut routes = group
        .entries()
        .map(|entry| (entry.id(), None))
        .collect::<Vec<_>>();
    let mut group_names = HashMap::new();
    if schema >= 6 {
        for child in group.groups() {
            let id = identity_group_id(&child)?.to_owned();
            ensure!(
                data.profiles.iter().any(|profile| profile.id == id),
                "Identity group refers to a missing profile"
            );
            ensure!(
                group_names.insert(id.clone(), child.name.clone()).is_none(),
                "Duplicate identity group"
            );
            ensure!(
                child.groups().next().is_none(),
                "Nested identity groups are not supported"
            );
            routes.extend(child.entries().map(|entry| (entry.id(), Some(id.clone()))));
        }
        ensure!(
            group_names.len() == data.profiles.len(),
            "Missing identity groups"
        );
    } else {
        ensure!(
            group.groups().next().is_none(),
            "Identity groups require KDBX settings schema 6; move unrelated groups outside PGPCrypt"
        );
    }
    let mut fingerprints = HashSet::new();
    let mut key_entry_ids = HashMap::new();
    let mut reference_targets = Vec::new();
    let mut identities = HashMap::new();
    let mut memberships: HashMap<String, Vec<String>> = data
        .profiles
        .iter()
        .map(|profile| (profile.id.clone(), Vec::new()))
        .collect();
    for (entry_id, location) in routes {
        let entry = db.entry(entry_id).context("Missing managed entry")?;
        if entry.get(MARKER) == Some("settings") {
            ensure!(
                location.is_none() && entry_id == settings_ids[0],
                "Unexpected settings entry"
            );
            continue;
        }
        ensure!(
            entry.get(SCHEMA) == Some("1"),
            "Unsupported PGPCrypt KDBX entry schema"
        );
        match entry.get(MARKER) {
            Some("identity") => {
                let id = entry
                    .get(PROFILE_ID)
                    .context("Missing identity ID")?
                    .to_owned();
                ensure!(
                    (schema >= 6 && location.as_deref() == Some(id.as_str()))
                        || (schema == 5 && location.is_none()),
                    "Identity entry is outside its group"
                );
                let identity = Profile {
                    id: id.clone(),
                    name: if schema >= 6 {
                        group_names
                            .get(&id)
                            .context("Missing identity group")?
                            .clone()
                    } else {
                        entry
                            .get("Title")
                            .context("Missing identity title")?
                            .to_owned()
                    },
                    username: entry.get("UserName").unwrap_or_default().to_owned(),
                    email: entry.get("Email").unwrap_or_default().to_owned(),
                    url: entry.get("URL").unwrap_or_default().to_owned(),
                    notes: entry.get("Notes").unwrap_or_default().to_owned(),
                    fingerprints: Vec::new(),
                };
                ensure!(
                    identities.insert(id, identity).is_none(),
                    "Duplicate identity entry"
                );
            }
            Some("key_reference") => {
                ensure!(schema >= 6, "Key references require KDBX settings schema 6");
                let id = location
                    .as_ref()
                    .context("Key reference is outside an identity group")?;
                ensure!(
                    [
                        "OpenPGP.PublicKey",
                        "OpenPGP.PrivateKey",
                        "OpenPGP.Revocation"
                    ]
                    .iter()
                    .all(|field| entry.get(field).is_none()),
                    "Key references must not duplicate armored key material"
                );
                let fingerprint = entry
                    .get("OpenPGP.Fingerprint")
                    .context("Missing key reference fingerprint")?
                    .to_owned();
                let members = memberships
                    .get_mut(id)
                    .context("Key reference belongs to a missing profile")?;
                ensure!(
                    !members.contains(&fingerprint),
                    "Duplicate key reference in an identity group"
                );
                reference_targets.push((
                    fingerprint.clone(),
                    entry
                        .get("PGPCrypt.KeyEntry")
                        .context("Missing canonical key reference")?
                        .to_owned(),
                ));
                members.push(fingerprint);
            }
            Some("document") => {
                data.documents.push(Document {
                    id: entry
                        .get("PGPCrypt.DocumentId")
                        .context("Missing document ID")?
                        .to_owned(),
                    title: entry
                        .get("Title")
                        .context("Missing document title")?
                        .to_owned(),
                    text: entry
                        .get("Notes")
                        .context("Missing saved document text")?
                        .to_owned(),
                    // In schema 6, moving an entry in KeePassXC changes its
                    // identity. Its old custom field may legitimately be stale.
                    profile_id: if schema >= 6 {
                        location.clone().unwrap_or_default()
                    } else {
                        entry.get(PROFILE_ID).unwrap_or_default().to_owned()
                    },
                    created_at: entry
                        .get("PGPCrypt.CreatedAt")
                        .context("Missing document creation time")?
                        .parse()?,
                    updated_at: entry
                        .get("PGPCrypt.UpdatedAt")
                        .context("Missing document update time")?
                        .parse()?,
                });
            }
            Some("key") => {
                ensure!(
                    location.is_none(),
                    "Canonical keys must remain in the PGPCrypt root group"
                );
                let public = pgp::parse(
                    entry
                        .get("OpenPGP.PublicKey")
                        .context("Missing public key")?
                        .as_bytes(),
                )?;
                ensure!(
                    !public.is_tsk(),
                    "KDBX public-key field contains private material"
                );
                let private = entry.get("OpenPGP.PrivateKey").unwrap_or_default();
                let cert = if private.is_empty() {
                    public.clone()
                } else {
                    let private = pgp::parse(private.as_bytes())?;
                    ensure!(
                        private.is_tsk(),
                        "KDBX private-key field has no private material"
                    );
                    ensure!(
                        private.fingerprint() == public.fingerprint(),
                        "KDBX public/private key mismatch"
                    );
                    private.merge_public(public.clone())?
                };
                let fingerprint = cert.fingerprint().to_hex();
                ensure!(
                    entry.get("OpenPGP.Fingerprint") == Some(fingerprint.as_str())
                        && fingerprints.insert(fingerprint.clone()),
                    "Duplicate or mismatched KDBX key fingerprint"
                );
                key_entry_ids.insert(fingerprint.clone(), entry_id.uuid().to_string());
                data.certificates.push(pgp::encode(&cert)?.to_vec());
                if let Some(armor) = entry.get("OpenPGP.Revocation").filter(|s| !s.is_empty()) {
                    data.revocations.push(RevocationTicket {
                        fingerprint,
                        armor: armor.into(),
                    });
                }
            }
            _ => bail!(
                "Unknown entry in PGPCrypt group; move unrelated entries to another group in KeePassXC"
            ),
        }
    }
    for (fingerprint, target) in reference_targets {
        ensure!(
            key_entry_ids.get(&fingerprint) == Some(&target),
            "Key reference does not match its canonical key"
        );
    }
    ensure!(
        (60..=3600).contains(&data.idle_timeout_seconds),
        "Invalid PGPCrypt timeout"
    );
    if schema >= 5 {
        ensure!(
            identities.len() == data.profiles.len(),
            "Missing or unexpected identity entries"
        );
        for profile in &mut data.profiles {
            let identity = identities
                .remove(&profile.id)
                .context("Missing identity entry")?;
            profile.name = identity.name.clone();
            profile.username = identity.username.clone();
            profile.email = identity.email.clone();
            profile.url = identity.url.clone();
            profile.notes = identity.notes.clone();
            if schema >= 6 {
                profile.fingerprints = memberships
                    .remove(&profile.id)
                    .context("Missing identity memberships")?;
            }
        }
    } else {
        ensure!(
            identities.is_empty(),
            "Identity entries require PGPCrypt settings schema 5 or 6"
        );
    }
    data.validate()?;
    Ok((data, db))
}

fn identity_group_id(group: &Group) -> Result<&str> {
    let field = |name: &str| {
        group
            .custom_data
            .get(name)
            .and_then(|item| item.value.as_ref())
    };
    ensure!(
        matches!(field(MARKER),Some(CustomDataValue::String(value)) if value=="identity_group")
            && matches!(field(SCHEMA),Some(CustomDataValue::String(value)) if value=="1"),
        "Unknown group inside PGPCrypt; move unrelated groups outside PGPCrypt"
    );
    match field(PROFILE_ID) {
        Some(CustomDataValue::String(id)) => id
            .strip_prefix("profile:")
            .context("Missing or unsupported identity group ID"),
        _ => bail!("Missing identity group ID"),
    }
}

fn mark_identity_group(group: &mut Group, id: &str) {
    // keepass-rs infers any Base64-decodable custom-data text as Binary.
    // Bare 32-character hexadecimal IDs therefore change type when reopened.
    // An explicit non-Base64 prefix preserves the standard XML text value in
    // this library and KeePassXC without adding another metadata copy.
    for (name, value) in [
        (MARKER, "identity_group".to_owned()),
        (SCHEMA, "1".to_owned()),
        (PROFILE_ID, format!("profile:{id}")),
    ] {
        group.custom_data.insert(
            name.to_owned(),
            CustomDataItem {
                value: Some(CustomDataValue::String(value)),
                ..CustomDataItem::default()
            },
        );
    }
}

fn group(db: &mut Database) -> GroupId {
    let existing = db.root().groups().find(|g| g.name == GROUP).map(|g| g.id());
    existing.unwrap_or_else(|| {
        let mut root = db.root_mut();
        let mut group = root.add_group();
        group.name = GROUP.into();
        group.id()
    })
}
fn set_key(entry: &mut Entry, bytes: &[u8], data: &VaultData) -> Result<()> {
    let cert = pgp::parse(bytes)?;
    let fingerprint = cert.fingerprint().to_hex();
    entry.set_unprotected(
        "Title",
        cert.with_policy(&sequoia_openpgp::policy::StandardPolicy::new(), None)
            .ok()
            .and_then(|valid| valid.userids().revoked(false).next())
            .map(|u| {
                String::from_utf8_lossy(u.userid().value())
                    .chars()
                    .map(|c| {
                        // User IDs are OpenPGP data, not necessarily XML text. Keep
                        // exact bytes in armor, while making the display title safe.
                        if c.is_control() || matches!(c, '\u{fffe}' | '\u{ffff}') {
                            '\u{fffd}'
                        } else {
                            c
                        }
                    })
                    .collect::<String>()
            })
            .unwrap_or_else(|| fingerprint.clone()),
    );
    entry.set_unprotected(MARKER, "key");
    entry.set_unprotected(SCHEMA, "1");
    entry.set_unprotected("OpenPGP.Fingerprint", &fingerprint);
    // KeePassXC shows standard Notes immediately. Keep user-edited notes on
    // existing entries, and put the portable armor in protected custom fields.
    if entry.get("Notes").is_none() {
        entry.set_unprotected(
            "Notes",
            "Open the Advanced tab to reveal and copy OpenPGP.PublicKey, OpenPGP.PrivateKey or OpenPGP.Revocation into another OpenPGP application. A private-key password, if set, is separate from the database password. Keep private keys and revocation certificates confidential.",
        );
    }
    entry.set_protected("OpenPGP.PublicKey", pgp::public_armor(&cert)?);
    // Unprotected private packets remain protected by the KDBX container and
    // protected custom field. A separate packet password is optional.
    let private = if cert.is_tsk() {
        use sequoia_openpgp::serialize::Serialize;
        let mut b = Vec::new();
        cert.as_tsk().armored().serialize(&mut b)?;
        Zeroizing::new(String::from_utf8(b)?)
    } else {
        Zeroizing::new(String::new())
    };
    entry.set_protected("OpenPGP.PrivateKey", private.as_str());
    entry.set_protected(
        "OpenPGP.Revocation",
        data.revocations
            .iter()
            .find(|r| r.fingerprint == fingerprint)
            .map(|r| r.armor.as_str())
            .unwrap_or_default(),
    );
    Ok(())
}
pub fn write(
    data: &VaultData,
    original: Option<&Database>,
    password: &str,
    writer: &mut dyn Write,
) -> Result<()> {
    data.validate()?;
    for ticket in &data.revocations {
        ensure!(
            data.certificates.iter().any(|bytes| pgp::parse(bytes)
                .is_ok_and(|c| c.fingerprint().to_hex() == ticket.fingerprint)),
            "Revocation ticket without a matching key cannot be converted to KDBX"
        );
    }
    let mut db = original.cloned().unwrap_or_else(Database::new);
    db.config.version = DatabaseVersion::KDB4(1);
    db.config.compression_config = CompressionConfig::None;
    if original.is_none() {
        db.config.kdf_config = KdfConfig::Argon2id {
            iterations: 3,
            memory: 64 * 1024 * 1024,
            parallelism: 1,
            version: argon2::Version::Version13,
        };
    }
    let group_id = group(&mut db);
    let mut group_ids = HashMap::new();
    let mut locations = vec![(group_id, None)];
    {
        let managed = db.group(group_id).context("Missing PGPCrypt group")?;
        for child in managed.groups() {
            let id = identity_group_id(&child)?.to_owned();
            ensure!(
                child.groups().next().is_none(),
                "Nested identity groups are not supported"
            );
            ensure!(
                group_ids.insert(id.clone(), child.id()).is_none(),
                "Duplicate identity group"
            );
            locations.push((child.id(), Some(id)));
        }
    }
    let mut keys = HashMap::new();
    let mut identities = HashMap::new();
    let mut documents = HashMap::new();
    let mut references = HashMap::new();
    let mut settings_id = None;
    for (location, profile_id) in locations {
        let source = db.group(location).context("Missing managed group")?;
        for entry in source.entries() {
            let id = entry.id();
            match entry.get(MARKER) {
                Some("settings") => {
                    ensure!(
                        profile_id.is_none() && settings_id.replace(id).is_none(),
                        "Duplicate or misplaced settings entry"
                    );
                }
                Some("key") => {
                    ensure!(
                        profile_id.is_none(),
                        "Canonical key is outside the PGPCrypt root"
                    );
                    let fp = entry
                        .get("OpenPGP.Fingerprint")
                        .context("Missing key fingerprint")?
                        .to_owned();
                    ensure!(keys.insert(fp, id).is_none(), "Duplicate key entry");
                }
                Some("identity") => {
                    let profile = entry
                        .get(PROFILE_ID)
                        .context("Missing identity ID")?
                        .to_owned();
                    ensure!(
                        profile_id
                            .as_deref()
                            .is_none_or(|location| location == profile),
                        "Misplaced identity entry"
                    );
                    ensure!(
                        identities.insert(profile, id).is_none(),
                        "Duplicate identity entry"
                    );
                }
                Some("document") => {
                    ensure!(
                        documents
                            .insert(
                                entry
                                    .get("PGPCrypt.DocumentId")
                                    .context("Missing document ID")?
                                    .to_owned(),
                                id
                            )
                            .is_none(),
                        "Duplicate document entry"
                    );
                }
                Some("key_reference") => {
                    let profile = profile_id
                        .as_ref()
                        .context("Key reference is outside an identity group")?
                        .clone();
                    let fp = entry
                        .get("OpenPGP.Fingerprint")
                        .context("Missing key reference fingerprint")?
                        .to_owned();
                    ensure!(
                        references.insert((profile, fp), id).is_none(),
                        "Duplicate key reference"
                    );
                }
                _ => bail!(
                    "Unknown entry in PGPCrypt group; move unrelated entries to another group in KeePassXC"
                ),
            }
        }
    }
    let fingerprints = data
        .certificates
        .iter()
        .map(|bytes| pgp::parse(bytes).map(|cert| cert.fingerprint().to_hex()))
        .collect::<Result<HashSet<_>>>()?;
    let mut stale = Vec::new();
    stale.extend(
        keys.iter()
            .filter(|(fp, _)| !fingerprints.contains(*fp))
            .map(|(_, id)| *id),
    );
    stale.extend(
        identities
            .iter()
            .filter(|(profile, _)| !data.profiles.iter().any(|p| p.id == **profile))
            .map(|(_, id)| *id),
    );
    stale.extend(
        documents
            .iter()
            .filter(|(document, _)| !data.documents.iter().any(|d| d.id == **document))
            .map(|(_, id)| *id),
    );
    stale.extend(
        references
            .iter()
            .filter(|((profile, fp), _)| {
                !data
                    .profiles
                    .iter()
                    .any(|p| p.id == *profile && p.fingerprints.contains(fp))
            })
            .map(|(_, id)| *id),
    );
    for id in stale {
        db.entry_mut(id)
            .context("Missing stale managed entry")?
            .remove();
    }
    for profile in &data.profiles {
        let id = if let Some(id) = group_ids.get(&profile.id) {
            *id
        } else {
            let mut managed = db.group_mut(group_id).context("Missing PGPCrypt group")?;
            let child = managed.add_group();
            child.id()
        };
        let mut child = db.group_mut(id).context("Missing identity group")?;
        child.name = profile.name.clone();
        mark_identity_group(&mut child, &profile.id);
        group_ids.insert(profile.id.clone(), id);
    }
    {
        let id = if let Some(id) = settings_id {
            id
        } else {
            db.group_mut(group_id)
                .context("Missing PGPCrypt group")?
                .add_entry()
                .id()
        };
        let mut settings = db.entry_mut(id).context("Missing settings entry")?;
        settings.set_unprotected("Title", "Vault notes and settings");
        settings.set_unprotected(MARKER, "settings");
        settings.set_unprotected(SCHEMA, "8");
        settings.set_protected("PGPCrypt.Profiles", serde_json::to_string(&data.profiles)?);
        settings.set_protected(
            "PGPCrypt.Preferences",
            serde_json::to_string(&data.preferences)?,
        );
        settings.set_protected("PGPCrypt.DefaultSigningKey", &data.default_signing_key);
        settings.set_protected("Notes", &data.notes);
        settings.set_unprotected(
            "PGPCrypt.IdleTimeoutSeconds",
            data.idle_timeout_seconds.to_string(),
        );
    }
    for bytes in &data.certificates {
        let fp = pgp::parse(bytes)?.fingerprint().to_hex();
        let id = if let Some(id) = keys.get(&fp) {
            *id
        } else {
            db.group_mut(group_id)
                .context("Missing PGPCrypt group")?
                .add_entry()
                .id()
        };
        let mut entry = db.entry_mut(id).context("Missing key entry")?;
        if entry.as_ref().parent().id() != group_id {
            entry.move_to(group_id)?;
        }
        set_key(&mut entry, bytes, data)?;
        keys.insert(fp, id);
    }
    for profile in &data.profiles {
        let target = *group_ids
            .get(&profile.id)
            .context("Missing identity group")?;
        let id = if let Some(id) = identities.get(&profile.id) {
            *id
        } else {
            db.group_mut(target)
                .context("Missing identity group")?
                .add_entry()
                .id()
        };
        let mut entry = db.entry_mut(id).context("Missing identity entry")?;
        if entry.as_ref().parent().id() != target {
            entry.move_to(target)?;
        }
        entry.set_unprotected("Title", "Identity details");
        entry.set_unprotected(MARKER, "identity");
        entry.set_unprotected(SCHEMA, "1");
        entry.set_unprotected(PROFILE_ID, &profile.id);
        entry.set_protected("UserName", &profile.username);
        entry.set_protected("Email", &profile.email);
        entry.set_protected("URL", &profile.url);
        entry.set_protected("Notes", &profile.notes);
    }
    for document in &data.documents {
        let target = if document.profile_id.is_empty() {
            group_id
        } else {
            *group_ids
                .get(&document.profile_id)
                .context("Missing document identity group")?
        };
        let id = if let Some(id) = documents.get(&document.id) {
            *id
        } else {
            db.group_mut(target)
                .context("Missing document group")?
                .add_entry()
                .id()
        };
        let mut entry = db.entry_mut(id).context("Missing document entry")?;
        if entry.as_ref().parent().id() != target {
            entry.move_to(target)?;
        }
        entry.set_unprotected("Title", &document.title);
        entry.set_unprotected(MARKER, "document");
        entry.set_unprotected(SCHEMA, "1");
        entry.set_protected("Notes", &document.text);
        entry.set_unprotected("PGPCrypt.DocumentId", &document.id);
        entry.set_unprotected(PROFILE_ID, &document.profile_id);
        entry.set_unprotected("PGPCrypt.CreatedAt", document.created_at.to_string());
        entry.set_unprotected("PGPCrypt.UpdatedAt", document.updated_at.to_string());
    }
    for profile in &data.profiles {
        let target = *group_ids
            .get(&profile.id)
            .context("Missing identity group")?;
        for fp in &profile.fingerprints {
            let id = if let Some(id) = references.get(&(profile.id.clone(), fp.clone())) {
                *id
            } else {
                db.group_mut(target)
                    .context("Missing identity group")?
                    .add_entry()
                    .id()
            };
            let canonical = keys.get(fp).context("Key reference has no canonical key")?;
            let mut entry = db.entry_mut(id).context("Missing key reference")?;
            entry.set_unprotected("Title", format!("Key {fp}"));
            entry.set_unprotected(MARKER, "key_reference");
            entry.set_unprotected(SCHEMA, "1");
            entry.set_unprotected("OpenPGP.Fingerprint", fp);
            entry.set_unprotected("PGPCrypt.KeyEntry", canonical.uuid().to_string());
            if entry.get("Notes").is_none() {
                entry.set_unprotected("Notes","Identity membership reference; no key material is duplicated here. In the PGPCrypt root group, find the canonical key with this exact OpenPGP.Fingerprint. Reveal OpenPGP.PublicKey or OpenPGP.PrivateKey there to recover it. Private-key passwords, if set, are separate from the database password.");
            }
        }
    }
    for (profile, id) in group_ids {
        if !data.profiles.iter().any(|p| p.id == profile) {
            let stale = db.group_mut(id).context("Missing stale identity group")?;
            ensure!(
                stale.as_ref().entries().next().is_none(),
                "Identity group still contains a live entry"
            );
            stale.remove();
        }
    }
    let mut encrypted = Vec::new();
    db.save(&mut encrypted, DatabaseKey::new().with_password(password))?;
    ensure!(encrypted.len() <= MAX_SIZE, "KDBX exceeds 16 MiB");
    writer.write_all(&encrypted)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const PASS: &str = "disposable kdbx test passphrase";

    #[test]
    fn identity_standard_fields_accept_external_edits_and_require_stable_ids() -> Result<()> {
        let mut data = VaultData::default();
        let id = crate::vault::workspace_id()?;
        data.profiles.push(Profile {
            id: id.clone(),
            name: "Personal".into(),
            fingerprints: Vec::new(),
            username: "Original alias".into(),
            email: "original@example.invalid".into(),
            url: "https://example.invalid/old".into(),
            notes: "original notes".into(),
        });
        let mut bytes = Vec::new();
        write(&data, None, PASS, &mut bytes)?;
        let (_, mut db) = open(&bytes, PASS)?;
        {
            let root = db.root();
            let group = root.groups().find(|group| group.name == GROUP).unwrap();
            let identity_group = group
                .groups()
                .find(|group| group.name == "Personal")
                .unwrap();
            let entry = identity_group
                .entries()
                .find(|entry| entry.get(MARKER) == Some("identity"))
                .unwrap();
            assert!(
                matches!(identity_group.custom_data[PROFILE_ID].value.as_ref(), Some(CustomDataValue::String(value)) if value == &format!("profile:{id}")),
                "group IDs must remain text after KDBX serialization"
            );
            assert_eq!(entry.get("Title"), Some("Identity details"));
            for field in ["UserName", "Email", "URL", "Notes"] {
                assert!(entry.fields[field].is_protected());
            }
        }
        db.foreach_entry_mut(|mut entry| {
            if entry.get(MARKER) == Some("identity") {
                entry.set_unprotected("Title", "A local recovery label");
                entry.set_protected("UserName", "Edited alias");
                entry.set_protected("Notes", "Edited in another client");
            }
        });
        db.foreach_group_mut(|mut group| {
            if identity_group_id(&group).is_ok_and(|profile| profile == id) {
                group.name = "Edited identity".into();
            }
        });
        let mut changed = Vec::new();
        db.save(&mut changed, DatabaseKey::new().with_password(PASS))?;
        let (loaded, _) = open(&changed, PASS)?;
        assert_eq!(loaded.profiles[0].id, id);
        assert_eq!(loaded.profiles[0].name, "Edited identity");
        assert_eq!(loaded.profiles[0].username, "Edited alias");
        assert_eq!(loaded.profiles[0].notes, "Edited in another client");
        db.foreach_entry_mut(|mut entry| {
            if entry.get(MARKER) == Some("identity") {
                entry.set_unprotected("PGPCrypt.ProfileId", crate::vault::workspace_id().unwrap());
            }
        });
        let mut damaged = Vec::new();
        db.save(&mut damaged, DatabaseKey::new().with_password(PASS))?;
        assert!(
            open(&damaged, PASS).is_err(),
            "identity membership cannot silently detach"
        );
        Ok(())
    }

    fn grouped_fixture() -> Result<(VaultData, String, String, String, String)> {
        let mut data = VaultData::default();
        let cert = pgp::generate("Group fixture <groups@example.invalid>")?;
        let fp = cert.fingerprint().to_hex();
        data.certificates.push(pgp::encode(&cert)?.to_vec());
        let personal = crate::vault::workspace_id()?;
        let work = crate::vault::workspace_id()?;
        for (id, name) in [(&personal, "Personal"), (&work, "Work")] {
            data.profiles.push(Profile {
                id: id.clone(),
                name: name.into(),
                username: "Alias".into(),
                email: String::new(),
                url: String::new(),
                notes: "Private profile notes".into(),
                fingerprints: vec![fp.clone()],
            });
        }
        let document = data.save_document(
            "",
            "Saved message",
            &personal,
            Some("Saved document text"),
            1000,
        )?;
        Ok((data, fp, personal, work, document.id.clone()))
    }

    #[test]
    fn actual_groups_support_shared_keys_group_rename_and_manual_moves() -> Result<()> {
        let (data, fp, personal, work, document_id) = grouped_fixture()?;
        let mut bytes = Vec::new();
        write(&data, None, PASS, &mut bytes)?;
        let (_, mut db) = open(&bytes, PASS)?;
        let (personal_group, work_group, canonical, reference, document) = {
            let root = db.root();
            let managed = root.groups().find(|g| g.name == GROUP).unwrap();
            let personal_group = managed.groups().find(|g| g.name == "Personal").unwrap();
            let work_group = managed.groups().find(|g| g.name == "Work").unwrap();
            let canonical = managed
                .entries()
                .filter(|e| e.get(MARKER) == Some("key"))
                .collect::<Vec<_>>();
            assert_eq!(
                canonical.len(),
                1,
                "one canonical secret-key entry across identities"
            );
            for group in [&personal_group, &work_group] {
                let reference = group
                    .entries()
                    .find(|e| e.get(MARKER) == Some("key_reference"))
                    .unwrap();
                assert_eq!(reference.get("OpenPGP.Fingerprint"), Some(fp.as_str()));
                assert_eq!(
                    reference.get("PGPCrypt.KeyEntry"),
                    Some(canonical[0].id().uuid().to_string().as_str())
                );
                assert!(reference.get("OpenPGP.PrivateKey").is_none());
                assert!(reference.get("OpenPGP.PublicKey").is_none());
            }
            (
                personal_group.id(),
                work_group.id(),
                canonical[0].id(),
                personal_group
                    .entries()
                    .find(|e| e.get(MARKER) == Some("key_reference"))
                    .unwrap()
                    .id(),
                personal_group
                    .entries()
                    .find(|e| e.get(MARKER) == Some("document"))
                    .unwrap()
                    .id(),
            )
        };
        db.group_mut(personal_group).unwrap().name = "Renamed personal".into();
        db.entry_mut(reference).unwrap().remove();
        db.entry_mut(document).unwrap().move_to(work_group)?;
        db.entry_mut(document)
            .unwrap()
            .set_protected("Independent.Field", "preserve metadata");
        let mut external = Vec::new();
        db.save(&mut external, DatabaseKey::new().with_password(PASS))?;
        let (loaded, original) = open(&external, PASS)?;
        let personal_profile = loaded.profiles.iter().find(|p| p.id == personal).unwrap();
        assert_eq!(personal_profile.name, "Renamed personal");
        assert!(personal_profile.fingerprints.is_empty());
        assert_eq!(
            loaded
                .profiles
                .iter()
                .find(|p| p.id == work)
                .unwrap()
                .fingerprints,
            vec![fp]
        );
        assert_eq!(
            loaded
                .documents
                .iter()
                .find(|d| d.id == document_id)
                .unwrap()
                .profile_id,
            work
        );
        let mut saved = Vec::new();
        write(&loaded, Some(&original), PASS, &mut saved)?;
        let (_, reopened) = open(&saved, PASS)?;
        assert!(reopened.entry(canonical).is_some());
        assert_eq!(
            reopened.entry(document).unwrap().get("Independent.Field"),
            Some("preserve metadata")
        );
        assert_eq!(reopened.entry(document).unwrap().parent().id(), work_group);
        Ok(())
    }

    #[test]
    fn schema5_migration_preserves_entry_ids_custom_fields_and_history() -> Result<()> {
        let (data, _, personal, _, document_id) = grouped_fixture()?;
        let mut bytes = Vec::new();
        write(&data, None, PASS, &mut bytes)?;
        let (_, mut db) = open(&bytes, PASS)?;
        let (managed_id, children, entries) = {
            let root = db.root();
            let managed = root.groups().find(|g| g.name == GROUP).unwrap();
            let children = managed.groups().map(|g| g.id()).collect::<Vec<_>>();
            let entries = managed
                .groups()
                .flat_map(|g| {
                    g.entries()
                        .map(|e| {
                            (
                                e.id(),
                                e.get(MARKER).unwrap().to_owned(),
                                e.get(PROFILE_ID).unwrap_or_default().to_owned(),
                            )
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            (managed.id(), children, entries)
        };
        let mut identity_id = None;
        let mut saved_document = None;
        for (id, kind, profile_id) in entries {
            if kind == "key_reference" {
                db.entry_mut(id).unwrap().remove();
                continue;
            }
            let mut entry = db.entry_mut(id).unwrap();
            entry.move_to(managed_id)?;
            if kind == "identity" {
                entry.set_unprotected(
                    "Title",
                    data.profiles
                        .iter()
                        .find(|p| p.id == profile_id)
                        .unwrap()
                        .name
                        .clone(),
                );
                if profile_id == personal {
                    identity_id = Some(id);
                    entry.set_protected("Independent.Identity", "preserve profile custom field");
                }
            } else if kind == "document" {
                saved_document = Some(id);
                entry.set_protected("Independent.Document", "preserve document custom field");
                let historical: Entry = (*entry).clone();
                let mut history = keepass::db::History::default();
                history.add_entry(historical);
                entry.history = Some(history);
            }
        }
        for id in children {
            db.group_mut(id).unwrap().remove();
        }
        db.foreach_entry_mut(|mut entry| {
            if entry.get(MARKER) == Some("settings") {
                entry.set_unprotected(SCHEMA, "5");
            }
        });
        let mut legacy = Vec::new();
        db.save(&mut legacy, DatabaseKey::new().with_password(PASS))?;
        let (loaded, original) = open(&legacy, PASS)?;
        assert_eq!(loaded.profiles.len(), 2);
        assert_eq!(loaded.documents[0].id, document_id);
        let mut migrated = Vec::new();
        write(&loaded, Some(&original), PASS, &mut migrated)?;
        let (loaded, db) = open(&migrated, PASS)?;
        assert_eq!(loaded.profiles.len(), 2);
        assert_eq!(
            db.entry(identity_id.unwrap())
                .unwrap()
                .get("Independent.Identity"),
            Some("preserve profile custom field")
        );
        let document = db.entry(saved_document.unwrap()).unwrap();
        assert_eq!(
            document.get("Independent.Document"),
            Some("preserve document custom field")
        );
        assert_eq!(document.history.as_ref().unwrap().get_entries().len(), 1);
        assert_eq!(identity_group_id(&document.parent())?, personal);
        Ok(())
    }

    #[test]
    fn malformed_identity_groups_and_forged_references_are_rejected() -> Result<()> {
        let (data, _, _, _, _) = grouped_fixture()?;
        let mut bytes = Vec::new();
        write(&data, None, PASS, &mut bytes)?;
        let (_, db) = open(&bytes, PASS)?;
        for alteration in [
            "unknown_group",
            "nested_group",
            "wrong_target",
            "duplicate_secret",
        ] {
            let mut changed = db.clone();
            let main = {
                let root = changed.root();
                root.groups().find(|g| g.name == GROUP).unwrap().id()
            };
            match alteration {
                "unknown_group" => {
                    changed.group_mut(main).unwrap().add_group().name = "Unrelated".into();
                }
                "nested_group" => {
                    let child = {
                        let root = changed.group(main).unwrap();
                        root.groups().next().unwrap().id()
                    };
                    changed.group_mut(child).unwrap().add_group().name = "Nested".into();
                }
                _ => changed.foreach_entry_mut(|mut entry| {
                    if entry.get(MARKER) == Some("key_reference") {
                        if alteration == "wrong_target" {
                            entry.set_unprotected("PGPCrypt.KeyEntry", "forged reference");
                        } else {
                            entry.set_protected(
                                "OpenPGP.PrivateKey",
                                "must not be duplicated in references",
                            );
                        }
                    }
                }),
            }
            let mut malformed = Vec::new();
            changed.save(&mut malformed, DatabaseKey::new().with_password(PASS))?;
            assert!(
                open(&malformed, PASS).is_err(),
                "unsupported structure: {alteration}"
            );
        }
        Ok(())
    }

    #[test]
    fn portable_fields_integrity_and_preservation() -> Result<()> {
        let mut data = VaultData::default();
        let cert = pgp::generate("Portable fixture <portable@example.invalid>")?;
        data.certificates.push(pgp::encode(&cert)?.to_vec());
        data.notes = "secret portable notes".into();
        let mut bytes = Vec::new();
        write(&data, None, PASS, &mut bytes)?;
        assert!(bytes.starts_with(MAGIC));
        assert!(!bytes.windows(8).any(|w| w == b"portable"));
        let (loaded, mut db) = open(&bytes, PASS)?;
        assert_eq!(loaded.notes, data.notes);
        assert_eq!(
            pgp::parse(&loaded.certificates[0])?.fingerprint(),
            cert.fingerprint()
        );
        let root = db.root();
        let group = root.groups().find(|g| g.name == GROUP).unwrap();
        let entry = group
            .entries()
            .find(|e| e.get(MARKER) == Some("key"))
            .unwrap();
        assert!(entry.fields["OpenPGP.PrivateKey"].is_protected());
        assert!(entry.fields["OpenPGP.Revocation"].is_protected());
        assert!(entry.get("Notes").unwrap().contains("Advanced"));
        for field in ["OpenPGP.PublicKey", "OpenPGP.PrivateKey"] {
            let mut malformed = db.clone();
            malformed.foreach_entry_mut(|mut e| {
                if e.get(MARKER) == Some("key") {
                    e.set_protected(
                        field,
                        if field == "OpenPGP.PublicKey" {
                            pgp::private_armor(&cert).unwrap().to_string()
                        } else {
                            pgp::public_armor(&cert).unwrap()
                        },
                    );
                }
            });
            let mut snapshot = Vec::new();
            malformed.save(&mut snapshot, DatabaseKey::new().with_password(PASS))?;
            assert!(
                open(&snapshot, PASS).is_err(),
                "mixed public/private field: {field}"
            );
        }
        // Earlier PGPCrypt KDBX settings lack the default-key field.
        let mut old_db = db.clone();
        old_db.foreach_entry_mut(|mut entry| {
            if entry.get(MARKER) == Some("settings") {
                entry.set_unprotected(SCHEMA, "1");
                entry.fields.remove("PGPCrypt.DefaultSigningKey");
                entry.fields.remove("PGPCrypt.Preferences");
            }
        });
        let mut old_snapshot = Vec::new();
        old_db.save(&mut old_snapshot, DatabaseKey::new().with_password(PASS))?;
        assert!(open(&old_snapshot, PASS)?.0.default_signing_key.is_empty());
        let mut root = db.root_mut();
        let mut unrelated = root.add_entry();
        unrelated.set_unprotected("Title", "Unrelated entry");
        unrelated.set_protected("Password", "preserve this unrelated secret");
        let unrelated_id = unrelated.id();
        let mut copy = Vec::new();
        write(&loaded, Some(&db), PASS, &mut copy)?;
        let (_, reopened) = open(&copy, PASS)?;
        assert_eq!(
            reopened.entry(unrelated_id).unwrap().get_password(),
            Some("preserve this unrelated secret")
        );
        assert!(open(&bytes, "wrong password").is_err());
        for index in [24, bytes.len() / 2, bytes.len() - 1] {
            let mut damaged = bytes.clone();
            damaged[index] ^= 1;
            assert!(open(&damaged, PASS).is_err());
        }
        assert!(open(&bytes[..bytes.len() - 1], PASS).is_err());
        bytes.push(0);
        assert!(open(&bytes, PASS).is_err());
        Ok(())
    }
    #[test]
    fn excessive_work_compression_and_unknown_xml_are_rejected() -> Result<()> {
        let mut bytes = Vec::new();
        write(&VaultData::default(), None, PASS, &mut bytes)?;
        let needle = [5, 1, 0, 0, 0, b'M', 8, 0, 0, 0];
        let offset = bytes
            .windows(needle.len())
            .position(|b| b == needle)
            .unwrap()
            + needle.len();
        bytes[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(
            preflight(&bytes)
                .unwrap_err()
                .to_string()
                .contains("resource limits")
        );
        assert!(
            validate_xml(
                b"<KeePassFile><Meta><FuturePlugin>secret</FuturePlugin></Meta></KeePassFile>"
            )
            .is_err()
        );
        assert!(validate_xml(b"<!DOCTYPE x><KeePassFile/>").is_err());
        assert!(validate_xml(b"<KeePassFile><Meta/><Root><Group><Name>PGPCrypt</Name></Group></Root></KeePassFile>").is_ok());
        Ok(())
    }
}
