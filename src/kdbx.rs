//! Portable KDBX 4.1 persistence through keepass-rs, with a bounded profile.
//! Header inspection here only enforces resource/feature limits; the library
//! performs all encryption, key derivation and authentication.
use crate::{
    pgp,
    vault::{MAX_SIZE, RevocationTicket, VaultData},
};
use anyhow::{Context, Result, bail, ensure};
use keepass::{
    Database, DatabaseKey,
    config::{CompressionConfig, DatabaseVersion, KdfConfig},
    db::{Entry, GroupId},
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
    let mut data = VaultData::default();
    let mut settings = false;
    let mut fingerprints = HashSet::new();
    for entry in group.entries() {
        ensure!(
            entry.get(SCHEMA) == Some("1")
                || (entry.get(MARKER) == Some("settings") && entry.get(SCHEMA) == Some("2")),
            "Unsupported PGPCrypt KDBX entry schema"
        );
        match entry.get(MARKER) {
            Some("settings") => {
                ensure!(!settings, "Duplicate PGPCrypt settings");
                settings = true;
                data.default_signing_key = entry
                    .get("PGPCrypt.DefaultSigningKey")
                    .unwrap_or_default()
                    .to_owned();
                data.notes = entry.get("Notes").unwrap_or_default().to_owned();
                data.idle_timeout_seconds = entry
                    .get("PGPCrypt.IdleTimeoutSeconds")
                    .context("Missing timeout")?
                    .parse()?;
            }
            Some("key") => {
                let public = entry
                    .get("OpenPGP.PublicKey")
                    .context("Missing public key")?;
                let public = pgp::parse(public.as_bytes())?;
                let private = entry.get("OpenPGP.PrivateKey").unwrap_or_default();
                let cert = if private.is_empty() {
                    public.clone()
                } else {
                    let private = pgp::parse(private.as_bytes())?;
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
    ensure!(
        settings && (60..=3600).contains(&data.idle_timeout_seconds),
        "Missing/invalid PGPCrypt settings"
    );
    Ok((data, db))
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
        cert.userids()
            .next()
            .map(|u| String::from_utf8_lossy(u.userid().value()).into_owned())
            .unwrap_or_else(|| fingerprint.clone()),
    );
    entry.set_unprotected(MARKER, "key");
    entry.set_unprotected(SCHEMA, "1");
    entry.set_unprotected("OpenPGP.Fingerprint", &fingerprint);
    entry.set_protected("OpenPGP.PublicKey", pgp::public_armor(&cert)?);
    // Even imported unprotected packets remain protected by the KDBX container
    // and protected custom field; production-generated packets are also encrypted.
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
    {
        let mut group = db.group_mut(group_id).context("Missing PGPCrypt group")?;
        let settings_id = group
            .as_ref()
            .entries()
            .find(|e| e.get(MARKER) == Some("settings"))
            .map(|e| e.id());
        {
            let mut settings = if let Some(id) = settings_id {
                group.entry_mut(id).context("Missing settings")?
            } else {
                group.add_entry()
            };
            settings.set_unprotected("Title", "Vault notes and settings");
            settings.set_unprotected(MARKER, "settings");
            settings.set_unprotected(SCHEMA, "2");
            settings.set_protected("PGPCrypt.DefaultSigningKey", &data.default_signing_key);
            settings.set_protected("Notes", &data.notes);
            settings.set_unprotected(
                "PGPCrypt.IdleTimeoutSeconds",
                data.idle_timeout_seconds.to_string(),
            );
        }
        for bytes in &data.certificates {
            let fp = pgp::parse(bytes)?.fingerprint().to_hex();
            let existing = group
                .as_ref()
                .entries()
                .find(|e| {
                    e.get(MARKER) == Some("key")
                        && e.get("OpenPGP.Fingerprint") == Some(fp.as_str())
                })
                .map(|e| e.id());
            let mut entry = if let Some(id) = existing {
                group.entry_mut(id).context("Missing key entry")?
            } else {
                group.add_entry()
            };
            set_key(&mut entry, bytes, data)?;
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
        // Earlier PGPCrypt KDBX settings lack the default-key field.
        let mut old_db = db.clone();
        old_db.foreach_entry_mut(|mut entry| {
            if entry.get(MARKER) == Some("settings") {
                entry.set_unprotected(SCHEMA, "1");
                entry.fields.remove("PGPCrypt.DefaultSigningKey");
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
