//! Optional PGPCrypt-only inactivity destruction. Public companion metadata
//! and the local clock enforce a best-effort policy, not cryptographic expiry.
//! A normal successful open resets the deadline; dummy views do not.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, Metadata, OpenOptions, Permissions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const MAX_RECORD: usize = 2048;
const MAX_VAULT: usize = 17 * 1024 * 1024;
const DAY: u64 = 86_400;
const MAX_DURATION: u64 = 100 * 365 * DAY;

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Status {
    pub configured: bool,
    pub armed: bool,
    pub count: u32,
    pub unit: String,
    pub last_opened_at: u64,
    pub deadline: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: u32,
    count: u32,
    unit: String,
    last_opened_at: u64,
    deadline: u64,
    ciphertext_sha256: [u8; 32],
}

pub fn sidecar_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".pgpcrypt-expiry");
    PathBuf::from(name)
}

fn duration(count: u32, unit: &str) -> Result<u64> {
    ensure!(
        (1..=1000).contains(&count),
        "Choose an inactivity count from 1 to 1000"
    );
    // Explicit approximations avoid timezone, daylight-saving and calendar
    // ambiguities. The UI labels months as 30 days and years as 365 days.
    let unit_seconds = match unit {
        "days" => DAY,
        "weeks" => 7 * DAY,
        "months" => 30 * DAY,
        "years" => 365 * DAY,
        _ => anyhow::bail!("Choose days, weeks, months or years"),
    };
    let seconds = u64::from(count)
        .checked_mul(unit_seconds)
        .context("Inactivity duration is too large")?;
    ensure!(
        seconds <= MAX_DURATION,
        "Inactivity duration must not exceed 100 years"
    );
    Ok(seconds)
}

fn digest(bytes: &[u8]) -> Result<[u8; 32]> {
    let mut context = sequoia_openpgp::types::HashAlgorithm::SHA256
        .context()?
        .for_digest();
    context.update(bytes);
    let mut output = [0; 32];
    context.digest(&mut output)?;
    Ok(output)
}

fn validate_private(metadata: &Metadata, record: bool) -> Result<()> {
    // SAFETY: geteuid takes no arguments and has no failure return.
    let uid = unsafe { libc::geteuid() };
    ensure!(
        metadata.file_type().is_file()
            && metadata.uid() == uid
            && metadata.nlink() == 1
            && metadata.mode() & 0o077 == 0
            && (!record || metadata.mode() & 0o777 == 0o600),
        "Inactivity protection requires private regular files owned by your user, without symbolic or hard links"
    );
    Ok(())
}

fn same_file(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

fn open_private(path: &Path, write: bool, record: bool) -> Result<File> {
    let expected = fs::symlink_metadata(path)?;
    validate_private(&expected, record)?;
    let file = OpenOptions::new()
        .read(true)
        .write(write)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let actual = file.metadata()?;
    validate_private(&actual, record)?;
    ensure!(
        same_file(&expected, &actual),
        "File changed while being opened"
    );
    if write {
        ensure!(
            actual.mode() & 0o600 == 0o600,
            "Inactivity protection requires a readable and writable vault"
        );
    }
    Ok(file)
}

fn read_bounded(file: &mut File, maximum: usize) -> Result<Vec<u8>> {
    ensure!(
        file.metadata()?.len() <= maximum as u64,
        "Oversized inactivity-protection input"
    );
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    Read::by_ref(file)
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= maximum,
        "Oversized inactivity-protection input"
    );
    Ok(bytes)
}

fn current_snapshot(path: &Path) -> Result<Vec<u8>> {
    let mut file = open_private(path, true, false)?;
    let bytes = read_bounded(&mut file, MAX_VAULT)?;
    ensure!(!bytes.is_empty(), "Cannot arm an empty vault");
    Ok(bytes)
}

fn validate_record(record: &Record) -> Result<()> {
    let seconds = duration(record.count, &record.unit)?;
    ensure!(
        record.schema == 1
            && record.last_opened_at > 0
            && record.last_opened_at.checked_add(seconds) == Some(record.deadline),
        "Invalid inactivity-protection record"
    );
    Ok(())
}

fn read_record(path: &Path) -> Result<Option<Record>> {
    let mut file = match open_private(&sidecar_path(path), false, true) {
        Ok(file) => file,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error.context("Inactivity-protection record is unavailable")),
    };
    let record: Record = serde_json::from_slice(&read_bounded(&mut file, MAX_RECORD)?)
        .context("Invalid inactivity-protection record")?;
    validate_record(&record)?;
    Ok(Some(record))
}

fn record_destination(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_private(&metadata, true)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn write_record(path: &Path, record: &Record) -> Result<()> {
    validate_record(record)?;
    let path = sidecar_path(path);
    let existed = record_destination(&path)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let directory = File::open(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.as_file()
        .set_permissions(Permissions::from_mode(0o600))?;
    let bytes = serde_json::to_vec(record)?;
    ensure!(
        bytes.len() <= MAX_RECORD,
        "Oversized inactivity-protection record"
    );
    temp.write_all(&bytes)?;
    temp.as_file().sync_all()?;
    ensure!(
        record_destination(&path)? == existed,
        "Inactivity-protection record changed while saving"
    );
    if existed {
        temp.persist(&path).map_err(|error| error.error)?;
    } else {
        temp.persist_noclobber(&path).map_err(|error| error.error)?;
    }
    directory.sync_all()?;
    Ok(())
}

pub fn status(path: &Path, ciphertext: &[u8]) -> Result<Status> {
    let Some(record) = read_record(path)? else {
        return Ok(Status::default());
    };
    ensure!(ciphertext.len() <= MAX_VAULT, "Oversized vault");
    let armed = crate::protection::enabled(path)?
        && digest(ciphertext)? == record.ciphertext_sha256
        && current_snapshot(path).is_ok_and(|current| current == ciphertext);
    Ok(Status {
        configured: true,
        armed,
        count: record.count,
        unit: record.unit,
        last_opened_at: record.last_opened_at,
        deadline: record.deadline,
    })
}

/// Caller holds the real vault lock and has completed a normal unlock.
pub fn configure(path: &Path, ciphertext: &[u8], count: u32, unit: &str, now: u64) -> Result<()> {
    ensure!(
        crate::protection::enabled(path)?,
        "Enable vault protection before configuring inactivity deletion"
    );
    ensure!(now > 0, "The device clock is unavailable");
    let seconds = duration(count, unit)?;
    ensure!(
        ciphertext.len() <= MAX_VAULT && current_snapshot(path)? == ciphertext,
        "Vault changed; reopen it before configuring inactivity protection"
    );
    let record = Record {
        schema: 1,
        count,
        unit: unit.to_owned(),
        last_opened_at: now,
        deadline: now
            .checked_add(seconds)
            .context("Inactivity deadline is too large")?,
        ciphertext_sha256: digest(ciphertext)?,
    };
    write_record(path, &record)
}

pub fn disable(path: &Path) -> Result<()> {
    let path = sidecar_path(path);
    if !record_destination(&path)? {
        return Ok(());
    }
    let file = open_private(&path, false, true)?;
    ensure!(
        same_file(&file.metadata()?, &fs::symlink_metadata(&path)?),
        "Inactivity-protection record changed"
    );
    fs::remove_file(&path)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)?.sync_all()?;
    Ok(())
}

pub fn refresh_after_save(path: &Path, previous: &[u8], committed: &[u8]) -> Result<()> {
    if !crate::protection::enabled(path)? {
        return Ok(());
    }
    let Some(mut record) = read_record(path)? else {
        return Ok(());
    };
    ensure!(
        previous.len() <= MAX_VAULT && committed.len() <= MAX_VAULT,
        "Oversized vault"
    );
    if digest(previous)? != record.ciphertext_sha256 {
        return Ok(());
    }
    ensure!(
        current_snapshot(path)? == committed,
        "Vault changed before inactivity protection could be refreshed"
    );
    record.ciphertext_sha256 = digest(committed)?;
    write_record(path, &record)
}

/// Only a successful normal-password unlock calls this. Clock rollback never
/// moves the existing last-open time backward or shortens its reset deadline.
pub fn record_normal_open(path: &Path, ciphertext: &[u8], now: u64) -> Result<()> {
    if !crate::protection::enabled(path)? {
        return Ok(());
    }
    let Some(mut record) = read_record(path)? else {
        return Ok(());
    };
    ensure!(ciphertext.len() <= MAX_VAULT, "Oversized vault");
    if digest(ciphertext)? != record.ciphertext_sha256 {
        return Ok(());
    }
    ensure!(
        current_snapshot(path)? == ciphertext,
        "Vault changed before its normal unlock could be recorded"
    );
    record.last_opened_at = now.max(record.last_opened_at);
    record.deadline = record
        .last_opened_at
        .checked_add(duration(record.count, &record.unit)?)
        .context("Inactivity deadline is too large")?;
    write_record(path, &record)
}

/// Run before decrypting. Only a matching, safe, enabled record can authorize
/// destruction. Missing/malformed/stale records leave normal opening available.
pub fn check_and_destroy_if_expired(path: &Path, now: u64) -> Result<bool> {
    if !crate::protection::enabled(path)? {
        return Ok(false);
    }
    let record = match read_record(path) {
        Ok(Some(record)) => record,
        Ok(None) | Err(_) => return Ok(false),
    };
    if now < record.deadline {
        return Ok(false);
    }
    let _lock = crate::vault::acquire_lock(path)?;
    let current = match current_snapshot(path) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(false),
    };
    if digest(&current)? != record.ciphertext_sha256 || !crate::protection::enabled(path)? {
        return Ok(false);
    }
    crate::duress::destroy_matching(path, &current)
        .map_err(|_| anyhow::Error::new(crate::duress::DestructionTriggered))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Result<(tempfile::TempDir, PathBuf, Vec<u8>)> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("disposable-inactivity-vault");
        let bytes = vec![0x5a; 8192];
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(&bytes)?;
        crate::protection::enable(&path)?;
        Ok((dir, path, bytes))
    }

    #[test]
    fn normal_open_resets_deadline_and_expiry_overwrites_same_length() -> Result<()> {
        let (_dir, path, bytes) = fixture()?;
        let start = 1_700_000_000;
        configure(&path, &bytes, 2, "days", start)?;
        assert!(status(&path, &bytes)?.armed);
        assert!(!check_and_destroy_if_expired(&path, start + DAY)?);
        assert_eq!(fs::read(&path)?, bytes);
        record_normal_open(&path, &bytes, start + DAY)?;
        assert_eq!(status(&path, &bytes)?.deadline, start + 3 * DAY);
        record_normal_open(&path, &bytes, start - 1)?;
        assert_eq!(status(&path, &bytes)?.last_opened_at, start + DAY);
        assert!(!check_and_destroy_if_expired(&path, start + 2 * DAY)?);
        assert!(check_and_destroy_if_expired(&path, start + 3 * DAY)?);
        let overwritten = fs::read(&path)?;
        assert_eq!(overwritten.len(), bytes.len());
        assert_ne!(overwritten, bytes);
        assert!(!check_and_destroy_if_expired(&path, start + 4 * DAY)?);
        Ok(())
    }

    #[test]
    fn stale_disabled_and_unsafe_files_are_not_destroyed() -> Result<()> {
        let (dir, path, bytes) = fixture()?;
        let start = 1_700_000_000;
        configure(&path, &bytes, 1, "weeks", start)?;
        let modified = vec![0xa5; bytes.len() + 4096];
        fs::write(&path, &modified)?;
        assert!(!status(&path, &modified)?.armed);
        assert!(!check_and_destroy_if_expired(&path, start + 8 * DAY)?);
        assert_eq!(fs::read(&path)?, modified);
        refresh_after_save(&path, &modified, &modified)?;
        assert!(!status(&path, &modified)?.armed);
        refresh_after_save(&path, &bytes, &modified)?;
        assert!(status(&path, &modified)?.armed);
        fs::set_permissions(&path, Permissions::from_mode(0o400))?;
        assert!(!status(&path, &modified)?.armed);
        assert!(!check_and_destroy_if_expired(&path, start + 8 * DAY)?);
        fs::set_permissions(&path, Permissions::from_mode(0o600))?;
        let link = dir.path().join("other-link");
        fs::hard_link(&path, &link)?;
        assert!(!check_and_destroy_if_expired(&path, start + 8 * DAY)?);
        assert_eq!(fs::read(&path)?, modified);
        fs::remove_file(&link)?;
        crate::protection::disable(&path)?;
        assert!(!check_and_destroy_if_expired(&path, start + 8 * DAY)?);
        assert!(configure(&path, &modified, 1, "days", start).is_err());
        Ok(())
    }

    #[test]
    fn unit_limits_and_malformed_records_fail_closed() -> Result<()> {
        let (_dir, path, bytes) = fixture()?;
        let start = 1_700_000_000;
        for (count, unit) in [(0, "days"), (1001, "days"), (101, "years"), (1, "unknown")] {
            assert!(configure(&path, &bytes, count, unit, start).is_err());
        }
        assert!(configure(&path, &bytes, 1, "days", u64::MAX).is_err());
        configure(&path, &bytes, 1, "months", start)?;
        assert_eq!(status(&path, &bytes)?.deadline, start + 30 * DAY);
        configure(&path, &bytes, 1, "years", start)?;
        assert_eq!(status(&path, &bytes)?.deadline, start + 365 * DAY);
        fs::write(sidecar_path(&path), b"{invalid record}")?;
        assert!(!check_and_destroy_if_expired(&path, u64::MAX)?);
        assert_eq!(fs::read(&path)?, bytes);
        disable(&path)?;
        assert!(!sidecar_path(&path).exists());
        Ok(())
    }
}
