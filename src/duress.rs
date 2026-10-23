//! Opt-in, PGPCrypt-only emergency destruction and dummy-password matching.
//! This is not secure physical erasure or plausible deniability. Standard
//! age/KDBX files remain unchanged; separate private verifier records reveal
//! configuration. A dummy match only authorizes an empty, read-only view in the
//! caller; it never decrypts or modifies the real vault.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, Metadata, OpenOptions, Permissions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const MAX_RECORD: usize = 1024;
const MAX_VAULT: usize = 17 * 1024 * 1024;
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Purpose {
    Emergency,
    Dummy,
}

impl Purpose {
    fn suffix(self) -> &'static str {
        match self {
            Self::Emergency => ".pgpcrypt-emergency",
            Self::Dummy => ".pgpcrypt-dummy",
        }
    }

    fn option(self) -> crate::protection::OptionKind {
        match self {
            Self::Emergency => crate::protection::OptionKind::Emergency,
            Self::Dummy => crate::protection::OptionKind::Dummy,
        }
    }

    fn context(self) -> &'static [u8] {
        match self {
            Self::Emergency => b"PGPCrypt emergency password v1",
            Self::Dummy => b"PGPCrypt dummy password v1",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Status {
    pub configured: bool,
    pub armed: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    purpose: Purpose,
    salt: [u8; 16],
    verifier: [u8; 32],
    ciphertext_sha256: [u8; 32],
}

/// The emergency password matched, but the destruction operation failed or its
/// outcome is uncertain. Deliberately carry no detailed error chain to the UI.
#[derive(Debug)]
pub struct DestructionTriggered;
impl std::fmt::Display for DestructionTriggered {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("Vault cannot be opened; it may be damaged")
    }
}
impl std::error::Error for DestructionTriggered {}

pub fn sidecar_path(path: &Path) -> PathBuf {
    record_path(path, Purpose::Emergency)
}

pub fn dummy_sidecar_path(path: &Path) -> PathBuf {
    record_path(path, Purpose::Dummy)
}

fn record_path(path: &Path, purpose: Purpose) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(purpose.suffix());
    PathBuf::from(name)
}

fn config(purpose: Purpose) -> argon2::Config<'static> {
    // Parameters are application constants, never attacker-selected JSON/PHC.
    argon2::Config {
        variant: argon2::Variant::Argon2id,
        version: argon2::Version::Version13,
        mem_cost: 64 * 1024,
        time_cost: 3,
        lanes: 1,
        hash_length: 32,
        // Bind the verifier cryptographically to its purpose as well as
        // checking the record tag. Editing a copied tag cannot swap behaviors.
        ad: purpose.context(),
        ..argon2::Config::default()
    }
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

fn same_file(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

fn validate_private(metadata: &Metadata, exact_mode: bool) -> Result<()> {
    // SAFETY: geteuid takes no arguments and has no failure return.
    let uid = unsafe { libc::geteuid() };
    ensure!(
        metadata.file_type().is_file()
            && metadata.uid() == uid
            && metadata.nlink() == 1
            && metadata.mode() & 0o077 == 0
            && (!exact_mode || metadata.mode() & 0o777 == 0o600),
        "Alternative-password protection requires a private regular file owned by your user, without symbolic or hard links"
    );
    Ok(())
}

fn open_private(path: &Path, write: bool, exact_mode: bool) -> Result<File> {
    let expected = fs::symlink_metadata(path)?;
    validate_private(&expected, exact_mode)?;
    let file = OpenOptions::new()
        .read(true)
        .write(write)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let actual = file.metadata()?;
    validate_private(&actual, exact_mode)?;
    ensure!(
        same_file(&expected, &actual),
        "File changed while being opened"
    );
    Ok(file)
}

fn read_bounded(file: &mut File, maximum: usize) -> Result<Vec<u8>> {
    ensure!(
        file.metadata()?.len() <= maximum as u64,
        "Oversized alternative-password input"
    );
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    Read::by_ref(file)
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= maximum,
        "Oversized alternative-password input"
    );
    Ok(bytes)
}

fn read_record(path: &Path, purpose: Purpose) -> Result<Option<Record>> {
    let path = record_path(path, purpose);
    let mut file = match open_private(&path, false, true) {
        Ok(file) => file,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error.context("Alternative-password record is unavailable")),
    };
    let bytes = read_bounded(&mut file, MAX_RECORD)?;
    let record: Record =
        serde_json::from_slice(&bytes).context("Invalid alternative-password record")?;
    ensure!(
        record.version == 1 && record.purpose == purpose,
        "Unsupported alternative-password record or mismatched purpose"
    );
    Ok(Some(record))
}

fn check_record_destination(path: &Path) -> Result<Option<Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_private(&metadata, true)?;
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn write_record(path: &Path, record: &Record) -> Result<()> {
    let path = record_path(path, record.purpose);
    let expected = check_record_destination(&path)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.as_file()
        .set_permissions(Permissions::from_mode(0o600))?;
    let bytes = serde_json::to_vec(record)?;
    ensure!(
        bytes.len() <= MAX_RECORD,
        "Oversized alternative-password record"
    );
    temp.write_all(&bytes)?;
    temp.as_file().sync_all()?;
    let current = check_record_destination(&path)?;
    ensure!(
        match (&expected, &current) {
            (None, None) => true,
            (Some(before), Some(now)) => same_file(before, now),
            _ => false,
        },
        "Alternative-password record changed while saving"
    );
    if expected.is_some() {
        temp.persist(&path).map_err(|error| error.error)?;
    } else {
        temp.persist_noclobber(&path).map_err(|error| error.error)?;
    }
    directory.sync_all()?;
    Ok(())
}

fn current_snapshot(path: &Path) -> Result<Vec<u8>> {
    // A read-only vault cannot honestly be reported ready for an in-place
    // overwrite. Probe writable access without changing any bytes.
    let mut file = open_private(path, true, false)?;
    ensure!(
        file.metadata()?.mode() & 0o600 == 0o600,
        "Emergency protection requires a readable and writable vault"
    );
    let bytes = read_bounded(&mut file, MAX_VAULT)?;
    ensure!(!bytes.is_empty(), "Cannot arm an empty vault");
    Ok(bytes)
}

fn snapshot_for(path: &Path, purpose: Purpose) -> Result<Vec<u8>> {
    if purpose == Purpose::Emergency {
        current_snapshot(path)
    } else {
        // The dummy view has no write authority over the original. It may be
        // opened even if the owner has made that file read-only.
        let mut file = open_private(path, false, false)?;
        let bytes = read_bounded(&mut file, MAX_VAULT)?;
        ensure!(!bytes.is_empty(), "Cannot match an empty vault");
        Ok(bytes)
    }
}

pub fn status(path: &Path, ciphertext: &[u8]) -> Result<Status> {
    record_status(path, ciphertext, Purpose::Emergency)
}

pub fn dummy_status(path: &Path, ciphertext: &[u8]) -> Result<Status> {
    record_status(path, ciphertext, Purpose::Dummy)
}

fn record_status(path: &Path, ciphertext: &[u8], purpose: Purpose) -> Result<Status> {
    let Some(record) = read_record(path, purpose)? else {
        return Ok(Status::default());
    };
    ensure!(ciphertext.len() <= MAX_VAULT, "Oversized vault");
    let armed = crate::protection::option_enabled(path, purpose.option())?
        && digest(ciphertext)? == record.ciphertext_sha256
        && snapshot_for(path, purpose).is_ok_and(|current| current == ciphertext);
    Ok(Status {
        configured: true,
        armed,
    })
}

/// The caller must hold the vault lock and reject the normal unlock password.
pub fn configure(path: &Path, ciphertext: &[u8], emergency_password: &str) -> Result<()> {
    ensure!(
        crate::protection::option_enabled(path, Purpose::Emergency.option())?,
        "Enable the emergency-password option before setting its password"
    );
    configure_record(path, ciphertext, emergency_password, Purpose::Emergency)
}

/// The caller must reject normal/emergency passwords and hold the vault lock.
pub fn dummy_configure(path: &Path, ciphertext: &[u8], password: &str) -> Result<()> {
    ensure!(
        crate::protection::option_enabled(path, Purpose::Dummy.option())?,
        "Enable the dummy-password option before setting its password"
    );
    configure_record(path, ciphertext, password, Purpose::Dummy)
}

fn configure_record(
    path: &Path,
    ciphertext: &[u8],
    password: &str,
    purpose: Purpose,
) -> Result<()> {
    crate::password::validate_new_password(password)?;
    let other = match purpose {
        Purpose::Emergency => Purpose::Dummy,
        Purpose::Dummy => Purpose::Emergency,
    };
    ensure!(
        !password_matches_configured(path, password, other)?,
        "Choose different emergency and dummy passwords"
    );
    ensure!(
        ciphertext.len() <= MAX_VAULT && !ciphertext.is_empty(),
        "Invalid vault size"
    );
    ensure!(
        snapshot_for(path, purpose)? == ciphertext,
        "Vault changed; reopen it before configuring alternative passwords"
    );
    let mut salt = [0; 16];
    sequoia_openpgp::crypto::random(&mut salt)?;
    let hash = Zeroizing::new(argon2::hash_raw(
        password.as_bytes(),
        &salt,
        &config(purpose),
    )?);
    let mut verifier = [0; 32];
    verifier.copy_from_slice(&hash);
    let record = Record {
        version: 1,
        purpose,
        salt,
        verifier,
        ciphertext_sha256: digest(ciphertext)?,
    };
    // Password derivation takes time. Refuse an intervening external save.
    ensure!(
        snapshot_for(path, purpose)? == ciphertext,
        "Vault changed; reopen it before configuring alternative passwords"
    );
    ensure!(
        crate::protection::option_enabled(path, purpose.option())?,
        "This vault-protection option is disabled"
    );
    write_record(path, &record)
}

/// Disable the option first, then erase its verifier configuration.
pub fn disable(path: &Path) -> Result<()> {
    crate::protection::set_option(path, Purpose::Emergency.option(), false)
}

pub fn dummy_disable(path: &Path) -> Result<()> {
    crate::protection::set_option(path, Purpose::Dummy.option(), false)
}

/// Used only while configuring passwords, never for authorizing an unlock.
/// Check a valid salted verifier even if its ciphertext binding is stale. A
/// malformed or unsafe record is an error, so it cannot silently allow reuse.
pub fn emergency_password_matches_configured(path: &Path, password: &str) -> Result<bool> {
    password_matches_configured(path, password, Purpose::Emergency)
}

pub fn dummy_password_matches_configured(path: &Path, password: &str) -> Result<bool> {
    password_matches_configured(path, password, Purpose::Dummy)
}

fn password_matches_configured(path: &Path, password: &str, purpose: Purpose) -> Result<bool> {
    let Some(record) = read_record(path, purpose)? else {
        return Ok(false);
    };
    argon2::verify_raw(
        password.as_bytes(),
        &record.salt,
        &record.verifier,
        &config(purpose),
    )
    .map_err(Into::into)
}

/// A stale, missing or malformed record never prevents normal vault opening and
/// never authorizes destruction. External edits deliberately disarm the trigger.
/// The caller holds the vault lock during ordinary saves.
pub fn refresh_after_save(path: &Path, previous: &[u8], committed: &[u8]) -> Result<()> {
    if !crate::protection::enabled(path)? {
        return Ok(());
    }
    // Try both even if one record is malformed or unavailable. The caller must
    // report any failure as post-commit and check each status after reopening.
    let emergency = refresh_record(path, previous, committed, Purpose::Emergency);
    let dummy = refresh_record(path, previous, committed, Purpose::Dummy);
    emergency?;
    dummy
}

fn refresh_record(path: &Path, previous: &[u8], committed: &[u8], purpose: Purpose) -> Result<()> {
    if !crate::protection::option_enabled(path, purpose.option())? {
        return Ok(());
    }
    let Some(mut record) = read_record(path, purpose)? else {
        return Ok(());
    };
    ensure!(
        previous.len() <= MAX_VAULT && committed.len() <= MAX_VAULT,
        "Oversized vault"
    );
    if record.ciphertext_sha256 != digest(previous)? {
        return Ok(());
    }
    ensure!(
        snapshot_for(path, purpose)? == committed,
        "Vault changed before alternative-password protection could be refreshed"
    );
    record.ciphertext_sha256 = digest(committed)?;
    write_record(path, &record)
}

/// Non-destructive check for callers already holding the vault lock. This does
/// not authorize writing, reveal real contents, or acquire a second flock.
pub fn emergency_matches(path: &Path, password: &str) -> Result<bool> {
    if !crate::protection::option_enabled(path, Purpose::Emergency.option())? {
        return Ok(false);
    }
    Ok(matching_snapshot(path, password, Purpose::Emergency)?.is_some())
}

/// A dummy match must be implemented by the caller as an empty read-only
/// session. The companion record and behavior are forensically distinguishable.
pub fn dummy_matches(path: &Path, password: &str) -> Result<bool> {
    if !crate::protection::option_enabled(path, Purpose::Dummy.option())? {
        return Ok(false);
    }
    Ok(matching_snapshot(path, password, Purpose::Dummy)?.is_some())
}

fn matching_snapshot(path: &Path, password: &str, purpose: Purpose) -> Result<Option<Vec<u8>>> {
    if !crate::protection::option_enabled(path, purpose.option())? {
        return Ok(None);
    }
    let record = match read_record(path, purpose) {
        Ok(Some(record)) => record,
        Ok(None) | Err(_) => return Ok(None),
    };
    let current = match snapshot_for(path, purpose) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    if digest(&current)? != record.ciphertext_sha256 {
        return Ok(None);
    }
    if !argon2::verify_raw(
        password.as_bytes(),
        &record.salt,
        &record.verifier,
        &config(purpose),
    )? {
        return Ok(None);
    }
    if !crate::protection::option_enabled(path, purpose.option())? {
        return Ok(None);
    }
    Ok(Some(current))
}

/// Called before ordinary unlock, while no vault session is open. Returns true
/// only after the complete logical file was overwritten and synced. A matched
/// password with an uncertain/error outcome returns DestructionTriggered.
pub fn check_and_destroy(path: &Path, password: &str) -> Result<bool> {
    if !crate::protection::option_enabled(path, Purpose::Emergency.option())? {
        return Ok(false);
    }
    if !matches!(read_record(path, Purpose::Emergency), Ok(Some(_))) {
        return Ok(false);
    }
    let _lock = crate::vault::acquire_lock(path)?;
    let Some(current) = matching_snapshot(path, password, Purpose::Emergency)? else {
        return Ok(false);
    };
    // After a match, all details use the same outward error: do not reveal the
    // feature through a special error code or claim destruction succeeded.
    destroy_matching(path, &current, Purpose::Emergency.option())
        .map_err(|_| anyhow::Error::new(DestructionTriggered))?;
    Ok(true)
}

pub(crate) fn destroy_matching(
    path: &Path,
    current: &[u8],
    option: crate::protection::OptionKind,
) -> Result<()> {
    ensure!(
        crate::protection::option_enabled(path, option)?,
        "This vault-protection option is disabled"
    );
    ensure!(
        !current.is_empty() && current.len() <= MAX_VAULT,
        "Invalid vault size"
    );
    let mut random = vec![0; current.len()];
    sequoia_openpgp::crypto::random(&mut random)?;
    let mut file = open_private(path, true, false)?;
    let metadata = file.metadata()?;
    ensure!(
        read_bounded(&mut file, MAX_VAULT)? == current,
        "Vault changed before emergency destruction"
    );
    let named = fs::symlink_metadata(path)?;
    validate_private(&named, false)?;
    ensure!(same_file(&metadata, &named), "Vault path changed");
    ensure!(
        crate::protection::option_enabled(path, option)?,
        "This vault-protection option is disabled"
    );
    // Never truncate: every attempted write stays within the original length.
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&random)?;
    file.sync_all()?;
    ensure!(
        file.metadata()?.len() == current.len() as u64,
        "Vault length changed during emergency destruction"
    );
    ensure!(
        same_file(&file.metadata()?, &fs::symlink_metadata(path)?),
        "Vault path changed during emergency destruction"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const PASSWORD: &str = "disposable emergency password";
    const DUMMY_PASSWORD: &str = "disposable dummy password";

    fn fixture() -> Result<(tempfile::TempDir, PathBuf, Vec<u8>)> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("disposable-vault");
        let bytes = vec![0x5a; 8192];
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(&bytes)?;
        crate::protection::enable(&path)?;
        crate::protection::set_option(&path, Purpose::Emergency.option(), true)?;
        crate::protection::set_option(&path, Purpose::Dummy.option(), true)?;
        Ok((dir, path, bytes))
    }

    #[test]
    fn wrong_password_preserves_bytes_and_trigger_preserves_size() -> Result<()> {
        let (_dir, path, original) = fixture()?;
        assert_eq!(status(&path, &original)?, Status::default());
        configure(&path, &original, PASSWORD)?;
        assert_eq!(
            status(&path, &original)?,
            Status {
                configured: true,
                armed: true
            }
        );
        assert!(!check_and_destroy(&path, "wrong password")?);
        assert_eq!(fs::read(&path)?, original);
        assert!(check_and_destroy(&path, PASSWORD)?);
        let destroyed = fs::read(&path)?;
        assert_eq!(destroyed.len(), original.len());
        assert_ne!(destroyed, original);
        assert_eq!(fs::metadata(&path)?.mode() & 0o777, 0o600);
        assert_eq!(
            status(&path, &destroyed)?,
            Status {
                configured: true,
                armed: false
            }
        );
        assert!(!check_and_destroy(&path, PASSWORD)?);
        disable(&path)?;
        assert!(!sidecar_path(&path).exists());
        Ok(())
    }

    #[test]
    fn external_change_disarms_but_ordinary_save_refreshes() -> Result<()> {
        let (_dir, path, original) = fixture()?;
        configure(&path, &original, PASSWORD)?;
        let changed = vec![0xa5; original.len() + 4096];
        fs::write(&path, &changed)?;
        assert_eq!(
            status(&path, &changed)?,
            Status {
                configured: true,
                armed: false
            }
        );
        assert!(!check_and_destroy(&path, PASSWORD)?);
        assert_eq!(fs::read(&path)?, changed);
        refresh_after_save(&path, &changed, &changed)?;
        assert!(!status(&path, &changed)?.armed);
        refresh_after_save(&path, &original, &changed)?;
        assert!(status(&path, &changed)?.armed);
        assert!(check_and_destroy(&path, PASSWORD)?);
        assert_eq!(fs::metadata(&path)?.len(), changed.len() as u64);
        Ok(())
    }

    #[test]
    fn links_and_unsafe_records_never_authorize_destruction() -> Result<()> {
        let (dir, path, original) = fixture()?;
        configure(&path, &original, PASSWORD)?;
        fs::set_permissions(&path, Permissions::from_mode(0o400))?;
        assert!(!status(&path, &original)?.armed);
        assert!(configure(&path, &original, PASSWORD).is_err());
        assert!(!check_and_destroy(&path, PASSWORD)?);
        assert_eq!(fs::read(&path)?, original);
        fs::set_permissions(&path, Permissions::from_mode(0o600))?;
        let record_path = sidecar_path(&path);
        let record_copy = dir.path().join("record-copy");
        fs::rename(&record_path, &record_copy)?;
        std::os::unix::fs::symlink(&record_copy, &record_path)?;
        assert!(!check_and_destroy(&path, PASSWORD)?);
        assert!(disable(&path).is_err());
        assert_eq!(fs::read(&path)?, original);
        fs::remove_file(&record_path)?;
        fs::rename(&record_copy, &record_path)?;
        let symbolic = dir.path().join("vault-symlink");
        std::os::unix::fs::symlink(&path, &symbolic)?;
        fs::copy(&record_path, sidecar_path(&symbolic))?;
        assert!(!check_and_destroy(&symbolic, PASSWORD)?);
        assert_eq!(fs::read(&path)?, original);
        let alias = dir.path().join("vault-hardlink");
        fs::hard_link(&path, &alias)?;
        assert!(!check_and_destroy(&path, PASSWORD)?);
        assert!(configure(&path, &original, PASSWORD).is_err());
        assert_eq!(fs::read(&path)?, original);
        fs::remove_file(&alias)?;
        fs::set_permissions(&record_path, Permissions::from_mode(0o644))?;
        assert!(!check_and_destroy(&path, PASSWORD)?);
        assert!(status(&path, &original).is_err());
        assert_eq!(fs::read(&path)?, original);
        Ok(())
    }

    #[test]
    fn dummy_and_non_destructive_checks_preserve_the_real_file() -> Result<()> {
        let (_dir, path, original) = fixture()?;
        let _lock = crate::vault::acquire_lock(&path)?;
        assert_eq!(dummy_status(&path, &original)?, Status::default());
        configure(&path, &original, PASSWORD)?;
        dummy_configure(&path, &original, DUMMY_PASSWORD)?;
        // These helpers must not acquire another flock or touch real contents.
        assert!(emergency_matches(&path, PASSWORD)?);
        assert!(dummy_matches(&path, DUMMY_PASSWORD)?);
        assert!(!emergency_matches(&path, DUMMY_PASSWORD)?);
        assert!(!dummy_matches(&path, PASSWORD)?);
        assert!(!dummy_matches(&path, "wrong password")?);
        assert_eq!(fs::read(&path)?, original);
        assert_eq!(
            fs::metadata(dummy_sidecar_path(&path))?.mode() & 0o777,
            0o600
        );
        fs::set_permissions(&path, Permissions::from_mode(0o400))?;
        assert!(dummy_status(&path, &original)?.armed);
        assert!(dummy_matches(&path, DUMMY_PASSWORD)?);
        assert!(!emergency_matches(&path, PASSWORD)?);
        assert_eq!(fs::read(&path)?, original);
        fs::set_permissions(&path, Permissions::from_mode(0o600))?;
        dummy_disable(&path)?;
        assert_eq!(dummy_status(&path, &original)?, Status::default());
        assert!(status(&path, &original)?.armed);
        Ok(())
    }

    #[test]
    fn copied_or_retagged_records_cannot_swap_password_purposes() -> Result<()> {
        let (_dir, path, original) = fixture()?;
        configure(&path, &original, PASSWORD)?;
        fs::copy(sidecar_path(&path), dummy_sidecar_path(&path))?;
        assert!(!dummy_matches(&path, PASSWORD)?);
        assert!(dummy_status(&path, &original).is_err());
        let mut copied: serde_json::Value =
            serde_json::from_slice(&fs::read(dummy_sidecar_path(&path))?)?;
        copied["purpose"] = serde_json::json!("dummy");
        fs::write(dummy_sidecar_path(&path), serde_json::to_vec(&copied)?)?;
        // The purpose tag now parses, but Argon2's associated data also binds it.
        assert!(!dummy_matches(&path, PASSWORD)?);
        dummy_configure(&path, &original, DUMMY_PASSWORD)?;
        fs::copy(dummy_sidecar_path(&path), sidecar_path(&path))?;
        assert!(!check_and_destroy(&path, DUMMY_PASSWORD)?);
        copied = serde_json::from_slice(&fs::read(sidecar_path(&path))?)?;
        copied["purpose"] = serde_json::json!("emergency");
        fs::write(sidecar_path(&path), serde_json::to_vec(&copied)?)?;
        assert!(!check_and_destroy(&path, DUMMY_PASSWORD)?);
        assert_eq!(fs::read(&path)?, original);
        Ok(())
    }

    #[test]
    fn ordinary_saves_refresh_both_records_but_external_changes_disarm_them() -> Result<()> {
        let (_dir, path, original) = fixture()?;
        configure(&path, &original, PASSWORD)?;
        dummy_configure(&path, &original, DUMMY_PASSWORD)?;
        let committed = vec![0x31; original.len() + 4096];
        fs::write(&path, &committed)?;
        refresh_after_save(&path, &original, &committed)?;
        assert!(status(&path, &committed)?.armed);
        assert!(dummy_status(&path, &committed)?.armed);
        assert!(emergency_matches(&path, PASSWORD)?);
        assert!(dummy_matches(&path, DUMMY_PASSWORD)?);
        assert_eq!(fs::read(&path)?, committed);
        let outside = vec![0x42; committed.len()];
        fs::write(&path, &outside)?;
        // A stale caller snapshot must not silently rearm either record.
        refresh_after_save(&path, &original, &outside)?;
        assert!(!status(&path, &outside)?.armed);
        assert!(!dummy_status(&path, &outside)?.armed);
        assert!(!emergency_matches(&path, PASSWORD)?);
        assert!(!dummy_matches(&path, DUMMY_PASSWORD)?);
        assert_eq!(fs::read(&path)?, outside);
        Ok(())
    }

    #[test]
    fn disabled_master_blocks_existing_records_and_ignores_broken_refreshes() -> Result<()> {
        let (_dir, path, original) = fixture()?;
        configure(&path, &original, PASSWORD)?;
        dummy_configure(&path, &original, DUMMY_PASSWORD)?;
        let emergency = fs::read(sidecar_path(&path))?;
        let dummy = fs::read(dummy_sidecar_path(&path))?;
        crate::protection::disable(&path)?;
        // Even if a cleanup failed or a companion is restored, its presence
        // alone cannot override the disabled master switch.
        for (record_path, bytes) in [
            (sidecar_path(&path), emergency),
            (dummy_sidecar_path(&path), dummy),
        ] {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(record_path)?;
            file.write_all(&bytes)?;
        }
        assert!(!status(&path, &original)?.armed);
        assert!(!dummy_status(&path, &original)?.armed);
        assert!(!emergency_matches(&path, PASSWORD)?);
        assert!(!dummy_matches(&path, DUMMY_PASSWORD)?);
        assert!(!check_and_destroy(&path, PASSWORD)?);
        assert!(configure(&path, &original, PASSWORD).is_err());
        assert!(dummy_configure(&path, &original, DUMMY_PASSWORD).is_err());
        fs::write(sidecar_path(&path), b"invalid leftover record")?;
        refresh_after_save(&path, &original, &original)?;
        assert_eq!(fs::read(&path)?, original);
        Ok(())
    }

    #[test]
    fn failure_refreshing_one_record_still_refreshes_the_other() -> Result<()> {
        let (_dir, path, original) = fixture()?;
        configure(&path, &original, PASSWORD)?;
        dummy_configure(&path, &original, DUMMY_PASSWORD)?;
        fs::write(sidecar_path(&path), b"invalid emergency record")?;
        let committed = vec![0x54; original.len()];
        fs::write(&path, &committed)?;
        assert!(refresh_after_save(&path, &original, &committed).is_err());
        assert!(dummy_status(&path, &committed)?.armed);
        assert!(dummy_matches(&path, DUMMY_PASSWORD)?);
        assert_eq!(fs::read(&path)?, committed);
        Ok(())
    }

    #[test]
    fn empty_and_short_passwords_use_unique_salts_and_duplicate_checks_include_stale_records()
    -> Result<()> {
        let (_dir, path, original) = fixture()?;
        configure(&path, &original, "")?;
        assert!(emergency_password_matches_configured(&path, "")?);
        assert!(dummy_configure(&path, &original, "").is_err());
        let first: Record = serde_json::from_slice(&fs::read(sidecar_path(&path))?)?;
        configure(&path, &original, "x")?;
        let second: Record = serde_json::from_slice(&fs::read(sidecar_path(&path))?)?;
        assert_ne!(first.salt, second.salt);
        assert_ne!(first.verifier, second.verifier);
        dummy_configure(&path, &original, "y")?;
        assert!(configure(&path, &original, "y").is_err());
        assert!(dummy_password_matches_configured(&path, "y")?);
        assert!(configure(&path, &original, &"x".repeat(129)).is_err());
        let outside = vec![0x7f; original.len()];
        fs::write(&path, &outside)?;
        assert!(!emergency_matches(&path, "x")?);
        assert!(emergency_password_matches_configured(&path, "x")?);
        assert!(dummy_configure(&path, &outside, "x").is_err());
        fs::write(sidecar_path(&path), b"malformed verifier")?;
        assert!(emergency_password_matches_configured(&path, "x").is_err());
        assert!(dummy_configure(&path, &outside, "z").is_err());
        assert_eq!(fs::read(&path)?, outside);
        Ok(())
    }

    #[test]
    fn option_off_erases_verifier_and_on_requires_a_new_password() -> Result<()> {
        let (_dir, path, original) = fixture()?;
        configure(&path, &original, PASSWORD)?;
        dummy_configure(&path, &original, DUMMY_PASSWORD)?;
        let old_record = fs::read(dummy_sidecar_path(&path))?;
        dummy_disable(&path)?;
        assert!(!crate::protection::options(&path)?.dummy);
        assert!(!dummy_sidecar_path(&path).exists());
        assert!(!dummy_matches(&path, DUMMY_PASSWORD)?);
        assert!(dummy_configure(&path, &original, DUMMY_PASSWORD).is_err());
        assert!(emergency_matches(&path, PASSWORD)?);
        // Restoring a stale companion cannot override the separate option flag.
        let mut restored = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dummy_sidecar_path(&path))?;
        restored.write_all(&old_record)?;
        assert!(!dummy_matches(&path, DUMMY_PASSWORD)?);
        crate::protection::set_option(&path, Purpose::Dummy.option(), true)?;
        assert!(!dummy_sidecar_path(&path).exists());
        assert!(!dummy_matches(&path, DUMMY_PASSWORD)?);
        dummy_configure(&path, &original, "new")?;
        assert!(dummy_matches(&path, "new")?);
        assert_eq!(fs::read(&path)?, original);
        Ok(())
    }
}
