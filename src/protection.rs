//! Explicit master gate for optional PGPCrypt unlock/expiry behaviors.
//! This public flag contains no key material or credentials. Missing, malformed
//! or unsafe markers always disarm the optional behaviors.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, Metadata, OpenOptions, Permissions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const MAX_RECORD: usize = 1024;
const SUFFIX: &str = ".pgpcrypt-protection";
const COMPANIONS: [&str; 3] = [".pgpcrypt-emergency", ".pgpcrypt-dummy", ".pgpcrypt-expiry"];

/// An option can be enabled without having a password or policy configured.
/// These flags are UI permissions, not indicators that a secret has been set.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Options {
    pub emergency: bool,
    pub dummy: bool,
    pub expiry: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OptionKind {
    Emergency,
    Dummy,
    Expiry,
}

impl OptionKind {
    fn suffix(self) -> &'static str {
        match self {
            Self::Emergency => COMPANIONS[0],
            Self::Dummy => COMPANIONS[1],
            Self::Expiry => COMPANIONS[2],
        }
    }
}

impl std::str::FromStr for OptionKind {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        match value {
            "emergency" => Ok(Self::Emergency),
            "dummy" => Ok(Self::Dummy),
            "expiry" => Ok(Self::Expiry),
            _ => anyhow::bail!("Choose an emergency, dummy or expiry option"),
        }
    }
}

impl Options {
    fn get(self, option: OptionKind) -> bool {
        match option {
            OptionKind::Emergency => self.emergency,
            OptionKind::Dummy => self.dummy,
            OptionKind::Expiry => self.expiry,
        }
    }

    fn set(&mut self, option: OptionKind, enabled: bool) {
        match option {
            OptionKind::Emergency => self.emergency = enabled,
            OptionKind::Dummy => self.dummy = enabled,
            OptionKind::Expiry => self.expiry = enabled,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: u32,
    enabled: bool,
    #[serde(default)]
    options: Options,
}

pub fn sidecar_path(path: &Path) -> PathBuf {
    companion(path, SUFFIX)
}

fn companion(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn private_regular(metadata: &Metadata) -> bool {
    // SAFETY: geteuid takes no arguments and cannot fail.
    metadata.file_type().is_file()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.nlink() == 1
        && metadata.mode() & 0o777 == 0o600
}

fn same_file(first: &Metadata, second: &Metadata) -> bool {
    first.dev() == second.dev() && first.ino() == second.ino()
}

fn checked_metadata(path: &Path) -> Result<Option<Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                private_regular(&metadata),
                "Protection records must be regular mode-0600 files owned by your user, without symbolic or hard links: {}",
                path.display()
            );
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn read(vault_path: &Path) -> Result<Record> {
    let path = sidecar_path(vault_path);
    let Some(expected) = checked_metadata(&path)? else {
        return Ok(Record {
            schema: 2,
            enabled: false,
            options: Options::default(),
        });
    };
    ensure!(
        expected.len() <= MAX_RECORD as u64,
        "Oversized protection record"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&path)?;
    let actual = file.metadata()?;
    ensure!(
        private_regular(&actual) && same_file(&expected, &actual),
        "Protection record changed while opening"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((MAX_RECORD + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_RECORD, "Oversized protection record");
    let mut record: Record = serde_json::from_slice(&bytes)?;
    ensure!(
        matches!(record.schema, 1 | 2),
        "Unsupported protection record"
    );
    if record.schema == 1 && record.enabled {
        // Preserve alpha9 behavior during migration. Only safe private records
        // imply an existing toggle; actual trigger checks still validate their
        // contents, purpose and ciphertext binding independently.
        record.options = Options {
            emergency: checked_metadata(&companion(vault_path, COMPANIONS[0]))?.is_some(),
            dummy: checked_metadata(&companion(vault_path, COMPANIONS[1]))?.is_some(),
            expiry: checked_metadata(&companion(vault_path, COMPANIONS[2]))?.is_some(),
        };
    }
    Ok(record)
}

/// Trigger checks must fail closed even if a record is corrupt or inaccessible.
pub fn enabled(path: &Path) -> Result<bool> {
    Ok(read(path).is_ok_and(|record| record.enabled))
}

/// Return only option-toggle choices. No password configuration state is exposed.
pub fn options(path: &Path) -> Result<Options> {
    Ok(match read(path) {
        Ok(record) if record.enabled => record.options,
        _ => Options::default(),
    })
}

pub fn option_enabled(path: &Path, option: OptionKind) -> Result<bool> {
    Ok(options(path)?.get(option))
}

fn write(path: &Path, active: bool, options: Options) -> Result<()> {
    let record_path = sidecar_path(path);
    let expected = checked_metadata(&record_path)?;
    let parent = record_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file()
        .set_permissions(Permissions::from_mode(0o600))?;
    let bytes = serde_json::to_vec(&Record {
        schema: 2,
        enabled: active,
        options,
    })?;
    ensure!(bytes.len() <= MAX_RECORD, "Oversized protection record");
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    let current = checked_metadata(&record_path)?;
    ensure!(
        match (&expected, &current) {
            (None, None) => true,
            (Some(before), Some(now)) => same_file(before, now),
            _ => false,
        },
        "Protection record changed while saving"
    );
    if expected.is_some() {
        temporary
            .persist(&record_path)
            .map_err(|error| error.error)?;
    } else {
        temporary
            .persist_noclobber(&record_path)
            .map_err(|error| error.error)?;
    }
    directory.sync_all()?;
    Ok(())
}

fn clear_companions(path: &Path, suffixes: &[&str]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)?;
    for suffix in suffixes {
        let candidate = companion(path, suffix);
        let Some(expected) = checked_metadata(&candidate).context(
            "Protection is off, but an unsafe companion could not be cleared; check its ownership and permissions before re-enabling",
        )? else {
            continue;
        };
        // Open without following links and compare identities before unlinking.
        // Callers hold the vault lock; an uncooperative writer in the same
        // directory can still race the final path lookup, as with vault saves.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&candidate)?;
        let actual = file.metadata()?;
        let named =
            checked_metadata(&candidate)?.context("Companion disappeared while clearing")?;
        ensure!(
            private_regular(&actual) && same_file(&expected, &actual) && same_file(&actual, &named),
            "Companion changed while clearing; protection remains off"
        );
        fs::remove_file(&candidate)?;
    }
    directory.sync_all()?;
    Ok(())
}

/// Caller holds the vault lock and has authenticated its normal password.
pub fn enable(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        private_regular(&metadata),
        "Enable protection only for a private regular vault file owned by your user"
    );
    if enabled(path)? {
        return Ok(());
    }
    // This ordering prevents old options from silently returning after a
    // disable or interrupted cleanup. A failure leaves the gate off.
    write(path, false, Options::default())?;
    clear_companions(path, &COMPANIONS)?;
    write(path, true, Options::default())
}

/// Disarm first. A cleanup failure must not leave any optional trigger active.
pub fn disable(path: &Path) -> Result<()> {
    write(path, false, Options::default())?;
    clear_companions(path, &COMPANIONS)
}

/// Caller holds the real vault lock. Turning a flag off disarms it before
/// cleanup; turning it on clears stale configuration before enabling editing.
/// Repeating an already-enabled choice preserves its current configuration.
pub fn set_option(path: &Path, option: OptionKind, active: bool) -> Result<()> {
    let mut record = read(path)?;
    ensure!(record.enabled || !active, "Enable vault protection first");
    if active && record.options.get(option) {
        // Upgrade an old master marker without changing active configuration.
        return write(path, true, record.options);
    }
    record.options.set(option, false);
    write(path, record.enabled, record.options)?;
    clear_companions(path, &[option.suffix()])?;
    if active {
        record.options.set(option, true);
        write(path, true, record.options)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Result<(tempfile::TempDir, PathBuf, Vec<u8>)> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("disposable-vault");
        let bytes = b"disposable encrypted fixture bytes".to_vec();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(&bytes)?;
        Ok((directory, path, bytes))
    }

    fn companion_fixture(path: &Path, suffix: &str) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(companion(path, suffix))?;
        file.write_all(b"not a live option; disposable fixture")?;
        Ok(())
    }

    #[test]
    fn master_enable_disable_cleans_only_known_companions() -> Result<()> {
        let (_directory, path, original) = fixture()?;
        assert!(!enabled(&path)?);
        for suffix in COMPANIONS {
            companion_fixture(&path, suffix)?;
        }
        enable(&path)?;
        assert!(enabled(&path)?);
        for suffix in COMPANIONS {
            assert!(!companion(&path, suffix).exists());
        }
        assert_eq!(fs::metadata(sidecar_path(&path))?.mode() & 0o777, 0o600);
        companion_fixture(&path, COMPANIONS[0])?;
        enable(&path)?; // Repeating enable does not erase live configuration.
        assert!(companion(&path, COMPANIONS[0]).exists());
        disable(&path)?;
        assert!(!enabled(&path)?);
        assert!(!companion(&path, COMPANIONS[0]).exists());
        assert_eq!(fs::read(&path)?, original);
        enable(&path)?;
        assert!(enabled(&path)?);
        for suffix in COMPANIONS {
            assert!(!companion(&path, suffix).exists());
        }
        Ok(())
    }

    #[test]
    fn malformed_and_unsafe_markers_fail_closed() -> Result<()> {
        let (directory, path, original) = fixture()?;
        let marker = sidecar_path(&path);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&marker)?;
        file.write_all(b"{malformed}")?;
        assert!(!enabled(&path)?);
        enable(&path)?;
        assert!(enabled(&path)?);
        fs::set_permissions(&marker, Permissions::from_mode(0o644))?;
        assert!(!enabled(&path)?);
        assert!(enable(&path).is_err());
        fs::remove_file(&marker)?;
        let target = directory.path().join("unrelated-file");
        fs::write(&target, b"leave this alone")?;
        std::os::unix::fs::symlink(&target, &marker)?;
        assert!(!enabled(&path)?);
        assert!(disable(&path).is_err());
        assert_eq!(fs::read(&target)?, b"leave this alone");
        assert_eq!(fs::read(&path)?, original);
        Ok(())
    }

    #[test]
    fn unsafe_cleanup_leaves_gate_off_without_removing_target() -> Result<()> {
        let (directory, path, original) = fixture()?;
        enable(&path)?;
        let target = directory.path().join("unrelated-file");
        fs::write(&target, b"leave this alone")?;
        let unsafe_option = companion(&path, COMPANIONS[1]);
        std::os::unix::fs::symlink(&target, &unsafe_option)?;
        assert!(disable(&path).is_err());
        assert!(!enabled(&path)?);
        assert!(enable(&path).is_err());
        assert!(!enabled(&path)?);
        assert_eq!(fs::read(&target)?, b"leave this alone");
        assert_eq!(fs::read(&path)?, original);
        Ok(())
    }

    #[test]
    fn option_flags_do_not_reveal_configuration_and_reenable_erases_old_records() -> Result<()> {
        let (_directory, path, original) = fixture()?;
        enable(&path)?;
        assert_eq!(options(&path)?, Options::default());
        assert!(set_option(&path, OptionKind::Dummy, true).is_ok());
        assert!(options(&path)?.dummy);
        // A checked option still has no configured password; the flags do not
        // distinguish this state from one with a subsequently saved verifier.
        assert!(!companion(&path, COMPANIONS[1]).exists());
        companion_fixture(&path, COMPANIONS[1])?;
        set_option(&path, OptionKind::Dummy, true)?;
        assert!(companion(&path, COMPANIONS[1]).exists());
        set_option(&path, OptionKind::Dummy, false)?;
        assert!(!options(&path)?.dummy);
        assert!(!companion(&path, COMPANIONS[1]).exists());
        companion_fixture(&path, COMPANIONS[1])?; // restored stale record
        set_option(&path, OptionKind::Dummy, true)?;
        assert!(!companion(&path, COMPANIONS[1]).exists());
        disable(&path)?;
        assert_eq!(options(&path)?, Options::default());
        assert!(set_option(&path, OptionKind::Emergency, true).is_err());
        enable(&path)?;
        assert_eq!(options(&path)?, Options::default());
        assert_eq!(fs::read(&path)?, original);
        Ok(())
    }

    #[test]
    fn legacy_marker_preserves_existing_toggles_on_upgrade() -> Result<()> {
        let (_directory, path, _) = fixture()?;
        let mut marker = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(sidecar_path(&path))?;
        marker.write_all(br#"{"schema":1,"enabled":true}"#)?;
        companion_fixture(&path, COMPANIONS[0])?;
        assert!(enabled(&path)?);
        assert!(options(&path)?.emergency);
        assert!(!options(&path)?.dummy);
        set_option(&path, OptionKind::Emergency, true)?;
        assert!(companion(&path, COMPANIONS[0]).exists());
        let upgraded: serde_json::Value = serde_json::from_slice(&fs::read(sidecar_path(&path))?)?;
        assert_eq!(upgraded["schema"], 2);
        assert_eq!(upgraded["options"]["emergency"], true);
        Ok(())
    }

    #[test]
    fn unsafe_option_cleanup_disarms_only_that_toggle_before_reporting_failure() -> Result<()> {
        let (directory, path, original) = fixture()?;
        enable(&path)?;
        set_option(&path, OptionKind::Dummy, true)?;
        set_option(&path, OptionKind::Emergency, true)?;
        let target = directory.path().join("leave-unrelated-file-alone");
        fs::write(&target, b"unrelated contents")?;
        std::os::unix::fs::symlink(&target, companion(&path, COMPANIONS[1]))?;
        assert!(set_option(&path, OptionKind::Dummy, false).is_err());
        assert!(!option_enabled(&path, OptionKind::Dummy)?);
        assert!(option_enabled(&path, OptionKind::Emergency)?);
        assert!(set_option(&path, OptionKind::Dummy, true).is_err());
        assert!(!option_enabled(&path, OptionKind::Dummy)?);
        assert_eq!(fs::read(&target)?, b"unrelated contents");
        assert_eq!(fs::read(&path)?, original);
        Ok(())
    }
}
