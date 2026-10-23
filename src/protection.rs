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

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: u32,
    enabled: bool,
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

fn read(path: &Path) -> Result<bool> {
    let path = sidecar_path(path);
    let Some(expected) = checked_metadata(&path)? else {
        return Ok(false);
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
    let record: Record = serde_json::from_slice(&bytes)?;
    ensure!(record.schema == 1, "Unsupported protection record");
    Ok(record.enabled)
}

/// Trigger checks must fail closed even if a record is corrupt or inaccessible.
pub fn enabled(path: &Path) -> Result<bool> {
    Ok(read(path).unwrap_or(false))
}

fn write(path: &Path, active: bool) -> Result<()> {
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
        schema: 1,
        enabled: active,
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

fn clear_companions(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)?;
    for suffix in COMPANIONS {
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
    write(path, false)?;
    clear_companions(path)?;
    write(path, true)
}

/// Disarm first. A cleanup failure must not leave any optional trigger active.
pub fn disable(path: &Path) -> Result<()> {
    write(path, false)?;
    clear_companions(path)
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
}
