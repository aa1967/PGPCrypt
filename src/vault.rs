//! Standard age v1 passphrase encryption; no application-defined crypto framing.
use age::secrecy::SecretString;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const MAX_SIZE: usize = 16 * 1024 * 1024;
const MAX_ENCRYPTED: usize = MAX_SIZE + 1024 * 1024;
const PAD: usize = 4096;
// age's scrypt profile uses r=8,p=1. N=2^18 needs approximately 256 MiB.
// Set an explicit cost independent of compiler optimization/hardware calibration.
const WORK_FACTOR: u8 = 18;

#[derive(Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct RevocationTicket {
    pub fingerprint: String,
    pub armor: String,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct VaultData {
    pub certificates: Vec<Vec<u8>>,
    pub notes: String,
    #[serde(default)]
    pub revocations: Vec<RevocationTicket>,
    #[serde(default = "default_timeout")]
    pub idle_timeout_seconds: u32,
}

fn default_timeout() -> u32 {
    300
}

impl Default for VaultData {
    fn default() -> Self {
        Self {
            certificates: Vec::new(),
            notes: String::new(),
            revocations: Vec::new(),
            idle_timeout_seconds: default_timeout(),
        }
    }
}

#[derive(Serialize)]
struct StoredRef<'a> {
    application: &'static str,
    schema: u32,
    data: &'a VaultData,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    application: String,
    schema: u32,
    data: VaultData,
}

pub struct Vault {
    pub data: VaultData,
    path: PathBuf,
    // age regenerates the file key and salt on every save, so its passphrase is
    // retained in a zeroizing secret while unlocked. It never returns to the UI.
    passphrase: SecretString,
    _lock: File,
}

pub(crate) fn acquire_lock(path: &Path) -> Result<File> {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(PathBuf::from(name))?;
    use std::os::fd::AsRawFd;
    // SAFETY: file owns a valid descriptor; closing it releases the advisory lock.
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "Vault is already open in another process"
    );
    Ok(file)
}

pub(crate) fn resolve(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = parent
        .canonicalize()
        .context("Vault directory does not exist")?;
    Ok(parent.join(path.file_name().context("Choose a vault filename")?))
}

impl Vault {
    pub fn create(path: &Path, password: &str) -> Result<Self> {
        ensure!(
            password.chars().count() >= 16,
            "Use at least 16 characters; prefer randomly chosen words"
        );
        let path = resolve(path)?;
        let lock = acquire_lock(&path)?;
        ensure!(!path.try_exists()?, "Destination already exists");
        let vault = Self {
            data: VaultData::default(),
            path,
            passphrase: SecretString::from(password.to_owned()),
            _lock: lock,
        };
        vault.write(true)?;
        Ok(vault)
    }

    pub fn open(path: &Path, password: &str) -> Result<Self> {
        let path = resolve(path)?;
        let lock = acquire_lock(&path)?;
        let mut input = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&path)?;
        ensure!(input.metadata()?.is_file(), "Vault must be a regular file");
        let mut bytes = Vec::new();
        Read::by_ref(&mut input)
            .take((MAX_ENCRYPTED + 1) as u64)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= MAX_ENCRYPTED, "Oversized vault");
        if bytes.starts_with(b"PGPVLT01") {
            bail!(
                "Legacy alpha1 vault: use pgpcrypt-migrate to create a new age vault; the original is unchanged"
            );
        }
        let decryptor = age::Decryptor::new_buffered(bytes.as_slice())
            .context("Not a supported age v1 vault")?;
        ensure!(
            decryptor.is_scrypt(),
            "Vault requires age passphrase encryption"
        );
        let passphrase = SecretString::from(password.to_owned());
        let mut identity = age::scrypt::Identity::new(passphrase.clone());
        identity.set_max_work_factor(WORK_FACTOR);
        let reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .context(
                "Could not unlock: wrong passphrase, damaged vault, or unsupported KDF cost",
            )?;
        let mut plaintext = Zeroizing::new(Vec::new());
        reader
            .take((MAX_SIZE + 1) as u64)
            .read_to_end(&mut plaintext)
            .context("Vault authentication failed")?;
        ensure!(plaintext.len() <= MAX_SIZE, "Vault payload exceeds 16 MiB");
        // No decoded data is exposed until the complete age stream authenticates.
        let stored: Stored = serde_json::from_slice(&plaintext).context("Invalid vault schema")?;
        ensure!(
            stored.application == "PGPCrypt" && matches!(stored.schema, 1 | 2),
            "Unsupported vault schema"
        );
        ensure!(
            (60..=3600).contains(&stored.data.idle_timeout_seconds),
            "Unsupported idle timeout"
        );
        Ok(Self {
            data: stored.data,
            path,
            passphrase,
            _lock: lock,
        })
    }

    pub fn save(&self) -> Result<()> {
        self.write(false)
    }

    fn write(&self, create: bool) -> Result<()> {
        let mut plaintext = Zeroizing::new(serde_json::to_vec(&StoredRef {
            application: "PGPCrypt",
            schema: 2,
            data: &self.data,
        })?);
        let size = plaintext.len().div_ceil(PAD) * PAD;
        ensure!(size <= MAX_SIZE, "Vault exceeds the 16 MiB limit");
        // JSON whitespace padding is encrypted; this is not an encryption header.
        plaintext.resize(size, b' ');
        let parent = self.path.parent().context("Invalid path")?;
        let mut temp = tempfile::NamedTempFile::new_in(parent)?;
        let mut recipient = age::scrypt::Recipient::new(self.passphrase.clone());
        recipient.set_work_factor(WORK_FACTOR);
        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))?;
        let mut writer = encryptor.wrap_output(temp.as_file_mut())?;
        writer.write_all(&plaintext)?;
        writer.finish()?;
        temp.as_file().sync_all()?;
        if create {
            temp.persist_noclobber(&self.path).map_err(|e| e.error)?;
        } else {
            if fs::symlink_metadata(&self.path)?.file_type().is_symlink() {
                bail!("Refusing symlink destination");
            }
            temp.persist(&self.path).map_err(|e| e.error)?;
        }
        File::open(parent)?.sync_all()?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PASS: &str = "disposable test passphrase only";

    #[test]
    fn roundtrip_privacy_and_integrity() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("test.pgpcrypt.age");
        let mut vault = Vault::create(&path, PASS)?;
        vault.data.notes = "Alice secret metadata alice@example.invalid".into();
        vault.data.certificates.push(b"secret key fixture".to_vec());
        vault.save()?;
        let first = fs::read(&path)?;
        assert!(first.starts_with(b"age-encryption.org/v1\n"));
        assert!(!first.windows(5).any(|w| w == b"Alice"));
        assert!(!first.windows(7).any(|w| w == b"fixture"));
        assert!(Vault::open(&path, PASS).is_err(), "second writer must fail");
        vault.save()?;
        assert_ne!(
            first,
            fs::read(&path)?,
            "fresh age encryption on every save"
        );
        drop(vault);
        assert!(Vault::open(&path, "wrong passphrase").is_err());
        let vault = Vault::open(&path, PASS)?;
        assert_eq!(
            vault.data.notes,
            "Alice secret metadata alice@example.invalid"
        );
        assert_eq!(vault.data.certificates[0], b"secret key fixture");
        drop(vault);
        for index in [24, first.len() / 2, first.len() - 1] {
            let mut damaged = first.clone();
            damaged[index] ^= 1;
            fs::write(&path, damaged)?;
            assert!(Vault::open(&path, PASS).is_err(), "tampering at {index}");
        }
        fs::write(&path, &first[..first.len() - 1])?;
        assert!(Vault::open(&path, PASS).is_err());
        let mut appended = first.clone();
        appended.push(0);
        fs::write(&path, appended)?;
        assert!(Vault::open(&path, PASS).is_err());
        Ok(())
    }

    #[test]
    fn creation_and_path_guards() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("vault");
        assert!(Vault::create(&path, "short").is_err());
        let vault = Vault::create(&path, PASS)?;
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        drop(vault);
        assert!(Vault::create(&path, PASS).is_err());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link)?;
        assert!(Vault::open(&link, PASS).is_err());
        Ok(())
    }

    #[test]
    fn legacy_vault_is_rejected_without_modification() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("legacy.pgpvault");
        let original = include_bytes!("../tests/fixtures/legacy-alpha1.pgpvault");
        fs::write(&path, original)?;
        assert!(
            Vault::open(&path, PASS)
                .err()
                .unwrap()
                .to_string()
                .contains("pgpcrypt-migrate")
        );
        assert_eq!(fs::read(path)?, original.as_slice());
        Ok(())
    }

    #[test]
    fn excessive_kdf_cost_is_rejected_before_derivation() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("cost.pgpcrypt.age");
        drop(Vault::create(&path, PASS)?);
        let mut bytes = fs::read(&path)?;
        let cost = bytes.windows(4).position(|part| part == b" 18\n").unwrap();
        bytes[cost + 1] = b'5'; // N=2^58 must not trigger a giant allocation.
        fs::write(&path, bytes)?;
        let error = Vault::open(&path, PASS).err().unwrap();
        assert!(matches!(
            error.downcast_ref::<age::DecryptError>(),
            Some(age::DecryptError::ExcessiveWork { .. })
        ));
        Ok(())
    }
}
