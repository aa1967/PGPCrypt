//! Standard age v1 or KDBX 4.1 encrypted containers; atomic ciphertext persistence.
use age::secrecy::SecretString;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    collections::HashSet,
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

#[derive(Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct RevocationTicket {
    pub fingerprint: String,
    pub armor: String,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Preferences {
    #[serde(default)]
    pub auto_lock: bool,
    #[serde(default)]
    pub lock_on_focus_loss: bool,
    #[serde(default)]
    pub lock_on_session_events: bool,
    #[serde(default)]
    pub clipboard_clear_seconds: u32,
    #[serde(default = "default_theme")]
    pub theme: String,
    #[serde(default)]
    pub qubes_rpc: bool,
}
fn default_theme() -> String {
    "light".into()
}
impl Default for Preferences {
    fn default() -> Self {
        Self {
            auto_lock: false,
            lock_on_focus_loss: false,
            lock_on_session_events: false,
            clipboard_clear_seconds: 0,
            theme: "light".into(),
            qubes_rpc: false,
        }
    }
}
impl Preferences {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.clipboard_clear_seconds == 0 || (5..=1800).contains(&self.clipboard_clear_seconds),
            "Clipboard interval must be disabled or 5 seconds to 30 minutes"
        );
        ensure!(
            matches!(
                self.theme.as_str(),
                "light"
                    | "warm-light"
                    | "dark"
                    | "nord"
                    | "solarized-light"
                    | "solarized-dark"
                    | "solarized"
            ),
            "Unsupported theme"
        );
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub fingerprints: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub id: String,
    pub title: String,
    pub text: String,
    pub profile_id: String,
    pub created_at: u64,
    pub updated_at: u64,
}

pub fn workspace_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    sequoia_openpgp::crypto::random(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn valid_workspace_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn valid_label(label: &str, max: usize) -> bool {
    !label.trim().is_empty() && label.chars().count() <= max && !label.chars().any(char::is_control)
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct VaultData {
    pub certificates: Vec<Vec<u8>>,
    pub notes: String,
    #[serde(default)]
    pub revocations: Vec<RevocationTicket>,
    #[serde(default = "default_timeout")]
    pub idle_timeout_seconds: u32,
    #[serde(default)]
    pub default_signing_key: String,
    #[serde(default)]
    pub preferences: Preferences,
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(default)]
    pub documents: Vec<Document>,
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
            default_signing_key: String::new(),
            preferences: Preferences::default(),
            profiles: Vec::new(),
            documents: Vec::new(),
        }
    }
}

impl VaultData {
    pub fn validate(&self) -> Result<()> {
        self.preferences.validate()?;
        ensure!(
            (60..=3600).contains(&self.idle_timeout_seconds),
            "Unsupported idle timeout"
        );
        ensure!(
            self.profiles.len() <= 64,
            "A vault supports at most 64 profiles"
        );
        ensure!(
            self.documents.len() <= 1024,
            "A vault supports at most 1024 documents"
        );
        let fingerprints = self
            .certificates
            .iter()
            .map(|bytes| crate::pgp::parse(bytes).map(|c| c.fingerprint().to_hex()))
            .collect::<Result<HashSet<_>>>()?;
        let mut ids = HashSet::new();
        let mut names = HashSet::new();
        for profile in &self.profiles {
            ensure!(
                valid_workspace_id(&profile.id) && ids.insert(profile.id.as_str()),
                "Invalid or duplicate profile ID"
            );
            ensure!(
                valid_label(&profile.name, 80)
                    && !profile.name.eq_ignore_ascii_case("all")
                    && profile.name != "+"
                    && names.insert(profile.name.to_lowercase()),
                "Profile names must be unique, 1–80 characters, and different from All or +"
            );
            let mut members = HashSet::new();
            ensure!(
                profile
                    .fingerprints
                    .iter()
                    .all(|fp| fingerprints.contains(fp) && members.insert(fp)),
                "Profile contains a missing or duplicate key"
            );
        }
        let mut document_ids = HashSet::new();
        let mut text_bytes = 0usize;
        for document in &self.documents {
            ensure!(
                valid_workspace_id(&document.id) && document_ids.insert(document.id.as_str()),
                "Invalid or duplicate document ID"
            );
            ensure!(
                valid_label(&document.title, 120),
                "Document titles must contain 1–120 characters without control characters"
            );
            ensure!(
                document.text.len() <= 4 * 1024 * 1024,
                "Document exceeds 4 MiB"
            );
            ensure!(
                document
                    .text
                    .chars()
                    .all(|c| matches!(c, '\t' | '\n' | '\r')
                        || (c >= ' ' && c != '\u{fffe}' && c != '\u{ffff}')),
                "Document contains control characters unsupported by portable KDBX text"
            );
            ensure!(
                document.profile_id.is_empty() || ids.contains(document.profile_id.as_str()),
                "Document refers to a missing profile"
            );
            ensure!(
                document.created_at > 0 && document.updated_at >= document.created_at,
                "Invalid document timestamps"
            );
            text_bytes = text_bytes
                .checked_add(document.text.len())
                .context("Documents are too large")?;
            ensure!(
                text_bytes <= MAX_SIZE,
                "Saved documents exceed the vault size limit"
            );
        }
        Ok(())
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum VaultFormat {
    #[default]
    Age,
    Kdbx,
}
impl VaultFormat {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "" | "age" => Ok(Self::Age),
            "kdbx" => Ok(Self::Kdbx),
            _ => bail!("Unsupported vault format"),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Age => "age",
            Self::Kdbx => "kdbx",
        }
    }
}

pub struct Vault {
    pub data: VaultData,
    path: PathBuf,
    // age regenerates the file key and salt on every save, so its passphrase is
    // retained in a zeroizing secret while unlocked. It never returns to the UI.
    passphrase: SecretString,
    _lock: File,
    format: VaultFormat,
    kdbx: Option<Box<keepass::Database>>,
    // Ciphertext is not secret. Keep the exact bytes last opened or saved so a
    // non-cooperating editor (for example KeePassXC) cannot silently lose a save.
    encrypted_snapshot: RefCell<Vec<u8>>,
    read_only: bool,
}

/// The atomic replacement succeeded, but its directory sync failed. Callers
/// must reopen the committed file before allowing more mutations.
#[derive(Debug)]
pub struct SaveCommitted(std::io::Error);

impl std::fmt::Display for SaveCommitted {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            output,
            "Vault saved, but storage updates could not be completed. Reopen it and check Settings: {}",
            self.0
        )
    }
}

impl std::error::Error for SaveCommitted {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

fn file_error(error: std::io::Error, operation: &str, path: &Path) -> anyhow::Error {
    let hint = if error.kind() == std::io::ErrorKind::PermissionDenied {
        " Choose a folder owned by your user (for example your home folder), and check the permissions of the vault and any existing .lock file. Run PGPCrypt as your normal user."
    } else {
        ""
    };
    anyhow::Error::new(error).context(format!("Cannot {operation} '{}'.{hint}", path.display()))
}

pub(crate) fn acquire_lock(path: &Path) -> Result<File> {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    let lock_path = PathBuf::from(name);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&lock_path)
        .map_err(|error| file_error(error, "create or open the vault lock file", &lock_path))?;
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
        .map_err(|error| file_error(error, "access the vault directory", parent))?;
    Ok(parent.join(path.file_name().context("Choose a vault filename")?))
}

impl Vault {
    pub fn create(path: &Path, password: &str) -> Result<Self> {
        Self::create_format(path, password, VaultFormat::Age)
    }
    pub fn create_format(path: &Path, password: &str, format: VaultFormat) -> Result<Self> {
        Self::create_data(path, password, format, VaultData::default())
    }
    fn create_data(
        path: &Path,
        password: &str,
        format: VaultFormat,
        data: VaultData,
    ) -> Result<Self> {
        ensure!(
            password.chars().count() >= 16,
            "Use at least 16 characters; prefer randomly chosen words"
        );
        let path = resolve(path)?;
        for record in [
            crate::protection::sidecar_path(&path),
            crate::duress::sidecar_path(&path),
            crate::duress::dummy_sidecar_path(&path),
            crate::expiry::sidecar_path(&path),
        ] {
            match fs::symlink_metadata(&record) {
                Ok(_) => bail!(
                    "Protection companion files already exist for this name; choose a different vault filename"
                ),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(file_error(
                        error,
                        "check protection companion files",
                        &record,
                    ));
                }
            }
        }
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() => {
                bail!("Choose a vault filename inside the folder, not the folder itself")
            }
            Ok(_) => bail!(
                "Destination already exists; choose a different filename or open the existing vault"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(file_error(error, "check the destination", &path)),
        }
        let lock = acquire_lock(&path)?;
        ensure!(
            !path.try_exists().map_err(|error| file_error(
                error,
                "check the destination",
                &path
            ))?,
            "Destination already exists; choose a different filename or open the existing vault"
        );
        let vault = Self {
            data,
            path,
            passphrase: SecretString::from(password.to_owned()),
            _lock: lock,
            format,
            kdbx: None,
            encrypted_snapshot: RefCell::new(Vec::new()),
            read_only: false,
        };
        vault.write(true)?;
        Ok(vault)
    }

    pub fn open(path: &Path, password: &str) -> Result<Self> {
        let path = resolve(path)?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| file_error(error, "read the vault file", &path))?;
        ensure!(
            metadata.file_type().is_file(),
            "Choose a regular vault file, not a folder or symbolic link"
        );
        let lock = acquire_lock(&path)?;
        let mut input = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|error| file_error(error, "read the vault file", &path))?;
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
        if bytes.starts_with(crate::kdbx::MAGIC) {
            let (data, db) = crate::kdbx::open(&bytes, password)?;
            return Ok(Self {
                data,
                path,
                passphrase: SecretString::from(password.to_owned()),
                _lock: lock,
                format: VaultFormat::Kdbx,
                kdbx: Some(Box::new(db)),
                encrypted_snapshot: RefCell::new(bytes),
                read_only: false,
            });
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
            stored.application == "PGPCrypt" && matches!(stored.schema, 1..=5),
            "Unsupported vault schema"
        );
        ensure!(
            (60..=3600).contains(&stored.data.idle_timeout_seconds),
            "Unsupported idle timeout"
        );
        stored.data.validate()?;
        Ok(Self {
            data: stored.data,
            path,
            passphrase,
            _lock: lock,
            format: VaultFormat::Age,
            kdbx: None,
            encrypted_snapshot: RefCell::new(bytes),
            read_only: false,
        })
    }

    /// An empty view only: never decrypt the real payload or retain its password.
    /// The caller must first verify the separately configured dummy password.
    pub fn open_empty_read_only(path: &Path) -> Result<Self> {
        let path = resolve(path)?;
        let lock = acquire_lock(&path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&path)?;
        ensure!(file.metadata()?.is_file(), "Choose a regular vault file");
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take((MAX_ENCRYPTED + 1) as u64)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= MAX_ENCRYPTED, "Oversized vault");
        let format = if bytes.starts_with(crate::kdbx::MAGIC) {
            VaultFormat::Kdbx
        } else {
            ensure!(
                bytes.starts_with(b"age-encryption.org/v1"),
                "Vault cannot be opened; it may be damaged"
            );
            VaultFormat::Age
        };
        Ok(Self {
            data: VaultData::default(),
            path,
            passphrase: SecretString::from(String::new()),
            _lock: lock,
            format,
            kdbx: None,
            encrypted_snapshot: RefCell::new(bytes),
            read_only: true,
        })
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    pub fn protection_enabled(&self) -> Result<bool> {
        crate::protection::enabled(&self.path)
    }

    pub fn protection_enable(&self) -> Result<()> {
        ensure!(!self.read_only, "Vault is read-only");
        self.check_unchanged()?;
        crate::protection::enable(&self.path)
    }

    pub fn protection_disable(&self) -> Result<()> {
        ensure!(!self.read_only, "Vault is read-only");
        crate::protection::disable(&self.path)
    }

    pub fn expiry_status(&self) -> Result<crate::expiry::Status> {
        crate::expiry::status(&self.path, &self.encrypted_snapshot.borrow())
    }

    pub fn expiry_configure(&self, count: u32, unit: &str, now: u64) -> Result<()> {
        ensure!(!self.read_only, "Vault is read-only");
        self.check_unchanged()?;
        crate::expiry::configure(
            &self.path,
            &self.encrypted_snapshot.borrow(),
            count,
            unit,
            now,
        )
    }

    pub fn expiry_disable(&self) -> Result<()> {
        ensure!(!self.read_only, "Vault is read-only");
        crate::expiry::disable(&self.path)
    }

    pub fn record_normal_open(&self, now: u64) -> Result<()> {
        ensure!(!self.read_only, "Vault is read-only");
        crate::expiry::record_normal_open(&self.path, &self.encrypted_snapshot.borrow(), now)
    }

    pub fn format(&self) -> VaultFormat {
        self.format
    }

    pub fn emergency_status(&self) -> Result<crate::duress::Status> {
        crate::duress::status(&self.path, &self.encrypted_snapshot.borrow())
    }

    pub fn emergency_configure(&self, password: &str) -> Result<()> {
        use age::secrecy::ExposeSecret;
        ensure!(!self.read_only, "Vault is read-only");
        ensure!(
            password != self.passphrase.expose_secret(),
            "Choose an emergency password different from the vault password"
        );
        self.check_unchanged()?;
        ensure!(
            !crate::duress::dummy_matches(&self.path, password)?,
            "Choose different emergency and dummy passwords"
        );
        crate::duress::configure(&self.path, &self.encrypted_snapshot.borrow(), password)
    }

    pub fn emergency_disable(&self) -> Result<()> {
        ensure!(!self.read_only, "Vault is read-only");
        crate::duress::disable(&self.path)
    }

    pub fn dummy_status(&self) -> Result<crate::duress::Status> {
        crate::duress::dummy_status(&self.path, &self.encrypted_snapshot.borrow())
    }

    pub fn dummy_configure(&self, password: &str) -> Result<()> {
        use age::secrecy::ExposeSecret;
        ensure!(!self.read_only, "Vault is read-only");
        ensure!(
            password != self.passphrase.expose_secret(),
            "Choose a dummy password different from the vault password"
        );
        self.check_unchanged()?;
        ensure!(
            !crate::duress::emergency_matches(&self.path, password)?,
            "Choose different emergency and dummy passwords"
        );
        crate::duress::dummy_configure(&self.path, &self.encrypted_snapshot.borrow(), password)
    }

    pub fn dummy_disable(&self) -> Result<()> {
        ensure!(!self.read_only, "Vault is read-only");
        crate::duress::dummy_disable(&self.path)
    }

    /// Write a distinct encrypted destination; never alter the source.
    /// KDBX -> age carries only PGPCrypt keys, notes and settings.
    pub fn convert_copy(
        &self,
        destination: &Path,
        password: &str,
        format: VaultFormat,
    ) -> Result<()> {
        ensure!(!self.read_only, "Vault is read-only");
        ensure!(
            resolve(destination)? != self.path,
            "Choose a different destination; the source is never replaced"
        );
        let bytes = Zeroizing::new(serde_json::to_vec(&self.data)?);
        let data = serde_json::from_slice(&bytes)?;
        drop(Self::create_data(destination, password, format, data)?);
        Ok(())
    }

    pub fn save(&self) -> Result<()> {
        self.write(false)
    }

    fn check_unchanged(&self) -> Result<()> {
        let changed = "Vault changed outside PGPCrypt. Lock and reopen it before saving; external changes were not overwritten";
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&self.path)
            .context(changed)?;
        ensure!(file.metadata()?.is_file(), "{changed}");
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take((MAX_ENCRYPTED + 1) as u64)
            .read_to_end(&mut bytes)
            .context(changed)?;
        ensure!(bytes == *self.encrypted_snapshot.borrow(), "{changed}");
        Ok(())
    }

    fn write(&self, create: bool) -> Result<()> {
        ensure!(!self.read_only, "Vault is read-only");
        self.data.validate()?;
        if !create {
            self.check_unchanged()?;
        }
        let mut plaintext = Zeroizing::new(serde_json::to_vec(&StoredRef {
            application: "PGPCrypt",
            schema: 5,
            data: &self.data,
        })?);
        let size = plaintext.len().div_ceil(PAD) * PAD;
        ensure!(size <= MAX_SIZE, "Vault exceeds the 16 MiB limit");
        // JSON whitespace padding is encrypted; this is not an encryption header.
        plaintext.resize(size, b' ');
        let parent = self.path.parent().context("Invalid path")?;
        // Obtain the directory handle before committing any ciphertext, so a
        // directory-permission failure is reported before a vault is created.
        let directory = File::open(parent)
            .map_err(|error| file_error(error, "open the vault directory", parent))?;
        let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(|error| {
            file_error(error, "write encrypted data in the vault directory", parent)
        })?;
        match self.format {
            VaultFormat::Kdbx => {
                use age::secrecy::ExposeSecret;
                crate::kdbx::write(
                    &self.data,
                    self.kdbx.as_deref(),
                    self.passphrase.expose_secret(),
                    temp.as_file_mut(),
                )?;
            }
            VaultFormat::Age => {
                let mut recipient = age::scrypt::Recipient::new(self.passphrase.clone());
                recipient.set_work_factor(WORK_FACTOR);
                let encryptor = age::Encryptor::with_recipients(std::iter::once(
                    &recipient as &dyn age::Recipient,
                ))?;
                let mut writer = encryptor.wrap_output(temp.as_file_mut())?;
                writer.write_all(&plaintext)?;
                writer.finish()?;
            }
        }
        temp.as_file().sync_all()?;
        let mut encrypted = Vec::new();
        temp.reopen()?
            .take((MAX_ENCRYPTED + 1) as u64)
            .read_to_end(&mut encrypted)?;
        ensure!(encrypted.len() <= MAX_ENCRYPTED, "Oversized vault");
        if create {
            temp.persist_noclobber(&self.path)
                .map_err(|e| file_error(e.error, "create the vault file", &self.path))?;
        } else {
            // Encryption/KDF work can take seconds; recheck immediately before
            // replacement. An editor that ignores our lock still must not run
            // concurrently: POSIX rename has no compare-and-swap primitive.
            self.check_unchanged()?;
            temp.persist(&self.path)
                .map_err(|e| file_error(e.error, "replace the encrypted vault file", &self.path))?;
        }
        let previous = self.encrypted_snapshot.replace(encrypted);
        directory.sync_all().map_err(SaveCommitted)?;
        if !create {
            crate::duress::refresh_after_save(
                &self.path,
                &previous,
                &self.encrypted_snapshot.borrow(),
            )
            .map_err(|error| SaveCommitted(std::io::Error::other(error.to_string())))?;
            crate::expiry::refresh_after_save(
                &self.path,
                &previous,
                &self.encrypted_snapshot.borrow(),
            )
            .map_err(|error| SaveCommitted(std::io::Error::other(error.to_string())))?;
        }
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
        let certificate = crate::pgp::encode(&crate::pgp::generate("Secret key fixture")?)?;
        vault.data.certificates.push(certificate.to_vec());
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
        assert_eq!(vault.data.certificates[0], *certificate);
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
    fn external_edits_are_not_overwritten() -> Result<()> {
        for format in [VaultFormat::Age, VaultFormat::Kdbx] {
            let dir = tempfile::tempdir()?;
            let path = dir.path().join("vault");
            let external = dir.path().join("external");
            let mut vault = Vault::create_format(&path, PASS, format)?;
            let mut external_data = VaultData::default();
            external_data.notes = "saved by another application".into();
            drop(Vault::create_data(&external, PASS, format, external_data)?);
            let external_bytes = fs::read(&external)?;
            fs::copy(&external, &path)?;
            vault.data.notes = "stale in-memory update".into();
            let error = vault.save().unwrap_err();
            assert!(error.to_string().contains("changed outside PGPCrypt"));
            assert_eq!(fs::read(&path)?, external_bytes);
            fs::remove_file(&path)?;
            assert!(vault.save().is_err(), "deleted vault must not be recreated");
            std::os::unix::fs::symlink(&external, &path)?;
            assert!(vault.save().is_err(), "symlink must not be replaced");
            assert_eq!(fs::read(&external)?, external_bytes);
            fs::remove_file(&path)?;
            fs::copy(&external, &path)?;
            drop(vault);
            assert_eq!(
                Vault::open(&path, PASS)?.data.notes,
                "saved by another application"
            );
        }
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

#[cfg(test)]
mod conversion_tests {
    use super::*;
    #[test]
    fn format_conversion_preserves_source_and_saved_data() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let age = dir.path().join("source.age");
        let kdbx = dir.path().join("portable.kdbx");
        let back = dir.path().join("back.age");
        let pass = "disposable conversion password";
        let mut source = Vault::create(&age, pass)?;
        let (cert, ticket) = crate::pgp::generate_with_options(
            &crate::pgp::KeyOptions {
                name: "Conversion fixture".into(),
                authentication: false,
                email: String::new(),
                comment: String::new(),
                algorithm: "cv25519".into(),
                layout: "subkeys".into(),
                signing: true,
                certification: true,
                transport_encryption: true,
                storage_encryption: true,
                expires_at: None,
            },
            pass,
        )?;
        source
            .data
            .certificates
            .push(crate::pgp::encode(&cert)?.to_vec());
        source.data.revocations.push(RevocationTicket {
            fingerprint: cert.fingerprint().to_hex(),
            armor: ticket.clone(),
        });
        source.data.notes = "conversion note".into();
        source.data.idle_timeout_seconds = 120;
        source.save()?;
        let original = fs::read(&age)?;
        assert!(source.convert_copy(&age, pass, VaultFormat::Kdbx).is_err());
        source.convert_copy(&kdbx, pass, VaultFormat::Kdbx)?;
        assert_eq!(fs::read(&age)?, original);
        assert!(source.convert_copy(&kdbx, pass, VaultFormat::Kdbx).is_err());
        let portable = Vault::open(&kdbx, pass)?;
        assert_eq!(portable.format(), VaultFormat::Kdbx);
        assert_eq!(portable.data.notes, "conversion note");
        assert_eq!(portable.data.idle_timeout_seconds, 120);
        assert_eq!(portable.data.revocations[0].armor, ticket);
        let snapshot = fs::read(&kdbx)?;
        portable.convert_copy(&back, pass, VaultFormat::Age)?;
        assert_eq!(fs::read(&kdbx)?, snapshot);
        let restored = Vault::open(&back, pass)?;
        assert_eq!(restored.data.certificates, source.data.certificates);
        assert_eq!(restored.data.revocations[0].armor, ticket);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(kdbx)?.permissions().mode() & 0o777, 0o600);
        Ok(())
    }
}
