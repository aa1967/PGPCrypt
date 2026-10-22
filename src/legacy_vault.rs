//! Read-only alpha1 recovery. Excluded from the normal worker build.
use crate::vault::{MAX_SIZE, VaultData, acquire_lock, resolve};
use anyhow::{Result, ensure};
use std::path::Path;
use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt};
use zeroize::Zeroizing;

// Only the recovery binary links Debian's libsodium. These are stable C APIs;
// no crypto implementation or native source downloader is bundled here.
mod sodium {
    #[link(name = "sodium")]
    unsafe extern "C" {
        pub fn sodium_init() -> libc::c_int;
        pub fn crypto_pwhash_alg_argon2id13() -> libc::c_int;
        pub fn crypto_pwhash(
            out: *mut u8,
            outlen: u64,
            passwd: *const libc::c_char,
            passwdlen: u64,
            salt: *const u8,
            opslimit: u64,
            memlimit: usize,
            alg: libc::c_int,
        ) -> libc::c_int;
        pub fn crypto_aead_xchacha20poly1305_ietf_decrypt(
            m: *mut u8,
            mlen: *mut u64,
            nsec: *mut u8,
            c: *const u8,
            clen: u64,
            ad: *const u8,
            adlen: u64,
            npub: *const u8,
            k: *const u8,
        ) -> libc::c_int;
    }
}

pub fn read(path: &Path, password: &str) -> Result<VaultData> {
    let path = resolve(path)?;
    let _lock = acquire_lock(&path)?;
    let input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    ensure!(
        input.metadata()?.is_file(),
        "Legacy vault must be a regular file"
    );
    let mut bytes = Vec::new();
    input.take((MAX_SIZE + 65) as u64).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() >= 48 + 16 + 4096
            && bytes.len() <= MAX_SIZE + 64
            && bytes.starts_with(b"PGPVLT01"),
        "Not an alpha1 vault"
    );
    // SAFETY: sodium_init is thread-safe. All buffer sizes below match the old
    // fixed format and libsodium API; no unauthenticated plaintext is parsed.
    ensure!(
        unsafe { sodium::sodium_init() } >= 0,
        "Crypto initialization failed"
    );
    let mut key = Zeroizing::new([0u8; 32]);
    let result = unsafe {
        sodium::crypto_pwhash(
            key.as_mut_ptr(),
            32,
            password.as_ptr().cast(),
            password.len() as u64,
            bytes[8..24].as_ptr(),
            3,
            256 * 1024 * 1024,
            sodium::crypto_pwhash_alg_argon2id13(),
        )
    };
    ensure!(result == 0, "Legacy password derivation failed");
    let ciphertext = &bytes[48..];
    let mut plaintext = Zeroizing::new(vec![0; ciphertext.len() - 16]);
    let mut length = 0;
    let result = unsafe {
        sodium::crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.as_mut_ptr(),
            &mut length,
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            bytes.as_ptr(),
            48,
            bytes[24..48].as_ptr(),
            key.as_ptr(),
        )
    };
    ensure!(result == 0, "Wrong legacy passphrase or damaged vault");
    ensure!(
        length as usize == plaintext.len() && plaintext.len().is_multiple_of(4096),
        "Invalid legacy payload"
    );
    let length = u32::from_le_bytes(plaintext[..4].try_into()?) as usize;
    ensure!(
        length <= plaintext.len() - 4,
        "Invalid legacy payload length"
    );
    Ok(serde_json::from_slice(&plaintext[4..4 + length])?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_fixture_migrates_without_changing_original() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let old = dir.path().join("old.pgpvault");
        let new = dir.path().join("new.pgpcrypt.age");
        let fixture = include_bytes!("../tests/fixtures/legacy-alpha1.pgpvault");
        std::fs::write(&old, fixture)?;
        assert!(read(&old, "wrong").is_err());
        let data = read(&old, "disposable legacy migration passphrase")?;
        assert_eq!(data.notes, "legacy migration fixture note");
        assert_eq!(data.certificates.len(), 1);
        let fingerprint = crate::pgp::parse(&data.certificates[0])?.fingerprint();
        let mut vault = crate::vault::Vault::create(&new, "disposable migrated passphrase")?;
        vault.data = data;
        vault.save()?;
        drop(vault);
        let vault = crate::vault::Vault::open(&new, "disposable migrated passphrase")?;
        assert_eq!(
            crate::pgp::parse(&vault.data.certificates[0])?.fingerprint(),
            fingerprint
        );
        assert_eq!(vault.data.notes, "legacy migration fixture note");
        assert_eq!(std::fs::read(old)?, fixture.as_slice());
        Ok(())
    }
}
