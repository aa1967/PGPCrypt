//! Policy for newly chosen passwords. Existing passwords remain unlockable.
use anyhow::{Result, ensure};

pub const MAX_NEW_PASSWORD_CHARS: usize = 128;
// Existing desktop unlock fields accepted at most 32767 UTF-16 code units.
// Keep this comparison bounded while retaining their UTF-8 representation.
const MAX_COMPARISON_BYTES: usize = 128 * 1024;

/// Compare cached credentials without a content-dependent early exit. The
/// established Sequoia comparator does not conceal the lengths of the inputs.
/// This is an in-memory equality check, not a password-storage hash.
pub fn matches(left: &str, right: &str) -> bool {
    if left.len() > MAX_COMPARISON_BYTES || right.len() > MAX_COMPARISON_BYTES {
        return false;
    }
    sequoia_openpgp::crypto::mem::secure_cmp(left.as_bytes(), right.as_bytes())
        == std::cmp::Ordering::Equal
}

/// Count Unicode scalar values consistently with the desktop's UTF-32 count.
/// There is deliberately no minimum length, including for empty passwords.
pub fn validate_new_password(password: &str) -> Result<()> {
    ensure!(
        password.chars().count() <= MAX_NEW_PASSWORD_CHARS,
        "Use at most 128 characters for a new password/passphrase"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_empty_short_and_unicode_but_rejects_overlong_passwords() {
        for password in [String::new(), "x".into(), "🗝".repeat(128)] {
            assert!(validate_new_password(&password).is_ok());
        }
        assert!(validate_new_password(&"x".repeat(129)).is_err());
        assert!(validate_new_password(&"🗝".repeat(129)).is_err());
    }

    #[test]
    fn cached_comparison_accepts_existing_long_passwords_and_matches_exactly() {
        assert!(matches("", ""));
        assert!(matches("🗝", "🗝"));
        assert!(!matches("x", "xx"));
        assert!(!matches("correct", "correcu"));
        let old = "x".repeat(1024);
        assert!(matches(&old, &old));
        let oversized = "x".repeat(MAX_COMPARISON_BYTES + 1);
        assert!(!matches(&oversized, &oversized));
    }
}
