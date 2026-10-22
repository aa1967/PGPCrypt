//! Explicit one-way recovery; the application never opens the old crypto format.
use anyhow::{Result, ensure};
use std::path::Path;
use zeroize::Zeroizing;

fn main() -> Result<()> {
    pgpcrypt::harden_process()?;
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() == 2 && args[1] == "--help" {
        println!(
            "Usage: pgpcrypt-migrate OLD.pgpvault NEW.pgpcrypt.age\nPassphrases are prompted privately. The old file is never overwritten."
        );
        return Ok(());
    }
    ensure!(
        args.len() == 3,
        "Usage: pgpcrypt-migrate OLD.pgpvault NEW.pgpcrypt.age"
    );
    let old = Path::new(&args[1]);
    let new = Path::new(&args[2]);
    ensure!(!new.try_exists()?, "Destination already exists");
    let password = Zeroizing::new(rpassword::prompt_password("Old vault passphrase: ")?);
    let data = pgpcrypt::legacy_vault::read(old, &password)?;
    drop(password);
    let password = Zeroizing::new(rpassword::prompt_password(
        "New vault passphrase (16+ characters): ",
    )?);
    let confirmation = Zeroizing::new(rpassword::prompt_password("Confirm new passphrase: ")?);
    ensure!(*password == *confirmation, "Passphrases do not match");
    drop(confirmation);
    let mut vault = pgpcrypt::vault::Vault::create(new, &password)?;
    vault.data = data;
    vault.save()?;
    println!(
        "Migration completed. Original vault unchanged. Verify the new vault before retiring the backup."
    );
    Ok(())
}
