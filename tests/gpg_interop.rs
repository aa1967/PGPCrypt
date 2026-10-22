//! GnuPG is only an isolated test peer. Production never spawns it.
use anyhow::{Context, Result, ensure};
use pgpcrypt::pgp;
use std::{
    io::Write,
    process::{Command, Stdio},
};

struct GpgHome(tempfile::TempDir);
impl GpgHome {
    fn command(&self, args: &[&str], input: &[u8]) -> Result<Vec<u8>> {
        let mut child = Command::new("gpg")
            .arg("--homedir")
            .arg(self.0.path())
            .args([
                "--batch",
                "--no-tty",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
            ])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Install GnuPG to run interoperability tests")?;
        child.stdin.take().unwrap().write_all(input)?;
        let output = child.wait_with_output()?;
        ensure!(
            output.status.success(),
            "GnuPG test peer failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(output.stdout)
    }
}
impl Drop for GpgHome {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .arg("--homedir")
            .arg(self.0.path())
            .args(["--kill", "gpg-agent"])
            .output();
    }
}

#[test]
fn encrypt_decrypt_and_sign_verify_with_gnupg() -> Result<()> {
    let home = GpgHome(tempfile::tempdir()?);
    let cert = pgp::generate("Interop Fixture <interop@example.invalid>")?;
    let fingerprint = cert.fingerprint().to_hex();
    home.command(&["--import"], &pgp::encode(&cert)?)?;
    let text = "Disposable cross-implementation test\n";

    let encrypted = pgp::encrypt(text, std::slice::from_ref(&cert))?;
    assert_eq!(
        home.command(&["--decrypt"], encrypted.as_bytes())?,
        text.as_bytes()
    );

    let encrypted = home.command(
        &[
            "--trust-model",
            "always",
            "--armor",
            "--recipient",
            &fingerprint,
            "--encrypt",
        ],
        text.as_bytes(),
    )?;
    let decrypted = pgp::decrypt(std::str::from_utf8(&encrypted)?, vec![cert.clone()], "")?;
    assert_eq!(decrypted.text.as_str(), text);

    let signed = pgp::sign(text, &cert, "")?;
    assert_eq!(
        home.command(&["--decrypt"], signed.as_bytes())?,
        text.as_bytes()
    );
    let signed = home.command(
        &["--armor", "--local-user", &fingerprint, "--sign"],
        text.as_bytes(),
    )?;
    let verified = pgp::verify(std::str::from_utf8(&signed)?, vec![cert.clone()])?;
    assert_eq!(verified.text.as_str(), text);
    assert_eq!(
        verified.signers.as_slice(),
        std::slice::from_ref(&fingerprint)
    );

    let signed = home.command(
        &["--armor", "--local-user", &fingerprint, "--clearsign"],
        text.as_bytes(),
    )?;
    let verified = pgp::verify(std::str::from_utf8(&signed)?, vec![cert.clone()])?;
    assert_eq!(verified.signers, [fingerprint]);
    let damaged = String::from_utf8(signed)?.replace("Disposable", "Manipulated");
    assert!(
        pgp::verify(&damaged, vec![cert]).is_err(),
        "modified signed content must fail"
    );
    Ok(())
}
