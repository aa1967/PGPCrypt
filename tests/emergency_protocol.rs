//! All destruction in this test is restricted to fresh disposable TempDirs.
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::fs::PermissionsExt,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

struct Peer {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    sequence: u64,
}
impl Peer {
    fn new() -> Result<Self> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_pgpcrypt-worker"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        Ok(Self {
            input: child.stdin.take().unwrap(),
            output: BufReader::new(child.stdout.take().unwrap()),
            child,
            sequence: 0,
        })
    }
    fn raw(&mut self, op: &str, mut data: Value) -> Result<Value> {
        self.sequence += 1;
        data["id"] = json!(self.sequence);
        data["op"] = json!(op);
        serde_json::to_writer(&mut self.input, &data)?;
        self.input.write_all(b"\n")?;
        self.input.flush()?;
        let mut line = String::new();
        self.output.read_line(&mut line)?;
        let response: Value = serde_json::from_str(&line)?;
        ensure!(response["id"] == self.sequence, "Incorrect response ID");
        Ok(response)
    }
    fn ok(&mut self, op: &str, data: Value) -> Result<Value> {
        let response = self.raw(op, data)?;
        ensure!(
            response["ok"] == true,
            "Operation failed: {}",
            response["error"]
        );
        Ok(response["data"].clone())
    }
    fn lock(&mut self) -> Result<()> {
        self.ok("lock", json!({}))?;
        ensure!(
            self.child.wait()?.success(),
            "Worker did not exit after lock"
        );
        Ok(())
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn emergency_configuration_save_refresh_disable_and_trigger() -> Result<()> {
    let normal = "disposable normal vault password";
    let emergency = "different disposable emergency password";
    for format in ["age", "kdbx"] {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("disposable-vault");
        let copy = dir.path().join("separate-copy");
        let mut peer = Peer::new()?;
        peer.ok(
            "create",
            json!({"path":path,"password":normal,"format":format}),
        )?;
        assert_eq!(
            peer.ok("emergency_status", json!({}))?,
            json!({"configured":false,"armed":false})
        );
        assert_eq!(peer.ok("protection_status", json!({}))?["enabled"], false);
        assert_eq!(
            peer.raw("emergency_set", json!({"new_password":emergency}))?["ok"],
            false,
            "master-off must reject configuration"
        );
        peer.ok("protection_enable", json!({}))?;
        assert_eq!(
            peer.ok("protection_status", json!({}))?["emergency_enabled"],
            false
        );
        assert_eq!(
            peer.raw("emergency_set", json!({"new_password":emergency}))?["ok"],
            false,
            "an unchecked option must reject configuration"
        );
        peer.ok(
            "protection_option_enable",
            json!({"protection_option":"emergency"}),
        )?;
        let too_long = "x".repeat(129);
        for rejected in [normal, too_long.as_str()] {
            assert_eq!(
                peer.raw("emergency_set", json!({"new_password":rejected}))?["ok"],
                false
            );
        }
        assert!(!pgpcrypt::duress::sidecar_path(&path).exists());
        peer.ok("emergency_set", json!({"new_password":emergency}))?;
        let record = pgpcrypt::duress::sidecar_path(&path);
        assert_eq!(fs::metadata(&record)?.permissions().mode() & 0o777, 0o600);
        assert!(!fs::read_to_string(&record)?.contains(emergency));
        let original = fs::read(&path)?;
        peer.lock()?;
        let mut peer = Peer::new()?;
        assert_eq!(
            peer.raw(
                "open",
                json!({"path":path,"password":"ordinary wrong password"})
            )?["ok"],
            false
        );
        assert_eq!(fs::read(&path)?, original);
        peer.ok("open", json!({"path":path,"password":normal}))?;
        peer.ok(
            "document_save",
            json!({"title":"Disposable saved document","text":"Inside encrypted vault"}),
        )?;
        assert_eq!(
            peer.ok("emergency_status", json!({}))?["armed"],
            true,
            "a normal save must refresh the binding"
        );
        assert_ne!(fs::read(&path)?, original);
        peer.ok(
            "convert_copy",
            json!({"path":copy,"password":normal,"format":format}),
        )?;
        assert!(
            !pgpcrypt::duress::sidecar_path(&copy).exists(),
            "conversion must not arm its destination"
        );
        peer.ok(
            "protection_option_disable",
            json!({"protection_option":"emergency"}),
        )?;
        assert!(!record.exists());
        peer.ok(
            "protection_option_enable",
            json!({"protection_option":"emergency"}),
        )?;
        assert!(
            !record.exists(),
            "enabling must not restore an old password"
        );
        peer.ok("emergency_set", json!({"new_password":emergency}))?;
        let before = fs::read(&path)?;
        peer.lock()?;
        let mut trigger = Peer::new()?;
        let response = trigger.raw("open", json!({"path":path,"password":emergency}))?;
        assert_eq!(response["ok"], false);
        assert_eq!(response["code"], "operation_failed");
        assert_eq!(
            response["error"],
            "Vault cannot be opened; it may be damaged"
        );
        assert!(
            trigger.child.wait()?.success(),
            "triggered worker must terminate"
        );
        let after = fs::read(&path)?;
        assert_eq!(after.len(), before.len());
        assert_ne!(after, before);
        assert!(pgpcrypt::vault::Vault::open(&path, normal).is_err());
        assert!(fs::metadata(&copy)?.len() > 0, "separate copy is retained");
    }
    Ok(())
}

#[test]
fn dummy_password_is_an_empty_read_only_view_and_never_changes_the_real_vault() -> Result<()> {
    let normal = "disposable real vault password";
    let dummy = "disposable separate dummy password";
    let emergency = "disposable separate destruction password";
    for format in ["age", "kdbx"] {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("real-vault");
        let mut peer = Peer::new()?;
        peer.ok(
            "create",
            json!({"path":path,"format":format,"password":normal}),
        )?;
        peer.ok("generate",json!({"key_options":{"name":"Private real identity","algorithm":"cv25519","layout":"subkeys","signing":true,"certification":true,"transport_encryption":true,"storage_encryption":true,"expires_at":null}}))?;
        let fingerprint = peer.ok("list", json!({}))?["keys"][0]["fingerprint"].clone();
        peer.ok(
            "profile_save",
            json!({"profile_name":"Private profile","profile_fingerprints":[fingerprint]}),
        )?;
        let document = peer.ok(
            "document_save",
            json!({"title":"Real saved message","text":"Only in the real vault"}),
        )?["id"]
            .clone();
        peer.ok("protection_enable", json!({}))?;
        for option in ["dummy", "emergency"] {
            peer.ok(
                "protection_option_enable",
                json!({"protection_option":option}),
            )?;
        }
        assert_eq!(
            peer.raw("dummy_set", json!({"new_password":normal}))?["ok"],
            false
        );
        peer.ok("dummy_set", json!({"new_password":dummy}))?;
        assert_eq!(
            peer.raw("emergency_set", json!({"new_password":dummy}))?["ok"],
            false
        );
        peer.ok("emergency_set", json!({"new_password":emergency}))?;
        assert_eq!(
            peer.raw("dummy_set", json!({"new_password":emergency}))?["ok"],
            false
        );
        let before = fs::read(&path)?;
        peer.lock()?;
        let mut empty = Peer::new()?;
        assert_eq!(
            empty.ok("open", json!({"path":path,"password":dummy}))?["read_only"],
            true
        );
        assert_eq!(
            empty.ok("status", json!({}))?,
            json!({"unlocked":true}),
            "ordinary status must not identify an alternative-password session"
        );
        assert_eq!(empty.ok("list", json!({}))?["keys"], json!([]));
        assert_eq!(empty.ok("profiles_list", json!({}))?["profiles"], json!([]));
        assert_eq!(
            empty.ok("documents_list", json!({}))?["documents"],
            json!([])
        );
        assert_eq!(empty.ok("notes_get", json!({}))?["text"], "");
        for (operation, fields) in [
            ("notes_set", json!({"text":"must not overwrite real data"})),
            (
                "document_save",
                json!({"title":"Unsafe update","text":"must fail"}),
            ),
            ("profile_save", json!({"profile_name":"must fail"})),
            ("protection_disable", json!({})),
            ("emergency_disable", json!({})),
            ("dummy_disable", json!({})),
            ("expiry_disable", json!({})),
            ("settings_set", json!({"default_signing_key":""})),
        ] {
            assert_eq!(
                empty.raw(operation, fields)?["ok"],
                false,
                "read-only operation {operation}"
            );
        }
        assert_eq!(
            empty.raw("document_get", json!({"document_id":document}))?["ok"],
            false
        );
        assert_eq!(fs::read(&path)?, before);
        empty.lock()?;
        let mut real = Peer::new()?;
        assert_eq!(
            real.ok("open", json!({"path":path,"password":normal}))?["read_only"],
            false
        );
        assert_eq!(
            real.ok("list", json!({}))?["keys"][0]["fingerprint"],
            fingerprint
        );
        assert_eq!(
            real.ok("document_get", json!({"document_id":document}))?["text"],
            "Only in the real vault"
        );
        real.ok("protection_disable", json!({}))?;
        assert!(!pgpcrypt::duress::sidecar_path(&path).exists());
        assert!(!pgpcrypt::duress::dummy_sidecar_path(&path).exists());
        assert_eq!(fs::read(&path)?, before);
        real.lock()?;
        let mut disabled = Peer::new()?;
        assert_eq!(
            disabled.raw("open", json!({"path":path,"password":dummy}))?["ok"],
            false
        );
        assert_eq!(fs::read(&path)?, before);
    }
    Ok(())
}

#[test]
fn inactivity_resets_on_normal_unlock_and_destroys_before_decryption_when_overdue() -> Result<()> {
    use pgpcrypt::vault::{Vault, VaultFormat};
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let normal = "disposable inactivity vault password";
    for format in [VaultFormat::Age, VaultFormat::Kdbx] {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("time-gated-vault");
        let vault = Vault::create_format(&path, normal, format)?;
        vault.protection_enable()?;
        pgpcrypt::protection::set_option(
            vault.path(),
            pgpcrypt::protection::OptionKind::Expiry,
            true,
        )?;
        vault.expiry_configure(1, "days", now - 3600)?;
        drop(vault);
        let before = fs::read(&path)?;
        let mut peer = Peer::new()?;
        peer.ok("open", json!({"path":path,"password":normal}))?;
        let status = peer.ok("expiry_status", json!({}))?;
        assert!(status["last_opened_at"].as_u64().unwrap() >= now);
        assert_eq!(
            status["deadline"].as_u64().unwrap(),
            status["last_opened_at"].as_u64().unwrap() + 86400
        );
        peer.lock()?;
        assert_eq!(
            fs::read(&path)?,
            before,
            "normal unlock only updates its policy record"
        );
        let vault = Vault::open(&path, normal)?;
        vault.expiry_configure(1, "days", now - 2 * 86400)?;
        drop(vault);
        let mut trigger = Peer::new()?;
        // A wrong password still triggers the overdue policy before any vault
        // decryption or password authentication. Never use a real file here.
        let response = trigger.raw(
            "open",
            json!({"path":path,"password":"not the normal password"}),
        )?;
        assert_eq!(response["ok"], false);
        assert_eq!(response["code"], "operation_failed");
        assert_eq!(
            response["error"],
            "Vault cannot be opened; it may be damaged"
        );
        assert!(trigger.child.wait()?.success());
        let after = fs::read(&path)?;
        assert_eq!(after.len(), before.len());
        assert_ne!(after, before);
        assert!(Vault::open(&path, normal).is_err());
    }
    Ok(())
}

#[test]
fn option_toggles_reset_passwords_without_revealing_or_resurrecting_configuration() -> Result<()> {
    // Every path is a disposable fixture; the real user vault is never opened.
    for format in ["age", "kdbx"] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("toggle-fixture");
        let normal = "n";
        let mut peer = Peer::new()?;
        peer.ok(
            "create",
            json!({"path":path,"format":format,"password":normal}),
        )?;
        peer.ok("document_save", json!({"text":"Real private content"}))?;
        peer.ok("protection_enable", json!({}))?;
        for option in ["dummy", "emergency", "expiry"] {
            peer.ok(
                "protection_option_enable",
                json!({"protection_option":option}),
            )?;
        }
        // Empty and one-character alternatives have no minimum, but must differ
        // from the main password and every other configured alternative.
        peer.ok("dummy_set", json!({"new_password":""}))?;
        assert_eq!(
            peer.raw("emergency_set", json!({"new_password":""}))?["ok"],
            false
        );
        peer.ok("emergency_set", json!({"new_password":"x"}))?;
        assert_eq!(
            peer.raw("dummy_set", json!({"new_password":"x"}))?["ok"],
            false
        );
        peer.ok(
            "expiry_set",
            json!({"expiry_count":2,"expiry_unit":"weeks"}),
        )?;
        let snapshot = fs::read(&path)?;
        peer.lock()?;
        let mut blank = Peer::new()?;
        assert_eq!(
            blank.ok("open", json!({"path":path,"password":""}))?["read_only"],
            true
        );
        assert_eq!(
            blank.ok("documents_list", json!({}))?["documents"],
            json!([])
        );
        assert_eq!(
            blank.raw(
                "document_properties",
                json!({"document_id":"missing","title":"changed"})
            )?["ok"],
            false
        );
        blank.lock()?;
        assert_eq!(fs::read(&path)?, snapshot);
        let mut peer = Peer::new()?;
        peer.ok("open", json!({"path":path,"password":normal}))?;
        let record_path = pgpcrypt::duress::dummy_sidecar_path(&path);
        let previous: Value = serde_json::from_slice(&fs::read(&record_path)?)?;
        // Reset requires no knowledge of the old alternative. A fresh random
        // salt is generated even when reusing the same option's password.
        peer.ok("dummy_set", json!({"new_password":"y"}))?;
        let mut replacement: Value = serde_json::from_slice(&fs::read(&record_path)?)?;
        assert_ne!(replacement["salt"], previous["salt"]);
        assert_ne!(replacement["verifier"], previous["verifier"]);
        assert_eq!(replacement["salt"].as_array().unwrap().len(), 16);
        assert_eq!(replacement["verifier"].as_array().unwrap().len(), 32);
        // A stale binding must not let a second option reuse a configured
        // password: duplicate validation is independent of trigger matching.
        replacement["ciphertext_sha256"] = json!(vec![0u8; 32]);
        fs::write(&record_path, serde_json::to_vec(&replacement)?)?;
        assert_eq!(
            peer.raw("emergency_set", json!({"new_password":"y"}))?["ok"],
            false
        );
        peer.ok("dummy_set", json!({"new_password":"y"}))?;
        let status = peer.ok("protection_status", json!({}))?;
        assert_eq!(status["enabled"], true);
        assert_eq!(status["dummy_enabled"], true);
        assert_eq!(status["emergency_enabled"], true);
        assert_eq!(status["expiry_enabled"], true);
        for property in [
            "password",
            "new_password",
            "salt",
            "verifier",
            "configured",
            "armed",
        ] {
            assert!(status.get(property).is_none(), "status exposed {property}");
        }
        peer.ok(
            "protection_option_disable",
            json!({"protection_option":"dummy"}),
        )?;
        assert!(!record_path.exists());
        peer.ok(
            "protection_option_enable",
            json!({"protection_option":"dummy"}),
        )?;
        assert!(
            !record_path.exists(),
            "checking the option must start empty"
        );
        assert_eq!(
            peer.ok("protection_status", json!({}))?["dummy_enabled"],
            true
        );
        peer.lock()?;
        let mut peer = Peer::new()?;
        assert_eq!(
            peer.raw("open", json!({"path":path,"password":"y"}))?["ok"],
            false
        );
        assert_eq!(
            peer.raw("open", json!({"path":path,"password":""}))?["ok"],
            false
        );
        peer.ok("open", json!({"path":path,"password":normal}))?;
        assert_eq!(
            peer.ok("documents_list", json!({}))?["documents"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        peer.ok("dummy_set", json!({"new_password":"y"}))?;
        peer.ok("protection_disable", json!({}))?;
        for record in [
            pgpcrypt::duress::sidecar_path(&path),
            record_path,
            pgpcrypt::expiry::sidecar_path(&path),
        ] {
            assert!(
                !record.exists(),
                "master-off must erase every option record"
            );
        }
        peer.ok("protection_enable", json!({}))?;
        let status = peer.ok("protection_status", json!({}))?;
        assert_eq!(status["enabled"], true);
        for field in ["dummy_enabled", "emergency_enabled", "expiry_enabled"] {
            assert_eq!(status[field], false, "master re-enable retained {field}");
        }
        assert_eq!(
            peer.raw("dummy_set", json!({"new_password":"y"}))?["ok"],
            false
        );
        peer.lock()?;
        let mut peer = Peer::new()?;
        assert_eq!(
            peer.raw("open", json!({"path":path,"password":"x"}))?["ok"],
            false
        );
        assert_eq!(
            fs::read(&path)?,
            snapshot,
            "disabled emergency password changed the vault"
        );
        peer.ok("open", json!({"path":path,"password":normal}))?;
        peer.lock()?;
    }
    Ok(())
}
