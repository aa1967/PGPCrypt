use anyhow::{Result, ensure};
use pgpcrypt::pgp;
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

struct Peer {
    child: Child,
    input: Option<ChildStdin>,
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
            input: child.stdin.take(),
            output: BufReader::new(child.stdout.take().unwrap()),
            child,
            sequence: 0,
        })
    }
    fn raw(&mut self, op: &str, mut fields: Value) -> Result<Value> {
        self.sequence += 1;
        fields["id"] = json!(self.sequence);
        fields["op"] = json!(op);
        let mut bytes = serde_json::to_vec(&fields)?;
        bytes.push(b'\n');
        self.input.as_mut().unwrap().write_all(&bytes)?;
        let mut line = String::new();
        self.output.read_line(&mut line)?;
        let response: Value = serde_json::from_str(&line)?;
        ensure!(response["id"] == self.sequence, "Incorrect response ID");
        Ok(response)
    }
    fn ok(&mut self, op: &str, fields: Value) -> Result<Value> {
        let response = self.raw(op, fields)?;
        ensure!(
            response["ok"] == true,
            "Operation failed: {}",
            response["error"]
        );
        Ok(response["data"].clone())
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn worker_vault_workflow_and_private_key_boundary() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("worker.pgpvault");
    let password = "disposable protocol passphrase";
    let key_password = "disposable private key passphrase";
    let mut peer = Peer::new()?;
    assert_eq!(peer.ok("status", json!({}))?["unlocked"], false);
    for op in ["list", "notes_get", "public_export", "generate"] {
        assert_eq!(peer.raw(op, json!({}))?["ok"], false, "{op} while locked");
    }
    peer.ok("create", json!({"path":path,"password":password}))?;
    assert_eq!(
        peer.raw("open", json!({"path":path,"password":password}))?["ok"],
        false
    );
    peer.ok(
        "generate",
        json!({"password":key_password,"key_options":{
            "name":"Protocol fixture","email":"protocol@example.invalid","comment":"Disposable fixture",
            "algorithm":"cv25519","layout":"subkeys","signing":true,"certification":true,
            "transport_encryption":true,"storage_encryption":true,"expires_at":null
        }}),
    )?;
    let list = peer.ok("list", json!({}))?;
    let fp = list["keys"][0]["fingerprint"].as_str().unwrap().to_owned();
    assert_eq!(list["keys"][0]["has_secret"], true);
    assert_eq!(list["keys"][0]["status"], "Valid");
    assert!(list["keys"][0].get("secret").is_none());
    let public = peer.ok("public_export", json!({"fingerprint":fp}))?;
    assert!(!pgp::parse(public["text"].as_str().unwrap().as_bytes())?.is_tsk());
    peer.ok("import", json!({"text":public["text"]}))?;
    assert_eq!(
        peer.ok("list", json!({}))?["keys"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        peer.raw(
            "encrypt",
            json!({"text":"fixture","recipients":["unknown"]})
        )?["ok"],
        false
    );
    let encrypted = peer.ok(
        "encrypt",
        json!({"text":"worker private message","recipients":[fp]}),
    )?;
    let decrypted = peer.ok(
        "decrypt",
        json!({"text":encrypted["text"],"password":key_password}),
    )?;
    assert_eq!(decrypted["text"], "worker private message");
    let signed = peer.ok(
        "sign",
        json!({"text":"worker signed message","fingerprint":fp,"password":key_password}),
    )?;
    let verified = peer.ok("verify", json!({"text":signed["text"]}))?;
    assert_eq!(verified["text"], "worker signed message");
    assert_eq!(verified["signers"], json!([fp]));
    peer.ok("notes_set", json!({"text":"persisted protocol note"}))?;
    assert_eq!(peer.raw("private_export", json!({}))?["ok"], false);
    let exported = peer.ok("protected_private_export", json!({"fingerprint":fp}))?;
    let private = pgp::parse(exported["text"].as_str().unwrap().as_bytes())?;
    assert!(
        private
            .keys()
            .secret()
            .all(|ka| ka.key().secret().is_encrypted())
    );
    let ticket = peer.ok("revocation_export", json!({"fingerprint":fp}))?;
    assert!(
        ticket["text"]
            .as_str()
            .unwrap()
            .contains("BEGIN PGP PUBLIC KEY BLOCK")
    );
    assert_eq!(
        peer.ok("list", json!({}))?["keys"][0]["status"],
        "Valid",
        "Exporting a ticket must not revoke a key"
    );
    assert_eq!(
        peer.raw("settings_set", json!({"idle_timeout_seconds":0}))?["ok"],
        false
    );
    peer.ok("settings_set", json!({"idle_timeout_seconds":60}))?;
    let new_key_password = "replacement private key passphrase";
    assert_eq!(
        peer.raw(
            "protect_private_key",
            json!({"fingerprint":fp,"password":"wrong","new_password":new_key_password})
        )?["ok"],
        false
    );
    peer.ok(
        "protect_private_key",
        json!({"fingerprint":fp,"password":key_password,"new_password":new_key_password}),
    )?;
    assert_eq!(
        peer.raw(
            "sign",
            json!({"text":"fixture","fingerprint":fp,"password":key_password})
        )?["ok"],
        false
    );
    peer.ok(
        "sign",
        json!({"text":"fixture","fingerprint":fp,"password":new_key_password}),
    )?;
    peer.ok("lock", json!({}))?;
    assert!(
        peer.child.wait()?.success(),
        "worker must terminate after lock"
    );
    let mut peer = Peer::new()?;
    assert_eq!(
        peer.raw("open", json!({"path":path,"password":"wrong"}))?["ok"],
        false
    );
    assert_eq!(
        peer.ok("open", json!({"path":path,"password":password}))?["idle_timeout_seconds"],
        60
    );
    assert_eq!(
        peer.ok("notes_get", json!({}))?["text"],
        "persisted protocol note"
    );
    assert_eq!(peer.ok("list", json!({}))?["keys"][0]["fingerprint"], fp);
    // EOF must release the vault lock and terminate the worker without a lock command.
    drop(peer.input.take());
    assert!(peer.child.wait()?.success());
    let _vault = pgpcrypt::vault::Vault::open(&path, password)?;
    Ok(())
}

#[test]
fn malformed_and_unterminated_requests_fail_closed() -> Result<()> {
    for bytes in [
        b"{not-json}\n".as_slice(),
        b"{\"id\":1,\"op\":\"status\"}".as_slice(),
        b"{\"id\":1,\"op\":\"status\",\"extra\":true}\n".as_slice(),
    ] {
        let mut peer = Peer::new()?;
        peer.input.take().unwrap().write_all(bytes)?;
        assert!(!peer.child.wait()?.success());
    }
    let mut peer = Peer::new()?;
    peer.input
        .take()
        .unwrap()
        .write_all(&vec![b'x'; pgpcrypt::worker::MAX_FRAME + 1])?;
    assert!(!peer.child.wait()?.success());
    Ok(())
}

#[test]
fn worker_dies_when_its_desktop_parent_is_killed() -> Result<()> {
    use std::os::fd::AsRawFd;
    // Pass stdin explicitly: POSIX shells otherwise redirect background-command
    // stdin to /dev/null. The shell waits as the worker's desktop-like parent.
    let mut parent = Command::new("/bin/sh")
        .args(["-c", "exec 3<&0; \"$1\" <&3 & wait", "pgpcrypt-parent"])
        .arg(env!("CARGO_BIN_EXE_pgpcrypt-worker"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut input = parent.stdin.take().unwrap();
    let mut output = BufReader::new(parent.stdout.take().unwrap());
    input.write_all(b"{\"id\":1,\"op\":\"status\"}\n")?;
    let mut line = String::new();
    output.read_line(&mut line)?;
    assert_eq!(serde_json::from_str::<Value>(&line)?["ok"], true);
    parent.kill()?;
    parent.wait()?;
    let mut descriptor = libc::pollfd {
        fd: output.get_ref().as_raw_fd(),
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    };
    // SAFETY: descriptor is a live pipe FD and poll receives one valid struct.
    assert!(
        unsafe { libc::poll(&mut descriptor, 1, 5000) } > 0,
        "orphaned worker did not terminate"
    );
    line.clear();
    assert_eq!(
        output.read_line(&mut line)?,
        0,
        "worker output must close after parent death"
    );
    Ok(())
}

#[test]
fn optional_key_passwords_and_default_survive_reopen_and_conversion() -> Result<()> {
    for format in ["age", "kdbx"] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join(format!("source.{format}"));
        let other = if format == "age" { "kdbx" } else { "age" };
        let converted = directory.path().join(format!("copy.{other}"));
        let password = "disposable vault conversion password";
        let mut peer = Peer::new()?;
        peer.ok(
            "create",
            json!({"path":path,"password":password,"format":format}),
        )?;
        peer.ok("generate",json!({"key_options":{
            "name":"Optional password fixture","algorithm":"cv25519","layout":"subkeys",
            "signing":true,"certification":true,"transport_encryption":true,"storage_encryption":true,"expires_at":null
        }}))?;
        let list = peer.ok("list", json!({}))?;
        let fp = list["keys"][0]["fingerprint"].as_str().unwrap().to_owned();
        assert_eq!(list["keys"][0]["secret_protected"], false);
        assert_eq!(
            peer.raw("settings_set", json!({"default_signing_key":"missing"}))?["ok"],
            false
        );
        peer.ok("settings_set", json!({"default_signing_key":fp}))?;
        peer.ok("settings_set", json!({"idle_timeout_seconds":120}))?;
        assert_eq!(peer.ok("list", json!({}))?["default_signing_key"], fp);
        peer.ok("sign", json!({"text":"passwordless signing fixture"}))?;
        let exported = peer.ok("private_export", json!({"fingerprint":fp}))?;
        assert_eq!(exported["protected"], false);
        assert!(
            pgp::parse(exported["text"].as_str().unwrap().as_bytes())?
                .keys()
                .secret()
                .all(|ka| !ka.key().secret().is_encrypted())
        );
        assert_eq!(
            peer.raw("protected_private_export", json!({"fingerprint":fp}))?["ok"],
            false
        );
        peer.ok(
            "protect_private_key",
            json!({"fingerprint":fp,"new_password":"x"}),
        )?;
        peer.ok(
            "sign",
            json!({"text":"short password fixture","password":"x"}),
        )?;
        assert_eq!(
            peer.raw(
                "sign",
                json!({"text":"wrong password fixture","password":"wrong"})
            )?["ok"],
            false
        );
        peer.ok(
            "protect_private_key",
            json!({"fingerprint":fp,"password":"x","new_password":""}),
        )?;
        peer.ok("sign", json!({"text":"removed password fixture"}))?;
        let original = std::fs::read(&path)?;
        peer.ok(
            "convert_copy",
            json!({"path":converted,"password":password,"format":other}),
        )?;
        assert_eq!(std::fs::read(&path)?, original);
        peer.ok("lock", json!({}))?;
        assert!(peer.child.wait()?.success());
        let mut reopened = Peer::new()?;
        assert_eq!(
            reopened.ok("open", json!({"path":path,"password":password}))?["default_signing_key"],
            fp
        );
        reopened.ok("sign", json!({"text":"reopened source fixture"}))?;
        reopened.ok("lock", json!({}))?;
        assert!(reopened.child.wait()?.success());
        let mut portable = Peer::new()?;
        let settings = portable.ok("open", json!({"path":converted,"password":password}))?;
        assert_eq!(settings["default_signing_key"], fp);
        assert_eq!(settings["idle_timeout_seconds"], 120);
        portable.ok("sign", json!({"text":"converted default key fixture"}))?;
        portable.ok("settings_set", json!({"default_signing_key":""}))?;
        assert_eq!(
            portable.raw("sign", json!({"text":"no default fixture"}))?["ok"],
            false
        );
    }
    Ok(())
}

#[test]
fn preferences_subkeys_and_password_requests_roundtrip() -> Result<()> {
    for format in ["age", "kdbx"] {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(format!("settings.{format}"));
        let copy = dir.path().join("converted");
        let vault_password = "disposable settings vault password";
        let mut peer = Peer::new()?;
        let opened = peer.ok(
            "create",
            json!({"path":path,"password":vault_password,"format":format}),
        )?;
        assert_eq!(opened["preferences"]["auto_lock"], false);
        assert_eq!(opened["preferences"]["lock_on_focus_loss"], false);
        assert_eq!(opened["preferences"]["lock_on_session_events"], false);
        assert_eq!(opened["preferences"]["clipboard_clear_seconds"], 0);
        assert_eq!(opened["preferences"]["qubes_rpc"], false);
        for invalid in [
            json!({"theme":"unknown"}),
            json!({"clipboard_clear_seconds":4}),
            json!({"clipboard_clear_seconds":1801}),
        ] {
            assert_eq!(
                peer.raw("settings_set", json!({"preferences":invalid}))?["ok"],
                false
            );
        }
        let preferences = json!({"auto_lock":true,"lock_on_focus_loss":false,"lock_on_session_events":true,"clipboard_clear_seconds":1800,"theme":"solarized","qubes_rpc":false});
        peer.ok(
            "settings_set",
            json!({"preferences":preferences,"idle_timeout_seconds":3600}),
        )?;
        peer.ok("generate",json!({"password":"x","key_options":{
            "name":"Subkey fixture","algorithm":"cv25519","layout":"subkeys","signing":false,"certification":true,"transport_encryption":false,"storage_encryption":false,"expires_at":null
        }}))?;
        let fp = peer.ok("list", json!({}))?["keys"][0]["fingerprint"]
            .as_str()
            .unwrap()
            .to_owned();
        let before = peer.ok("subkeys", json!({"fingerprint":fp}))?;
        assert_eq!(before["keys"].as_array().unwrap().len(), 1);
        let options = json!({"purpose":"sign","algorithm":"cv25519","expires_at":null});
        let denied = peer.raw(
            "add_subkey",
            json!({"fingerprint":fp,"subkey_options":options,"new_password":"y"}),
        )?;
        assert_eq!(denied["code"], "password_required");
        peer.ok(
            "add_subkey",
            json!({"fingerprint":fp,"password":"x","subkey_options":options,"new_password":"y"}),
        )?;
        let missing = peer.raw("sign", json!({"fingerprint":fp,"text":"prompt fixture"}))?;
        assert_eq!(missing["code"], "password_required", "{missing}");
        peer.ok(
            "sign",
            json!({"fingerprint":fp,"password":"y","text":"new signing subkey fixture"}),
        )?;
        peer.ok("add_subkey",json!({"fingerprint":fp,"password":"x","subkey_options":{"purpose":"encrypt","algorithm":"cv25519","expires_at":null}}))?;
        let encrypted = peer.ok(
            "encrypt",
            json!({"recipients":[fp],"text":"new decryption subkey"}),
        )?;
        assert_eq!(
            peer.ok("decrypt", json!({"text":encrypted["text"]}))?["text"],
            "new decryption subkey"
        );
        let after = peer.ok("subkeys", json!({"fingerprint":fp}))?;
        assert_eq!(after["keys"].as_array().unwrap().len(), 3);
        peer.ok(
            "notes_set",
            json!({"text":"retained notes from hidden page"}),
        )?;
        peer.ok("convert_copy",json!({"path":copy,"password":vault_password,"format":if format=="age" {"kdbx"} else {"age"}}))?;
        peer.ok("lock", json!({}))?;
        assert!(peer.child.wait()?.success());
        let mut reopened = Peer::new()?;
        let data = reopened.ok("open", json!({"path":copy,"password":vault_password}))?;
        assert_eq!(data["preferences"], preferences);
        assert_eq!(data["idle_timeout_seconds"], 3600);
        assert_eq!(
            reopened.ok("subkeys", json!({"fingerprint":fp}))?["keys"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        assert_eq!(
            reopened.ok("notes_get", json!({}))?["text"],
            "retained notes from hidden page"
        );
    }
    Ok(())
}

#[test]
fn qrexec_adapter_refuses_unbound_services_and_request_privileges() -> Result<()> {
    for (service, domain, body) in [
        (
            "Sign",
            "work-mail",
            "{\"operation\":\"open\",\"version\":1,\"path\":\"/tmp/private\"}\n",
        ),
        (
            "Sign",
            "work-mail",
            "{\"operation\":\"decrypt\",\"version\":1,\"text\":\"ciphertext\"}\n",
        ),
        (
            "Decrypt",
            "dom0",
            "{\"operation\":\"decrypt\",\"version\":1,\"text\":\"ciphertext\"}\n",
        ),
        ("Lock", "work-mail", ""),
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_pgpcrypt-qrexec"))
            .arg(service)
            .env("QREXEC_REMOTE_DOMAIN", domain)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        child.stdin.take().unwrap().write_all(body.as_bytes())?;
        let output = child.wait_with_output()?;
        assert!(!output.status.success());
        assert!(output.stderr.is_empty());
        let result: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(result["ok"], false);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("/tmp/private"));
    }
    Ok(())
}
