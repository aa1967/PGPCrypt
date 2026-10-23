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
fn largest_escaped_document_roundtrips_through_private_ipc() -> Result<()> {
    for format in ["age", "kdbx"] {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("escaped-document.age");
        let mut peer = Peer::new()?;
        peer.ok(
            "create",
            json!({"path":path,"password":"disposable large document password","format":format}),
        )?;
        // JSON doubles this valid document to 8 MiB plus its envelope. The private
        // protocol must accept it without relaxing the document or vault bounds.
        let text = "\n".repeat(4 * 1024 * 1024);
        let id = peer.ok(
            "document_save",
            json!({"title":"Whitespace document","text":text}),
        )?["id"]
            .clone();
        assert_eq!(
            peer.ok("document_get", json!({"document_id":id}))?["text"],
            text
        );
        peer.ok("lock", json!({}))?;
        assert!(peer.child.wait()?.success());
        let mut reopened = Peer::new()?;
        reopened.ok(
            "open",
            json!({"path":path,"password":"disposable large document password"}),
        )?;
        assert_eq!(
            reopened.ok("document_get", json!({"document_id":id}))?["text"],
            text
        );
    }
    Ok(())
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
    assert!(
        list["keys"][0]["created_at"]
            .as_u64()
            .is_some_and(|time| time > 0)
    );
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
    assert!(
        signed["text"]
            .as_str()
            .unwrap()
            .starts_with("-----BEGIN PGP SIGNED MESSAGE-----")
    );
    assert!(
        signed["text"]
            .as_str()
            .unwrap()
            .contains("worker signed message")
    );
    let verified = peer.ok("verify", json!({"text":signed["text"]}))?;
    assert_eq!(verified["text"], "worker signed message");
    assert_eq!(verified["signers"], json!([fp]));
    assert_eq!(verified["signer_details"][0]["fingerprint"], fp);
    let signed_text = signed["text"].as_str().unwrap();
    let altered = signed_text.replace("worker signed message", "worker altered message");
    // Every failed verification is an explicit negative result and must not
    // return plaintext or identities retained from the preceding success.
    for text in [altered.as_str(), "ordinary unsigned text", ""] {
        let invalid = peer.raw("verify", json!({"text":text}))?;
        assert_eq!(invalid["ok"], false);
        assert_eq!(invalid["code"], "verification_failed");
        assert!(invalid.get("data").is_none());
        assert!(invalid.get("text").is_none());
        assert!(invalid.get("signers").is_none());
        assert!(invalid.get("signer_details").is_none());
    }
    let recovered = peer.ok("verify", json!({"text":signed["text"]}))?;
    assert_eq!(
        recovered, verified,
        "failed verification cannot poison a later success"
    );
    peer.ok("notes_set", json!({"text":"persisted protocol note"}))?;
    assert_eq!(peer.raw("private_export", json!({}))?["ok"], false);
    for operation in ["private_export", "protected_private_export"] {
        for supplied in ["", "wrong password"] {
            let response = peer.raw(operation, json!({"fingerprint":fp,"password":supplied}))?;
            assert_eq!(response["ok"], false);
            assert_eq!(response["code"], "password_required");
            assert!(
                response.get("data").is_none(),
                "failed authentication must release no armor"
            );
        }
    }
    let exported = peer.ok(
        "protected_private_export",
        json!({"fingerprint":fp,"password":key_password}),
    )?;
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
        assert_eq!(list["keys"][0]["secret_any_protected"], false);
        assert_eq!(list["keys"][0]["signing_password_required"], false);
        let signed = peer.ok("sign", json!({"text":"passwordless signing fixture"}))?;
        assert!(
            signed["text"]
                .as_str()
                .unwrap()
                .starts_with("-----BEGIN PGP SIGNED MESSAGE-----")
        );
        assert_eq!(
            peer.ok("verify", json!({"text":signed["text"]}))?["signers"],
            json!([fp])
        );
        let tampered = signed["text"]
            .as_str()
            .unwrap()
            .replace("passwordless signing fixture", "tampered signing fixture");
        assert_eq!(peer.raw("verify", json!({"text":tampered}))?["ok"], false);
        for supplied in ["", "wrong vault password"] {
            let response = peer.raw(
                "private_export",
                json!({"fingerprint":fp,"vault_password":supplied}),
            )?;
            assert_eq!(response["ok"], false);
            assert_eq!(response["code"], "vault_auth_required");
            assert!(response.get("data").is_none());
        }
        let exported = peer.ok(
            "private_export",
            json!({"fingerprint":fp,"vault_password":password}),
        )?;
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
        let protected_signed = peer.ok(
            "sign",
            json!({"text":"short password fixture","password":"x"}),
        )?;
        assert!(
            protected_signed["text"]
                .as_str()
                .unwrap()
                .starts_with("-----BEGIN PGP SIGNED MESSAGE-----")
        );
        assert_eq!(
            peer.ok("verify", json!({"text":protected_signed["text"]}))?["signers"],
            json!([fp])
        );
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
        assert_eq!(opened["preferences"]["notepad_popout"], true);
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
        let preferences = json!({"auto_lock":true,"lock_on_focus_loss":false,"lock_on_session_events":true,"clipboard_clear_seconds":1800,"theme":"solarized","qubes_rpc":false,"notepad_popout":false});
        for theme in ["warm-light", "nord", "solarized-light", "solarized-dark"] {
            peer.ok("settings_set", json!({"preferences":{"theme":theme}}))?;
        }
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

#[test]
fn profiles_scope_keys_and_documents_survive_conversion_without_plaintext_files() -> Result<()> {
    for format in ["age", "kdbx"] {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(format!("workspace.{format}"));
        let other = if format == "age" { "kdbx" } else { "age" };
        let copy = dir.path().join(format!("copy.{other}"));
        let password = "disposable workspace vault password";
        let mut peer = Peer::new()?;
        peer.ok(
            "create",
            json!({"path":path,"password":password,"format":format}),
        )?;
        assert_eq!(peer.ok("profiles_list", json!({}))?["profiles"], json!([]));
        assert_eq!(
            peer.ok("documents_list", json!({}))?["documents"],
            json!([])
        );
        let profile = peer.ok("profile_save", json!({"profile_name":"Personal"}))?["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let work_profile = peer.ok("profile_save", json!({"profile_name":"Work"}))?["id"]
            .as_str()
            .unwrap()
            .to_owned();
        for (name, assigned) in [
            ("Personal identity", &profile),
            ("Work identity", &work_profile),
        ] {
            peer.ok("generate",json!({"profile_id":assigned,"key_options":{
                "name":name,"algorithm":"cv25519","layout":"subkeys","signing":true,
                "certification":true,"transport_encryption":true,"storage_encryption":true,"expires_at":null
            }}))?;
        }
        let list = peer.ok("list", json!({}))?;
        let personal = list["keys"][0]["fingerprint"].as_str().unwrap().to_owned();
        let work = list["keys"][1]["fingerprint"].as_str().unwrap().to_owned();
        let memberships = peer.ok("profiles_list", json!({}))?["profiles"].clone();
        assert_eq!(memberships[0]["fingerprints"], json!([personal]));
        assert_eq!(memberships[1]["fingerprints"], json!([work]));
        let public = peer.ok("public_export", json!({"fingerprint":personal}))?["text"].clone();
        peer.ok(
            "profile_save",
            json!({"profile_id":profile,"profile_name":"Personal","profile_fingerprints":[]}),
        )?;
        peer.ok("import", json!({"profile_id":profile,"text":public}))?;
        assert_eq!(
            peer.ok("profiles_list", json!({}))?["profiles"][0]["fingerprints"],
            json!([personal]),
            "import must join the selected profile"
        );
        for invalid in [
            json!({"profile_name":"all"}),
            json!({"profile_name":"+"}),
            json!({"profile_name":"personal"}),
            json!({"profile_name":"Missing key","profile_fingerprints":["missing"]}),
            json!({"profile_name":"Duplicate member","profile_fingerprints":[personal,personal]}),
        ] {
            assert_eq!(peer.raw("profile_save", invalid)?["ok"], false);
        }
        assert_eq!(
            peer.raw("profile_delete", json!({"profile_id":""}))?["ok"],
            false
        );
        let list = peer.ok("list", json!({}))?;
        assert_eq!(
            list["keys"].as_array().unwrap().len(),
            2,
            "list retains all keys for profile management"
        );
        assert_eq!(list["profiles"].as_array().unwrap().len(), 2);
        peer.ok("settings_set", json!({"default_signing_key":work}))?;
        assert_eq!(
            peer.raw(
                "sign",
                json!({"profile_id":profile,"text":"profile fixture"})
            )?["ok"],
            false,
            "hidden default must not sign"
        );
        assert_eq!(
            peer.raw(
                "sign",
                json!({"profile_id":profile,"fingerprint":work,"text":"profile fixture"})
            )?["ok"],
            false
        );
        let signed = peer.ok(
            "sign",
            json!({"profile_id":profile,"fingerprint":personal,"text":"profile fixture"}),
        )?;
        let verified = peer.ok(
            "verify",
            json!({"profile_id":profile,"text":signed["text"]}),
        )?;
        assert_eq!(verified["signer_details"][0]["fingerprint"], personal);
        assert_eq!(
            verified["signer_details"][0]["identities"],
            json!(["Personal identity"])
        );
        assert_eq!(
            verified["signer_details"][0]["key_id"],
            personal[personal.len() - 16..]
        );
        assert_eq!(
            peer.raw(
                "verify",
                json!({"profile_id":work_profile,"text":signed["text"]})
            )?["ok"],
            false
        );
        assert_eq!(
            peer.raw(
                "encrypt",
                json!({"profile_id":profile,"recipients":[work],"text":"outside profile"})
            )?["ok"],
            false
        );
        let encrypted = peer.ok(
            "encrypt",
            json!({"profile_id":profile,"recipients":[personal],"text":"inside profile"}),
        )?;
        assert_eq!(
            peer.raw(
                "decrypt",
                json!({"profile_id":work_profile,"text":encrypted["text"]})
            )?["ok"],
            false
        );
        assert_eq!(
            peer.ok(
                "decrypt",
                json!({"profile_id":profile,"text":encrypted["text"]})
            )?["text"],
            "inside profile"
        );
        let body = "Saved inside encrypted vault — not a plaintext message file";
        let document = peer.ok(
            "document_save",
            json!({"profile_id":profile,"title":"Private message","text":body}),
        )?["id"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            peer.ok("documents_list", json!({"profile_id":work_profile}))?["documents"],
            json!([])
        );
        assert_eq!(
            peer.ok("documents_list", json!({"profile_id":profile}))?["documents"][0]["id"],
            document
        );
        assert!(
            peer.ok("documents_list", json!({}))?["documents"][0]
                .get("text")
                .is_none()
        );
        assert_eq!(
            peer.raw(
                "document_get",
                json!({"profile_id":work_profile,"document_id":document})
            )?["ok"],
            false
        );
        assert_eq!(
            peer.ok(
                "document_get",
                json!({"profile_id":profile,"document_id":document})
            )?["text"],
            body
        );
        for invalid in [
            json!({"document_id":document,"title":"Private message","text":"invalid\u{0000} text"}),
            json!({"title":"Missing profile","text":"not saved","profile_id":"missing"}),
        ] {
            assert_eq!(peer.raw("document_save", invalid)?["ok"], false);
        }
        assert_eq!(
            peer.ok("document_get", json!({"document_id":document}))?["text"],
            body,
            "failed updates must roll back"
        );
        let ciphertext = std::fs::read(&path)?;
        assert!(
            !ciphertext
                .windows(body.len())
                .any(|bytes| bytes == body.as_bytes())
        );
        peer.ok(
            "convert_copy",
            json!({"path":copy,"password":password,"format":other}),
        )?;
        assert_eq!(std::fs::read(&path)?, ciphertext);
        peer.ok("lock", json!({}))?;
        assert!(peer.child.wait()?.success());
        let mut portable = Peer::new()?;
        portable.ok("open", json!({"path":copy,"password":password}))?;
        assert_eq!(
            portable.ok("profiles_list", json!({}))?["profiles"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            portable.ok("document_get", json!({"document_id":document}))?["text"],
            body
        );
        portable.ok("profile_delete", json!({"profile_id":profile}))?;
        assert_eq!(
            portable.ok("document_get", json!({"document_id":document}))?["profile_id"],
            "",
            "profile deletion retains documents unassigned"
        );
        assert_eq!(
            portable.ok("list", json!({}))?["keys"]
                .as_array()
                .unwrap()
                .len(),
            2,
            "profile deletion must retain keys"
        );
        portable.ok("document_delete", json!({"document_id":document}))?;
        // A later save must not resurrect a removed document from retained KDBX state.
        portable.ok("notes_set", json!({"text":"later managed save"}))?;
        portable.ok("lock", json!({}))?;
        assert!(portable.child.wait()?.success());
        let mut reopened = Peer::new()?;
        reopened.ok("open", json!({"path":copy,"password":password}))?;
        assert_eq!(
            reopened.ok("documents_list", json!({}))?["documents"],
            json!([])
        );
        assert_eq!(
            reopened.ok("profiles_list", json!({}))?["profiles"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
    Ok(())
}

#[test]
fn new_password_limits_count_characters_and_keep_short_or_empty_passwords_usable() -> Result<()> {
    for format in ["age", "kdbx"] {
        let directory = tempfile::tempdir()?;
        let too_long = "🗝".repeat(129);
        let maximum = "🗝".repeat(128);
        for (index, password) in ["", "x", maximum.as_str()].into_iter().enumerate() {
            let path = directory.path().join(format!("password-{index}"));
            let mut peer = Peer::new()?;
            peer.ok(
                "create",
                json!({"path":path,"format":format,"password":password}),
            )?;
            peer.ok("lock", json!({}))?;
            assert!(peer.child.wait()?.success());
            let mut reopened = Peer::new()?;
            reopened.ok("open", json!({"path":path,"password":password}))?;
            if index == 2 {
                let denied = reopened.raw("generate", json!({"password":too_long,"key_options":{
                    "name":"Maximum password fixture","algorithm":"cv25519","layout":"subkeys",
                    "signing":true,"certification":true,"transport_encryption":true,"storage_encryption":true,"expires_at":null
                }}))?;
                assert_eq!(denied["ok"], false);
                assert_eq!(reopened.ok("list", json!({}))?["keys"], json!([]));
                reopened.ok("generate", json!({"password":maximum,"key_options":{
                    "name":"Maximum password fixture","algorithm":"cv25519","layout":"subkeys",
                    "signing":true,"certification":true,"transport_encryption":true,"storage_encryption":true,"expires_at":null
                }}))?;
                let fp = reopened.ok("list", json!({}))?["keys"][0]["fingerprint"].clone();
                reopened.ok(
                    "private_export",
                    json!({"fingerprint":fp,"password":maximum}),
                )?;
                assert_eq!(
                    reopened.raw(
                        "protect_private_key",
                        json!({"fingerprint":fp,"password":maximum,"new_password":too_long})
                    )?["ok"],
                    false
                );
                let rejected_copy = directory.path().join("rejected-copy");
                assert_eq!(
                    reopened.raw(
                        "convert_copy",
                        json!({"path":rejected_copy,"format":format,"password":too_long})
                    )?["ok"],
                    false
                );
                assert!(!rejected_copy.exists());
            }
            reopened.ok("lock", json!({}))?;
            assert!(reopened.child.wait()?.success());
        }
        let rejected = directory.path().join("rejected-new-vault");
        let mut peer = Peer::new()?;
        assert_eq!(
            peer.raw(
                "create",
                json!({"path":rejected,"format":format,"password":too_long})
            )?["ok"],
            false
        );
        assert!(!rejected.exists());
    }
    Ok(())
}

#[test]
fn mixed_secret_exports_require_vault_authentication_and_every_protected_packet_password()
-> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("mixed-secrets.age");
    let mut peer = Peer::new()?;
    peer.ok(
        "create",
        json!({"path":path,"password":"vault custody password"}),
    )?;
    peer.ok("generate",json!({"password":"x","key_options":{
        "name":"Mixed secret fixture","algorithm":"cv25519","layout":"subkeys","signing":true,
        "certification":true,"transport_encryption":true,"storage_encryption":true,"expires_at":null
    }}))?;
    let fp = peer.ok("list", json!({}))?["keys"][0]["fingerprint"].clone();
    peer.ok(
        "add_subkey",
        json!({"fingerprint":fp,"password":"x","subkey_options":{
            "purpose":"encrypt","algorithm":"cv25519","expires_at":null
        }}),
    )?;
    let missing_vault = peer.raw("private_export", json!({"fingerprint":fp,"password":"x"}))?;
    assert_eq!(missing_vault["ok"], false);
    assert_eq!(missing_vault["code"], "vault_auth_required");
    let missing_key = peer.raw(
        "private_export",
        json!({"fingerprint":fp,"vault_password":"vault custody password"}),
    )?;
    assert_eq!(missing_key["ok"], false);
    assert_eq!(missing_key["code"], "password_required");
    let exported = peer.ok(
        "private_export",
        json!({"fingerprint":fp,"password":"x","vault_password":"vault custody password"}),
    )?;
    let cert = pgp::parse(exported["text"].as_str().unwrap().as_bytes())?;
    assert_eq!(
        cert.keys()
            .secret()
            .filter(|key| !key.key().secret().is_encrypted())
            .count(),
        1
    );
    assert_eq!(
        cert.keys()
            .secret()
            .filter(|key| key.key().secret().is_encrypted())
            .count(),
        3,
        "authenticating an export must not remove its secret-packet encryption"
    );
    assert_eq!(
        peer.raw(
            "protected_private_export",
            json!({"fingerprint":fp,"password":"x","vault_password":"vault custody password"})
        )?["ok"],
        false
    );
    Ok(())
}

#[test]
fn identity_metadata_and_document_properties_survive_moves_collisions_and_conversion() -> Result<()>
{
    for format in ["age", "kdbx"] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("identity-documents");
        let portable = directory.path().join("portable-copy");
        let other = if format == "age" { "kdbx" } else { "age" };
        let password = "disposable identity vault password";
        let mut peer = Peer::new()?;
        peer.ok(
            "create",
            json!({"path":path,"format":format,"password":password}),
        )?;
        let personal = peer.ok("profile_save", json!({
            "profile_name":"Personal","profile_username":"Private pseudonym",
            "profile_email":"private@example.invalid","profile_url":"https://example.invalid/identity",
            "profile_notes":"Private biography\nOnly inside the vault"
        }))?["id"].clone();
        let work = peer.ok("profile_save", json!({"profile_name":"Work"}))?["id"].clone();
        let personal_id = personal.as_str().unwrap();
        let work_id = work.as_str().unwrap();
        let mut counts = json!({"":0});
        counts[personal_id] = json!(0);
        counts[work_id] = json!(0);
        for operation in ["list", "documents_list"] {
            assert_eq!(
                peer.ok(operation, json!({}))?["profile_document_counts"],
                counts,
                "empty identities need visible zero counts"
            );
        }
        let profiles = peer.ok("profiles_list", json!({}))?["profiles"].clone();
        assert_eq!(profiles[0]["username"], "Private pseudonym");
        assert_eq!(profiles[0]["email"], "private@example.invalid");
        assert_eq!(profiles[0]["url"], "https://example.invalid/identity");
        assert_eq!(
            profiles[0]["notes"],
            "Private biography\nOnly inside the vault"
        );
        assert_eq!(
            profiles[0]["fingerprints"],
            json!([]),
            "identity creation must not require keys"
        );
        assert_eq!(peer.raw("profile_save", json!({"profile_id":personal,"profile_name":"Personal","profile_notes":"invalid\u{0000} notes"}))?["ok"], false);
        assert_eq!(
            peer.ok("profiles_list", json!({}))?["profiles"],
            profiles,
            "invalid metadata must roll back"
        );
        let first = peer.ok(
            "document_save",
            json!({"profile_id":personal,"text":"first private body"}),
        )?;
        let second = peer.ok(
            "document_save",
            json!({"profile_id":personal,"text":"second private body"}),
        )?;
        assert_eq!(first["title"], "untitled");
        assert_eq!(second["title"], "untitled (1)");
        assert_ne!(first["id"], second["id"]);
        let work_document = peer.ok(
            "document_save",
            json!({"profile_id":work,"title":"UNTITLED","text":"work private body"}),
        )?;
        assert_eq!(
            work_document["title"], "UNTITLED",
            "equal titles are allowed in separate profiles"
        );
        counts[personal_id] = json!(2);
        counts[work_id] = json!(1);
        for operation in ["list", "documents_list"] {
            assert_eq!(
                peer.ok(operation, json!({}))?["profile_document_counts"],
                counts
            );
        }
        assert_eq!(
            peer.ok("documents_list", json!({"profile_id":personal}))?["profile_document_counts"],
            counts,
            "filtering documents must retain counts for the whole identity overview"
        );
        let moved = peer.ok(
            "document_properties",
            json!({"document_id":second["id"],"profile_id":work,"title":"untitled"}),
        )?;
        assert_eq!(moved["title"], "untitled (1)");
        assert_eq!(moved["profile_id"], work);
        counts[personal_id] = json!(1);
        counts[work_id] = json!(2);
        for operation in ["list", "documents_list"] {
            assert_eq!(
                peer.ok(operation, json!({}))?["profile_document_counts"],
                counts
            );
        }
        let reopened = peer.ok("document_get", json!({"document_id":second["id"]}))?;
        assert_eq!(
            reopened["text"], "second private body",
            "editing properties must retain content"
        );
        assert_eq!(reopened["created_at"], second["created_at"]);
        assert_eq!(
            peer.raw(
                "document_properties",
                json!({"document_id":second["id"],"profile_id":"missing","title":"must not save"})
            )?["ok"],
            false
        );
        assert_eq!(
            peer.ok("document_get", json!({"document_id":second["id"]}))?,
            reopened
        );
        let replaced = peer.ok("document_save", json!({"document_id":first["id"],"profile_id":personal,"title":"untitled","text":"updated first body"}))?;
        assert_eq!(replaced["id"], first["id"]);
        assert_eq!(replaced["title"], "untitled");
        assert_eq!(
            peer.ok("documents_list", json!({}))?["documents"]
                .as_array()
                .unwrap()
                .len(),
            3,
            "saving an existing document must not create a duplicate"
        );
        peer.ok(
            "document_save",
            json!({"title":"untitled","text":"unassigned body"}),
        )?;
        peer.ok("profile_delete", json!({"profile_id":work}))?;
        counts.as_object_mut().unwrap().remove(work_id);
        counts[""] = json!(3);
        for operation in ["list", "documents_list"] {
            assert_eq!(
                peer.ok(operation, json!({}))?["profile_document_counts"],
                counts
            );
        }
        let documents = peer.ok("documents_list", json!({}))?["documents"].clone();
        let mut titles = std::collections::HashSet::new();
        for document in documents.as_array().unwrap() {
            if document["profile_id"] == "" {
                assert!(
                    titles.insert(document["title"].as_str().unwrap().to_lowercase()),
                    "deleting an identity must resolve unassigned name collisions"
                );
            }
        }
        peer.ok(
            "convert_copy",
            json!({"path":portable,"format":other,"password":password}),
        )?;
        peer.ok("lock", json!({}))?;
        assert!(peer.child.wait()?.success());
        let mut peer = Peer::new()?;
        peer.ok("open", json!({"path":portable,"password":password}))?;
        assert_eq!(
            peer.ok("list", json!({}))?["profile_document_counts"],
            counts
        );
        assert_eq!(
            peer.ok("profiles_list", json!({}))?["profiles"][0],
            profiles[0]
        );
        assert_eq!(
            peer.ok("documents_list", json!({}))?["documents"],
            documents
        );
        assert_eq!(
            peer.ok("document_get", json!({"document_id":first["id"]}))?["text"],
            "updated first body"
        );
        assert_eq!(
            peer.ok("document_get", json!({"document_id":second["id"]}))?["text"],
            "second private body"
        );
    }
    Ok(())
}
