#!/usr/bin/env python3
"""Disposable fixtures only: PGPCrypt -> Debian KeePassXC 2.7 -> PGPCrypt.
Passwords travel through stdin, never command arguments/environment. No real
vault or user keyring is opened. Run after pushing source, not as a Git hook.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from age_interop import Peer, ROOT

PASS = "disposable kdbx interoperability password"
KEYPASS = "disposable independent private key password"


def main():
    cli = shutil.which("keepassxc-cli")
    environment = os.environ.copy()
    if cli is None:
        extraction = ROOT.parent / ".pgpcrypt-tools/keepassxc"
        cli = str(extraction / "usr/bin/keepassxc-cli")
        assert Path(cli).is_file(), "Install Debian's keepassxc package"
        environment["LD_LIBRARY_PATH"] = str(extraction / "usr/lib/x86_64-linux-gnu")

    def run(*arguments):
        result = subprocess.run([cli, *arguments], input=PASS + "\n", text=True,
                                capture_output=True, env=environment, timeout=60)
        assert result.returncode == 0, "KeePassXC rejected disposable fixture: " + result.stderr
        return result.stdout

    with tempfile.TemporaryDirectory(prefix="pgpcrypt-kdbx-interop-") as directory:
        path = Path(directory) / "portable.kdbx"
        age = Path(directory) / "converted.age"
        peer = Peer()
        assert peer.request("create", path=str(path), password=PASS, format="kdbx")["format"] == "kdbx"
        peer.request("generate", password=KEYPASS, key_options={
            "name": "KDBX interop fixture", "email": "", "comment": "",
            "algorithm": "cv25519", "layout": "subkeys", "signing": True,
            "certification": True, "transport_encryption": True,
            "storage_encryption": True, "expires_at": None,
        })
        fingerprint = peer.request("list")["keys"][0]["fingerprint"]
        private = peer.request("protected_private_export", fingerprint=fingerprint, password=KEYPASS)["text"]
        public = peer.request("public_export", fingerprint=fingerprint)["text"]
        ticket = peer.request("revocation_export", fingerprint=fingerprint)["text"]
        profile = peer.request("profile_save", profile_name="Personal",
                               profile_username="private pseudonym", profile_email="portable@example.invalid",
                               profile_url="https://example.invalid/identity", profile_notes="Private identity notes",
                               profile_fingerprints=[fingerprint])["id"]
        work_profile = peer.request("profile_save", profile_name="Work",
                                    profile_fingerprints=[fingerprint])["id"]
        document = peer.request("document_save", profile_id=profile, title="Saved message",
                                text="message saved inside the vault")["id"]
        peer.request("notes_set", text="notes created by PGPCrypt")
        peer.request("settings_set", idle_timeout_seconds=120)
        peer.lock()
        key_entry = "PGPCrypt/KDBX interop fixture"
        document_entry = "PGPCrypt/Personal/Saved message"
        identity_entry = "PGPCrypt/Personal/Identity details"
        # KeePassXC exports independently decoded XML. Both identities should be
        # real groups, with references to one canonical armored key rather than
        # duplicate secret material which could diverge after a password change.
        exported = ET.fromstring(run("export", "-q", str(path)))
        groups = [group for group in exported.iter("Group")
                  if group.findtext("Name") == "PGPCrypt"]
        assert len(groups) == 1
        managed = groups[0]
        identity_groups = {group.findtext("Name"): group for group in managed.findall("Group")}
        assert set(identity_groups) == {"Personal", "Work"}

        def fields(entry):
            return {field.findtext("Key"): field.findtext("Value", default="")
                    for field in entry.findall("String")}

        references = []
        for name, group in identity_groups.items():
            entries = [fields(entry) for entry in group.findall("Entry")]
            assert any(entry.get("Title") == "Identity details" for entry in entries), name
            refs = [entry for entry in entries if entry.get("PGPCrypt.Type") == "key_reference"]
            assert len(refs) == 1 and refs[0]["OpenPGP.Fingerprint"] == fingerprint
            assert refs[0]["PGPCrypt.KeyEntry"]
            assert all(attribute not in refs[0] for attribute in
                       ("OpenPGP.PublicKey", "OpenPGP.PrivateKey", "OpenPGP.Revocation"))
            references.extend(refs)
        assert len({entry["PGPCrypt.KeyEntry"] for entry in references}) == 1
        armored = [fields(entry) for entry in managed.iter("Entry")
                   if "OpenPGP.PrivateKey" in fields(entry)]
        assert len(armored) == 1 and armored[0]["OpenPGP.PrivateKey"].strip() == private.strip()
        for attribute, expected in [("UserName", "private pseudonym"),
                                    ("Email", "portable@example.invalid"),
                                    ("URL", "https://example.invalid/identity"),
                                    ("Notes", "Private identity notes")]:
            assert run("show", "-q", "-s", "-a", attribute, str(path), identity_entry).strip() == expected
        assert run("show", "-q", "-s", "-a", "Notes", str(path), document_entry).strip() == "message saved inside the vault"
        assert profile in run("show", "-q", "-s", "-a", "PGPCrypt.Profiles", str(path),
                              "PGPCrypt/Vault notes and settings")
        assert "Advanced" in run("show", "-q", "-a", "Notes", str(path), key_entry)
        for attribute, expected in [("OpenPGP.PublicKey", public),
                                    ("OpenPGP.PrivateKey", private),
                                    ("OpenPGP.Revocation", ticket)]:
            actual = run("show", "-q", "-s", "-a", attribute, str(path), key_entry)
            assert actual.strip() == expected.strip(), attribute
        run("edit", "-q", "--username", "updated portable pseudonym", "--url",
            "https://example.invalid/updated", "--notes", "Identity edited in KeePassXC",
            str(path), identity_entry)
        run("edit", "-q", "--notes", "my portable key note", str(path), key_entry)
        run("edit", "-q", "--notes", "message edited in KeePassXC", str(path), document_entry)
        run("edit", "-q", "--notes", "edited in KeePassXC", str(path),
            "PGPCrypt/Vault notes and settings")
        run("add", "-q", "--username", "unrelated fixture", str(path), "External entry")
        # Ordinary KeePassXC group operations are meaningful organizational
        # edits: moving a document changes its identity; removing a reference
        # unassigns just that identity without deleting the canonical key.
        run("mv", "-q", str(path), document_entry, "PGPCrypt/Work")
        document_entry = "PGPCrypt/Work/Saved message"
        run("rm", "-q", str(path), "PGPCrypt/Personal/Key " + fingerprint)
        peer = Peer()
        peer.request("open", path=str(path), password=PASS)
        assert peer.request("notes_get")["text"] == "edited in KeePassXC"
        assert peer.request("list")["keys"][0]["fingerprint"] == fingerprint
        moved = peer.request("document_get", document_id=document)
        assert moved["text"] == "message edited in KeePassXC"
        assert moved["profile_id"] == work_profile
        identities = peer.request("profiles_list")["profiles"]
        identity = next(item for item in identities if item["id"] == profile)
        work_identity = next(item for item in identities if item["id"] == work_profile)
        assert identity["fingerprints"] == []
        assert work_identity["fingerprints"] == [fingerprint]
        assert identity["username"] == "updated portable pseudonym"
        assert identity["email"] == "portable@example.invalid"
        assert identity["url"] == "https://example.invalid/updated"
        assert identity["notes"] == "Identity edited in KeePassXC"
        # KeePassXC does not honor PGPCrypt's advisory lock. A save made while
        # PGPCrypt holds a stale snapshot must survive its next write attempt.
        run("edit", "-q", "--notes", "external update while PGPCrypt is open", str(path),
            "PGPCrypt/Vault notes and settings")
        external_snapshot = path.read_bytes()
        peer.sequence += 1
        peer.child.stdin.write(json.dumps(dict(id=peer.sequence, op="notes_set",
                                              text="stale update must fail")) + "\n")
        peer.child.stdin.flush()
        rejected = json.loads(peer.child.stdout.readline())
        assert not rejected["ok"] and "changed outside PGPCrypt" in rejected["error"]
        assert path.read_bytes() == external_snapshot
        assert peer.request("notes_get")["text"] == "edited in KeePassXC"
        peer.lock()
        peer = Peer()
        peer.request("open", path=str(path), password=PASS)
        assert peer.request("notes_get")["text"] == "external update while PGPCrypt is open"
        peer.request("notes_set", text="saved again by PGPCrypt")
        snapshot = path.read_bytes()
        peer.request("convert_copy", path=str(age), password=PASS, format="age")
        assert path.read_bytes() == snapshot
        peer.lock()
        assert run("show", "-q", "-a", "Notes", str(path), key_entry).strip() == "my portable key note"
        assert run("show", "-q", "-a", "UserName", str(path), "External entry").strip() == "unrelated fixture"
        assert run("show", "-q", "-s", "-a", "Notes", str(path),
                   "PGPCrypt/Vault notes and settings").strip() == "saved again by PGPCrypt"
        peer = Peer()
        peer.request("open", path=str(age), password=PASS)
        assert peer.request("protected_private_export", fingerprint=fingerprint, password=KEYPASS)["text"] == private
        assert peer.request("revocation_export", fingerprint=fingerprint)["text"] == ticket
        assert peer.request("document_get", document_id=document)["text"] == "message edited in KeePassXC"
        assert peer.request("document_get", document_id=document)["profile_id"] == work_profile
        restored = peer.request("profiles_list")["profiles"]
        assert next(item for item in restored if item["id"] == profile) == identity
        assert next(item for item in restored if item["id"] == work_profile) == work_identity
        peer.lock()
    print("KDBX interoperability passed: protected keys/documents/identity groups and references, KeePassXC field/group edits, stale-write refusal, unrelated entries, age conversion")


if __name__ == "__main__":
    main()
