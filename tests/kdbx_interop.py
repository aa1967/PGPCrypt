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
        private = peer.request("protected_private_export", fingerprint=fingerprint)["text"]
        public = peer.request("public_export", fingerprint=fingerprint)["text"]
        ticket = peer.request("revocation_export", fingerprint=fingerprint)["text"]
        peer.request("notes_set", text="notes created by PGPCrypt")
        peer.request("settings_set", idle_timeout_seconds=120)
        peer.lock()
        key_entry = "PGPCrypt/KDBX interop fixture"
        assert "Advanced" in run("show", "-q", "-a", "Notes", str(path), key_entry)
        for attribute, expected in [("OpenPGP.PublicKey", public),
                                    ("OpenPGP.PrivateKey", private),
                                    ("OpenPGP.Revocation", ticket)]:
            actual = run("show", "-q", "-s", "-a", attribute, str(path), key_entry)
            assert actual.strip() == expected.strip(), attribute
        run("edit", "-q", "--notes", "my portable key note", str(path), key_entry)
        run("edit", "-q", "--notes", "edited in KeePassXC", str(path),
            "PGPCrypt/Vault notes and settings")
        run("add", "-q", "--username", "unrelated fixture", str(path), "External entry")
        peer = Peer()
        peer.request("open", path=str(path), password=PASS)
        assert peer.request("notes_get")["text"] == "edited in KeePassXC"
        assert peer.request("list")["keys"][0]["fingerprint"] == fingerprint
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
        assert peer.request("protected_private_export", fingerprint=fingerprint)["text"] == private
        assert peer.request("revocation_export", fingerprint=fingerprint)["text"] == ticket
        peer.lock()
    print("KDBX interoperability passed: protected keys/revocation, KeePassXC edits, stale-write refusal, unrelated entries, age conversion")


if __name__ == "__main__":
    main()
