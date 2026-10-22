#!/usr/bin/env python3
"""Exercise the vault against Debian's independent Go age implementation.

All credentials and files are disposable test fixtures. Passwords travel through
a controlling terminal, never command arguments or environment variables.
"""
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import shutil
import subprocess
import tempfile
import termios
import time

ROOT = Path(__file__).resolve().parent.parent
PASS = "disposable age interop passphrase"


def terminal_command(arguments):
    master, slave = pty.openpty()

    def controlling_terminal():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

    child = subprocess.Popen(arguments, stdin=slave, stdout=slave, stderr=slave,
                             preexec_fn=controlling_terminal)
    os.close(slave)
    buffer = b""
    deadline = time.monotonic() + 90
    try:
        while child.poll() is None:
            if time.monotonic() > deadline:
                raise TimeoutError("age interoperability command timed out")
            if select.select([master], [], [], 0.1)[0]:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                buffer = (buffer + chunk)[-8192:]
                if b"passphrase" in buffer.lower() and b":" in buffer:
                    os.write(master, (PASS + "\n").encode())
                    buffer = b""
        if child.wait(timeout=10):
            raise RuntimeError("Debian age rejected the interoperability fixture")
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        os.close(master)


class Peer:
    def __init__(self):
        self.child = subprocess.Popen([str(ROOT / "target/debug/pgpcrypt-worker")],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True)
        self.sequence = 0

    def request(self, op, **fields):
        self.sequence += 1
        self.child.stdin.write(json.dumps(dict(id=self.sequence, op=op, **fields)) + "\n")
        self.child.stdin.flush()
        response = json.loads(self.child.stdout.readline())
        assert response["ok"], response.get("error")
        return response["data"]

    def lock(self):
        self.request("lock")
        assert self.child.wait(timeout=10) == 0


def main():
    age = shutil.which("age")
    if age is None:
        candidate = ROOT.parent / ".pgpcrypt-tools/debian-rust/usr/bin/age"
        assert candidate.is_file(), "Install Debian's age package to run this test"
        age = str(candidate)
    with tempfile.TemporaryDirectory(prefix="pgpcrypt-age-interop-") as temporary:
        directory = Path(temporary)
        original = directory / "rust.pgpcrypt.age"
        plaintext = directory / "fixture.json"
        external = directory / "go.pgpcrypt.age"
        peer = Peer()
        peer.request("create", path=str(original), password=PASS)
        peer.request("generate", password="disposable age key passphrase", key_options={
            "name": "Age interop fixture", "email": "age@example.invalid",
            "algorithm": "cv25519", "layout": "subkeys", "signing": True,
            "certification": True, "transport_encryption": True,
            "storage_encryption": True, "expires_at": None,
        })
        fingerprint = peer.request("list")["keys"][0]["fingerprint"]
        peer.request("notes_set", text="independent age compatibility fixture")
        peer.lock()

        terminal_command([age, "--decrypt", "--output", str(plaintext), str(original)])
        decoded = json.loads(plaintext.read_text())
        assert decoded["application"] == "PGPCrypt" and decoded["schema"] == 3
        assert decoded["data"]["notes"] == "independent age compatibility fixture"
        assert len(decoded["data"]["certificates"]) == 1

        terminal_command([age, "--passphrase", "--output", str(external), str(plaintext)])
        peer = Peer()
        peer.request("open", path=str(external), password=PASS)
        assert peer.request("notes_get")["text"] == decoded["data"]["notes"]
        assert peer.request("list")["keys"][0]["fingerprint"] == fingerprint
        peer.lock()
    print("age interoperability passed: Rust vault -> Debian age -> Rust vault")


if __name__ == "__main__":
    main()
