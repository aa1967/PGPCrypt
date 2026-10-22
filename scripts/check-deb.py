#!/usr/bin/env python3
"""Validate a locally built package without installing system files."""
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import io
import pwd
import json


def checked(command, **kwargs):
    return subprocess.check_output(command, text=True, **kwargs)


def main():
    archive = Path(sys.argv[1]).resolve()
    repo = Path(__file__).resolve().parent.parent
    settings = os.environ.copy()
    settings["QT_QPA_PLATFORM"] = "offscreen"
    plugins = repo.parent / ".pgpcrypt-tools/qt/usr/lib/x86_64-linux-gnu/qt6/plugins"
    if plugins.is_dir():
        settings["QT_PLUGIN_PATH"] = str(plugins)

    print(checked(["dpkg-deb", "-f", str(archive), "Package", "Version", "Architecture", "Depends"]).strip())
    filesystem = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(archive)])
    with tarfile.open(fileobj=io.BytesIO(filesystem)) as contents:
        for entry in contents:
            assert entry.uid == 0 and entry.gid == 0, entry.name
            if entry.isfile():
                assert entry.mode & 0o004, "not world-readable: " + entry.name
    with tempfile.TemporaryDirectory(prefix="pgpcrypt-package-") as temporary:
        stage = Path(temporary)
        subprocess.run(["dpkg-deb", "-x", str(archive), temporary], check=True)
        # CI's Debian container is root. Run the installed GUI as an ordinary
        # user from a package directory that user cannot write, so relative-path
        # and permission failures cannot be masked by root privileges.
        child_identity = {}
        if os.geteuid() == 0:
            account = pwd.getpwnam("nobody")
            stage.chmod(0o755)
            runtime = stage / "runtime"
            runtime.mkdir(mode=0o700)
            os.chown(runtime, account.pw_uid, account.pw_gid)
            settings["XDG_RUNTIME_DIR"] = str(runtime)
            child_identity = {"user": account.pw_uid, "group": account.pw_gid, "extra_groups": []}
        for name in ("pgpcrypt-desktop", "pgpcrypt-worker", "pgpcrypt-migrate"):
            executable = stage / "usr/lib/pgpcrypt" / name
            assert os.access(executable, os.X_OK), name
            dynamic = checked(["readelf", "-d", str(executable)])
            assert "RPATH" not in dynamic and "RUNPATH" not in dynamic, name
            assert "not found" not in checked(["ldd", str(executable)]), name
        subprocess.run(["desktop-file-validate", str(stage / "usr/share/applications/pgpcrypt.desktop")], check=True)
        assert (stage / "usr/share/icons/hicolor/scalable/apps/pgpcrypt.svg").is_file()
        assert "/usr/lib/pgpcrypt/pgpcrypt-desktop" in (stage / "usr/bin/pgpcrypt").read_text()
        assert (stage / "usr/share/doc/pgpcrypt/source.tar.gz").is_file()
        dependencies = checked(["dpkg-deb", "-f", str(archive), "Depends"])
        assert "rustc" not in dependencies and "cargo" not in dependencies and "rustup" not in dependencies
        assert "libzxcvbn0" in dependencies
        assert (stage / "usr/share/doc/pgpcrypt/third-party-licenses/age-0.12.1").is_dir()
        denied_folder = stage / "read-only"
        denied_folder.mkdir()
        denied_folder.chmod(0o555)
        denied_path = denied_folder / "blocked.pgpcrypt.age"
        denied = subprocess.run([str(stage / "usr/lib/pgpcrypt/pgpcrypt-worker")],
                                input=json.dumps({"id": 1, "op": "create", "path": str(denied_path),
                                                  "password": "disposable permission fixture"}) + "\n",
                                env=settings, capture_output=True, text=True, timeout=10, **child_identity)
        if denied.returncode:
            raise RuntimeError(denied.stderr)
        failure = json.loads(denied.stdout)
        assert failure["ok"] is False and "os error 13" in failure["error"], failure
        assert "lock file" in failure["error"] and "home folder" in failure["error"], failure
        assert not denied_path.exists()
        print("Permission failure identifies the lock file and suggests a writable location.")
        for mode in ("--self-test", "--test-lock-restart"):
            result = subprocess.run([str(stage / "usr/lib/pgpcrypt/pgpcrypt-desktop"), mode],
                                    env=settings, cwd=stage / "usr/lib/pgpcrypt",
                                    capture_output=True, text=True, timeout=60, **child_identity)
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
            print(result.stdout.strip())
    print("Package validation passed; no system installation performed.")


if __name__ == "__main__":
    main()
