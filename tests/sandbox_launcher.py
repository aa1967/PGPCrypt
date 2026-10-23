#!/usr/bin/env python3
"""Argument/failure checks plus real Bubblewrap isolation when the host permits.
Disposable files only. Run after pushing; never a Git hook.
"""
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SOURCE = (ROOT / 'packaging/pgpcrypt-launcher').read_text()


def main():
    with tempfile.TemporaryDirectory(prefix='launcher-check-', dir=ROOT / 'target') as temporary:
        root = Path(temporary)
        home = root / 'home with spaces'
        home.mkdir()
        for name in ('.config', '.local', '.cache'):
            (home / name).mkdir()
            (home / name / 'host-sentinel').write_text('original')
        tools = root / 'tools'
        tools.mkdir()
        (tools / 'id').write_text('#!/bin/sh\necho 1000\n')
        (tools / 'id').chmod(0o755)
        capture = root / 'arguments.json'
        stub = root / 'bwrap-stub'
        stub.write_text('#!/usr/bin/python3\nimport json,os,sys\nfrom pathlib import Path\nPath(os.environ["CAPTURE"]).write_text(json.dumps(sys.argv[1:]))\nsys.exit(int(os.environ.get("STUB_EXIT",0)))\n')
        stub.chmod(0o755)
        wrapper = root / 'launcher'
        wrapper.write_text(SOURCE.replace('/usr/bin/bwrap', str(stub)))
        wrapper.chmod(0o755)
        env = dict(os.environ, HOME=str(home), PATH=str(tools)+':'+os.environ['PATH'], CAPTURE=str(capture))
        env.pop('XAUTHORITY', None)
        result = subprocess.run([str(wrapper)], env=env, capture_output=True)
        assert result.returncode == 0, result.stderr
        args = json.loads(capture.read_text())
        assert '--unshare-net' in args and '--cap-drop' in args and '--unshare-pid' in args
        for path in (home / '.config', home / '.local', home / '.cache', Path('/tmp')):
            assert any(args[i:i+2] == ['--tmpfs', str(path)] for i in range(len(args)-1))
        assert args[-2:] == ['--', '/usr/lib/pgpcrypt/pgpcrypt-desktop']
        assert 'unix:path=/tmp/pgpcrypt-no-session-bus' in args
        result = subprocess.run([str(wrapper)], env=dict(env, STUB_EXIT='23'), capture_output=True)
        assert result.returncode == 23, 'namespace errors must not start an unsandboxed app'
        shutil.rmtree(home / '.config')
        (home / '.config').symlink_to(home / '.cache', target_is_directory=True)
        assert subprocess.run([str(wrapper)], env=env, capture_output=True).returncode != 0
        (home / '.config').unlink()
        (home / '.config').mkdir()
        (home / '.config/host-sentinel').write_text('original')
        assert subprocess.run([str(wrapper), '--unexpected'], env=env, capture_output=True).returncode != 0
        print('Launcher arguments, spaced paths, symlink refusal and failure propagation passed.')

        bwrap = shutil.which('bwrap')
        assert bwrap, 'Install bubblewrap to check the launcher'
        # A real run must prove that writes to all overlays disappear and the
        # network namespace changed, rather than only inspecting command flags.
        net = os.readlink('/proc/self/ns/net')
        probe = root / 'probe'
        probe.write_text('''#!/usr/bin/python3
import json,os
from pathlib import Path
home=Path.home()
for name in ('.config','.local','.cache'):
    path=home/name
    assert not (path/'host-sentinel').exists()
    (path/'temporary-probe').write_text('temporary')
assert os.environ['XDG_CONFIG_HOME']==str(home/'.config')
assert os.readlink('/proc/self/ns/net')!=os.environ['HOST_NET']
Path(os.environ['PROBE_RESULT']).write_text('isolated')
''')
        probe.chmod(0o755)
        real = root / 'real-launcher'
        real.write_text(SOURCE.replace('/usr/lib/pgpcrypt/pgpcrypt-desktop', str(probe)))
        real.chmod(0o755)
        child = {}
        if os.geteuid() == 0:
            user = pwd.getpwnam('nobody')
            # Only this disposable fixture is writable by the reduced-privilege child.
            os.chown(root, user.pw_uid, user.pw_gid)
            for path in root.rglob('*'):
                if not path.is_symlink():
                    os.chown(path, user.pw_uid, user.pw_gid)
            child = {'user': user.pw_uid, 'group': user.pw_gid, 'extra_groups': []}
        realenv = dict(os.environ, HOME=str(home), HOST_NET=net, PROBE_RESULT=str(root/'isolation-result'))
        realenv.pop('XAUTHORITY', None)
        capability = subprocess.run([bwrap, '--unshare-user', '--unshare-net', '--ro-bind', '/', '/', '--', '/bin/true'], env=realenv, capture_output=True, text=True, **child)
        if capability.returncode:
            # Probe namespace support independently: do not misclassify bugs in
            # the actual launcher or display mounts as runner limitations.
            reasons=('Operation not permitted','No permissions to create new namespace','setting up uid map: Read-only file system','Permission denied')
            if any(reason in capability.stderr for reason in reasons):
                print('Real sandbox unavailable on this runner: '+capability.stderr.strip())
                return
            raise AssertionError(capability.stderr)
        result = subprocess.run([str(real)], env=realenv, capture_output=True, text=True, **child)
        assert result.returncode == 0, result.stderr
        assert (root/'isolation-result').read_text() == 'isolated'
        for name in ('.config', '.local', '.cache'):
            assert (home/name/'host-sentinel').read_text() == 'original'
            assert not (home/name/'temporary-probe').exists()
        print('Real Bubblewrap isolation passed: private state disappeared; host state unchanged; separate network namespace.')


if __name__ == '__main__':
    main()
