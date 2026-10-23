#!/usr/bin/env python3
"""Package current, statically verified probes for private XP runtime tests."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('xp', 'network', 'pointer', 'session'):
        parser.add_argument('--' + name, type=Path, required=True, help='probe build output directory')
    parser.add_argument('--service', type=Path, help='optional statically verified SCM fixture probe')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / '.work'):
        parser.error('private media must remain under .work/')
    # Check provenance before creating output. Never repackage a stale probe.
    probes = {}
    for name in ('xp', 'network', 'pointer', 'session') + (('service',) if args.service else ()):
        directory = getattr(args, name).resolve()
        result = json.loads((directory / 'result.json').read_text())
        executable = directory / (name + '_probe.exe')
        if (result['status'] != 'compiled_static_checks_passed' or
                result['source_sha256'] != sha(ROOT / ('tests/guest/' + name + '_probe.c')) or
                result['executable_sha256'] != sha(executable)):
            parser.error('probe is stale or unverified: ' + name)
        probes[name] = executable
    output.mkdir(parents=True, exist_ok=False)
    media = output / 'media'
    media.mkdir()
    for executable in probes.values():
        shutil.copy2(executable, media / executable.name)
    for source, target in [('network-regression.cmd', 'regress.cmd'),
                           ('network-stability.cmd', 'stability.cmd')]:
        (media / target).write_bytes((ROOT / 'tests/guest' / source).read_text().replace('\n', '\r\n').encode('ascii'))
    if args.service:
        with (media / 'regress.cmd').open('ab') as script:
            script.write(b'"%~dp0service_probe.exe"\r\necho SERVICE_PROBE_EXIT=%ERRORLEVEL% > COM1\r\necho COMPONENT_REGRESSION_FINISHED > COM1\r\n')
        (media / 'arm-shutdown.cmd').write_bytes(b'@echo off\r\nif exist C:\\xp25\\service-shutdown.txt del /q C:\\xp25\\service-shutdown.txt\r\nif exist C:\\xp25\\service-shutdown.txt exit /b 1\r\necho SHUTDOWN_PROOF_CLEARED > COM1\r\n"%~dp0service_probe.exe" --shutdown-arm\r\necho SHUTDOWN_PROBE_EXIT=%ERRORLEVEL% > COM1\r\n')
    command = ['genisoimage', '-quiet', '-J', '-r', '-o', str(output / 'network-tests.iso'), str(media)]
    subprocess.run(command, check=True)
    manifest = {'command': command, 'iso_sha256': sha(output / 'network-tests.iso'),
                'files': {p.name: sha(p) for p in sorted(media.iterdir())}}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(output / 'network-tests.iso')


if __name__ == '__main__':
    main()
