#!/usr/bin/env python3
"""Create private native wshtcpip build media from the immutable NT 5.1 source."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / 'Source/XPSP1/NT'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / '.work'):
        parser.error('private source and generated media must remain under .work/')
    output.mkdir(parents=True, exist_ok=False)
    media = output / 'media'
    media.mkdir()
    lines = ['@echo off']
    sources = {}
    for source in sorted((REFERENCE / 'net/tcpip/winsock').iterdir()):
        if not source.is_file():
            continue
        relative = source.relative_to(REFERENCE)
        target = media / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        sources[str(relative)] = sha(source)
        win = str(relative).replace('/', '\\')
        lines += ['copy /b /y "%~dp0' + win + '" "C:\\nt\\' + win + '" >nul',
                  'if errorlevel 1 exit /b 1']
    lines += ['exit /b 0']
    (media / 'apply.cmd').write_bytes(('\r\n'.join(lines) + '\r\n').encode('ascii'))
    for source, name in [(ROOT / 'build/native-network-build.cmd', 'build.cmd'),
                         (ROOT / 'build/native-scm-prepare.cmd', 'scm-prepare.cmd')]:
        (media / name).write_bytes(source.read_text().replace('\n', '\r\n').encode('ascii'))
    command = ['genisoimage', '-quiet', '-J', '-r', '-o', str(output / 'native-network.iso'), str(media)]
    subprocess.run(command, check=True)
    manifest = {'reference': str(REFERENCE), 'sources': sources, 'command': command,
                'requires': 'prepared disposable native x86 C:\\nt build VM',
                'iso_sha256': sha(output / 'native-network.iso'),
                'files': {str(p.relative_to(media)): sha(p) for p in media.rglob('*') if p.is_file()}}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(output / 'native-network.iso')


if __name__ == '__main__':
    main()
