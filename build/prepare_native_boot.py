#!/usr/bin/env python3
"""Prepare private media for the verified checked-x86 kernel compatibility build."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from apply_boot_compat import prepare as boot_patch
from apply_pointer_compat import prepare as pointer_patch

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / 'Source/XPSP1/NT'
PREBUILT = {
    'base/ntos/ex/up/obj/i386/exinit.obj': '84c255e854f8c9cd9e15e6a362e1c6a487badb76c00aca0e43f9b736c96bcec0',
    'base/ntos/ex/up/obj/i386/systime.obj': 'aba6688d9c5f1a60322cd62836eb94290ffc2042b19c5f9ec0bcf71929bae33a',
    'base/ntos/ex/mp/obj/i386/exinit.obj': '84819fe430bd37482abb5e0d013bdb5c9fc08ec3fecd27204eeb3e6e6b177d7f',
    'base/ntos/ex/mp/obj/i386/systime.obj': 'd653662b2bf7513c8e8c685d46ae851b08b277de09734cad12e609bd77633443',
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / '.work'):
        parser.error('Generated source/media must stay under .work/')
    output.mkdir(parents=True, exist_ok=False)
    media = output / 'media'
    media.mkdir()
    manifest = {'scope': 'checked x86 kernel, HALs, ntdll and Kernel32',
                'requires': 'existing disposable C:\\nt native build copy with prepared prerequisites',
                'limitation': 'Four supplied executive objects remain required; corresponding C sources absent.',
                'patched_files': {}, 'prebuilt_objects': PREBUILT, 'commands': []}
    copies = ['@echo off']
    for label, prepare in [('boot', boot_patch), ('pointer', pointer_patch)]:
        patch = output / (label + '-patch')
        for name, row in prepare(patch).items():
            destination = media / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(patch / name, destination)
            manifest['patched_files'][name] = row
            win = name.replace('/', '\\')
            copies += ['copy /b /y "%~dp0' + win + '" "C:\\nt\\' + win + '" >nul',
                       'if errorlevel 1 exit /b 1']
    restores = ['@echo off']
    for name, expected in PREBUILT.items():
        source = REFERENCE / name
        if sha(source) != expected:
            raise ValueError('Unrecognized supplied object: ' + name)
        destination = media / 'prebuilt' / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        win = name.replace('/', '\\')
        restores += ['copy /b /y "%~dp0prebuilt\\' + win + '" "C:\\nt\\' + win + '" >nul',
                     'if errorlevel 1 exit /b 1']
    for filename, lines in [('apply.cmd', copies), ('restore.cmd', restores)]:
        (media / filename).write_bytes(('\r\n'.join(lines + ['exit /b 0']) + '\r\n').encode('ascii'))
    batch = ROOT / 'build/native-boot-build.cmd'
    (media / 'build.cmd').write_bytes(batch.read_text().replace('\n', '\r\n').encode('ascii'))
    command = ['genisoimage', '-quiet', '-J', '-r', '-o', str(output / 'native-boot.iso'), str(media)]
    subprocess.run(command, check=True)
    manifest['commands'].append(command)
    manifest['media_files'] = {str(p.relative_to(media)): sha(p) for p in sorted(media.rglob('*')) if p.is_file()}
    manifest['iso_sha256'] = sha(output / 'native-boot.iso')
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(output / 'native-boot.iso')


if __name__ == '__main__':
    main()
