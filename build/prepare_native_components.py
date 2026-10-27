#!/usr/bin/env python3
"""Pin original component inputs in private native build media; never edit Source/."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / 'Source/XPSP1/NT'
DIRECTORIES = ('base/screg/sc/server', 'base/screg/sc/svcslib', 'base/screg/sc/lib',
               'base/screg/sc/inc', 'base/screg/winreg/server', 'base/screg/winreg/lib',
               'base/pnp/idl', 'base/pnp/umpnpmgr')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--candidates', action='store_true', help='compile candidate targets without installing them')
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / '.work'):
        parser.error('private media must remain under .work/')
    output.mkdir(parents=True, exist_ok=False)
    media = output / 'media'
    media.mkdir()
    sources = {}
    patches = {}
    lines = ['@echo off']
    directories = DIRECTORIES if not args.candidates else (
        'base/subsys/sm/server', 'base/screg/winreg/regconn', 'base/screg/winreg/regsvc',
        'ds/security/gina/common', 'ds/security/gina/msgina',
        'ds/security/gina/idl', 'ds/security/gina/rsoputil', 'ds/security/gina/userenv',
        'shell/published/inc', 'shell/lib/shguid', 'shell/lib/ieguid', 'shell/explorer/winnt')
    for directory in directories:
        for source in sorted((REFERENCE / directory).iterdir()):
            if not source.is_file():
                continue
            relative = source.relative_to(REFERENCE)
            target = media / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            sources[str(relative)] = sha(source)
            if directory == 'shell/published/inc' and source.suffix.lower() in ('.w', '.idl', '.odl'):
                data = source.read_bytes().replace(b'\r\n', b'\n')
                target.write_bytes(data.replace(b'\n', b'\r\n'))
                patches[str(relative)] = {'original_sha256': sha(source), 'patched_sha256': sha(target),
                                          'reason': 'Original HSPLIT scans CR-delimited tags; normalize its input only in the native build copy.'}
            win = str(relative).replace('/', '\\')
            lines += ['copy /b /y "%~dp0' + win + '" "C:\\nt\\' + win + '" >nul',
                      'if errorlevel 1 exit /b 1']
    if args.candidates:
        relative = 'public/sdk/inc/comdef.h'
        source = REFERENCE / relative
        data = source.read_bytes()
        old = b'#if defined(_COM_SMARTPTR_LEVEL2\n'
        if data.count(old) != 1:
            raise ValueError('unrecognized original comdef.h syntax defect')
        target = media / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data.replace(old, b'#if defined(_COM_SMARTPTR_LEVEL2)\n'))
        patches[relative] = {'original_sha256': sha(source), 'patched_sha256': sha(target),
                             'reason': 'Restore one missing closing parenthesis in the original preprocessor conditional.'}
        lines += ['copy /b /y "%~dp0public\\sdk\\inc\\comdef.h" "C:\\nt\\public\\sdk\\inc\\comdef.h" >nul',
                  'if errorlevel 1 exit /b 1']
    (media / 'apply.cmd').write_bytes(('\r\n'.join(lines + ['exit /b 0']) + '\r\n').encode('ascii'))
    batch = ROOT / 'build' / ('native-candidates-build.cmd' if args.candidates else 'native-components-build.cmd')
    (media / 'build.cmd').write_bytes(batch.read_text().replace('\n', '\r\n').encode('ascii'))
    command = ['genisoimage', '-quiet', '-J', '-r', '-o', str(output / 'native-components.iso'), str(media)]
    subprocess.run(command, check=True)
    manifest = {'reference': str(REFERENCE), 'sources': sources, 'patches': patches, 'command': command,
                'requires': 'prepared native C:\\nt with build-24 SCM/Winreg RPC prerequisites',
                'iso_sha256': sha(output / 'native-components.iso'),
                'files': {str(p.relative_to(media)): sha(p) for p in media.rglob('*') if p.is_file()}}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(output / 'native-components.iso')


if __name__ == '__main__':
    main()
