#!/usr/bin/env python3
"""Install one reviewed branding stage offline into a new disposable image."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from pe_resources import Resources

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vm'))
import xp_lab as lab

STAGES = {'system': ('system32/sysdm.cpl', 'system32/xpsp1res.dll', 'system32/winver.exe'),
          'explorer': ('explorer.exe',), 'shell': ('system32/shell32.dll',),
          'login': ('system32/logonui.exe',)}


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def verify_pair(old, new, changed):
    a, b = Resources(old), Resources(new)
    if any(list(key) not in changed and a.entries.get(key) != b.entries.get(key)
           for key in a.entries.keys() | b.entries.keys()):
        raise ValueError('unreviewed resource payload changed')
    for key, row in a.entries.items():
        if list(key) not in changed and b.entries.get(key) != row:
            raise ValueError('unreviewed resource payload changed')
        if key[0] == 16 and b.entries.get(key) != row:
            raise ValueError('VERSIONINFO changed')
    for index, (start, size, offset, count) in enumerate(a.pe.sections):
        if not start <= a.rva < start + size and a.pe.data[offset:offset + count] != b.pe.data[offset:offset + count]:
            raise ValueError('non-resource section changed')
        if not start <= a.rva < start + size and a.pe.sections[index] != b.pe.sections[index]:
            raise ValueError('non-resource section layout changed')
    for directory in range(16):
        if directory != 2 and a.pe.directory(directory) != b.pe.directory(directory):
            raise ValueError('non-resource PE directory changed')
    if a.pe.imports() != b.pe.imports() or a.pe.imports(True) != b.pe.imports(True) or a.pe.exports() != b.pe.exports():
        raise ValueError('imports/exports changed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--stage', choices=STAGES, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--restore', action='store_true', help='restore this stage in a new disposable overlay')
    parser.add_argument('--upgrade-from', type=Path, help='reviewed package whose files the base already carries')
    args = parser.parse_args()
    if args.restore and args.upgrade_from:
        parser.error('--restore and --upgrade-from are exclusive')
    base, package, output = args.base.resolve(), args.package.resolve(), args.output.resolve()
    if any(not p.is_relative_to(ROOT / '.work') for p in (base, package, output)):
        parser.error('branding work must remain private under .work/')
    if base.stat().st_mode & 0o222:
        parser.error('baseline must be a frozen read-only image')
    manifest = json.loads((package / 'manifest.json').read_text())
    previous = json.loads((args.upgrade_from.resolve() / 'manifest.json').read_text())['components'] if args.upgrade_from else None
    originals = Path(manifest['inputs']).resolve()
    if not originals.is_relative_to(ROOT / '.work'):
        parser.error('original extracted backups must remain private under .work/')
    output.mkdir(parents=True, exist_ok=False)
    os.chdir(output)
    before = sha(base)
    lab.run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', base, 'disk.qcow2'])
    records = {}
    with lab.partition(output / 'disk.qcow2', True) as device:
        for name in STAGES[args.stage]:
            row = manifest['components'][name]
            target = '/WINDOWS/' + name
            original = lab.run(['ntfscat', device, target])
            if previous:
                # Upgrade: the base carries the previous reviewed package's file.
                expected = previous[name]['sha256']
                if previous[name]['original_sha256'] != row['original_sha256']:
                    raise ValueError('packages were prepared from different originals: ' + name)
            else:
                expected = row['sha256'] if args.restore else row['original_sha256']
            if hashlib.sha256(original).hexdigest() != expected or sha(package / name) != row['sha256'] or sha(originals / name) != row['original_sha256']:
                raise ValueError('unrecognized original or prepared UI binary: ' + name)
            if previous and expected == row['sha256']:
                records[target] = {**row, 'unchanged_by_upgrade': True}
                continue
            backup = output / (('previous-' if previous else 'original-') + Path(name).name)
            backup.write_bytes(original)
            verify_pair(originals / name, package / name, row['changed_resources'])
            replacement = originals / name if args.restore else package / name
            guest_backup = ('/xp25/brand-%s-' % expected[:12] if previous else '/xp25/brand-original-') + Path(name).name
            lab.run(['ntfscp', '-t', device, backup, guest_backup])
            lab.run(['ntfscp', '-t', device, replacement, target])
            if lab.run(['ntfscat', device, target]) != replacement.read_bytes():
                raise ValueError('staged branding readback differs')
            records[target] = {**row, 'host_backup': str(backup), 'guest_backup': guest_backup}
    if sha(base) != before:
        raise ValueError('baseline hash changed')
    check = lab.run(['qemu-img', 'check', 'disk.qcow2'])
    (output / 'image-check.log').write_bytes(check)
    (output / 'disk.qcow2').chmod(0o444)
    (output / 'branding-install.json').write_text(json.dumps({'stage': args.stage, 'base': str(base),
        'base_sha256': before, 'package': str(package), 'components': records, 'restored': args.restore,
        'disk_sha256': sha(output / 'disk.qcow2'), 'guest_execution': 'not_attempted',
        'upgraded_from': str(args.upgrade_from.resolve()) if args.upgrade_from else None,
        'registry_changes': [], 'identity_changes': [], 'code_changes': []}, indent=2) + '\n')
    print(output / 'disk.qcow2')


if __name__ == '__main__':
    main()
