#!/usr/bin/env python3
"""Build an engineering image that carries a rebuilt XP25 winlogon.exe: a standalone reflink
copy of a frozen accepted image with only /WINDOWS/system32/winlogon.exe overwritten offline
(ntfscp keeps the file's NTFS security descriptor; only its content changes). The installed
winlogon.exe must be the expected one before the change and the rebuilt one after it; the
replacement must match the read_guest collection (files.json) of its native build. The parent
image is never written. Source/ is never touched.

usage: winlogon_package_image.py --parent <frozen .work/ image> --parent-sha256 <hex> \
         --expect-installed <hex> --winlogon <winlogon.exe> --collect <files.json> \
         --name <image>.qcow2 --output .work/<fresh>"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vm'))
import xp_lab as lab
TARGET = '/WINDOWS/system32/winlogon.exe'


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 22), b''):
            h.update(block)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, required=True)
    parser.add_argument('--parent-sha256', required=True)
    parser.add_argument('--expect-installed', required=True, help='SHA-256 of the winlogon.exe the parent carries')
    parser.add_argument('--winlogon', type=Path, required=True)
    parser.add_argument('--collect', type=Path, required=True, help='files.json of the native winlogon build')
    parser.add_argument('--name', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    parent, winlogon, out = args.parent.resolve(), args.winlogon.resolve(), args.output.resolve()
    if not out.is_relative_to(ROOT / '.work'):
        parser.error('private .work/ output required')
    if not parent.is_relative_to(ROOT / '.work') or parent.stat().st_mode & 0o222:
        parser.error('parent must be a frozen standalone .work/ image')
    info = json.loads(subprocess.check_output(['qemu-img', 'info', '--output=json', str(parent)]))
    if 'backing-filename' in info or sha(parent) != args.parent_sha256:
        parser.error('parent must be the unchanged standalone image matching --parent-sha256')
    rebuilt = sha(winlogon)
    collected = [f['sha256'] for f in json.loads(args.collect.read_text()).get('files', [])
                 if f.get('guest_path', '').endswith('/winlogon.exe')]
    if collected != [rebuilt]:
        parser.error('winlogon.exe does not match its native build collection')
    out.mkdir(parents=True, exist_ok=False)
    os.chdir(out)   # lab.partition writes mbr/partition scratch files into the cwd
    image = out / args.name
    subprocess.run(['cp', '--reflink=always', str(parent), str(image)], check=True)
    image.chmod(0o644)
    with lab.partition(image, True) as device:
        before = lab.run(['ntfscat', device, TARGET])
        if hashlib.sha256(before).hexdigest() != args.expect_installed:
            raise SystemExit('installed winlogon.exe is not the expected one')
        lab.run(['ntfscp', device, str(winlogon), TARGET])
        after = lab.run(['ntfscat', device, TARGET])
    if hashlib.sha256(after).hexdigest() != rebuilt:
        raise SystemExit('offline replacement of winlogon.exe did not take effect')
    check = subprocess.run(['qemu-img', 'check', str(image)], capture_output=True, text=True)
    (out / 'image-check.log').write_text(check.stdout + check.stderr)
    info = json.loads(subprocess.check_output(['qemu-img', 'info', '--output=json', str(image)]))
    if check.returncode or 'backing-filename' in info:
        raise SystemExit('flattened image failed verification')
    image.chmod(0o444)
    digest = sha(image)
    if sha(parent) != args.parent_sha256:
        raise SystemExit('parent changed during packaging')
    manifest = {
        'image': str(image), 'image_sha256': digest, 'bytes': image.stat().st_size,
        'virtual_size': info['virtual-size'], 'backing_file': None,
        'parent_image': str(parent), 'parent_image_sha256': args.parent_sha256, 'parent_image_unchanged': True,
        'change': {'file': TARGET, 'installed_sha256_before': args.expect_installed,
                   'rebuilt_sha256_after': rebuilt, 'bytes': len(after), 'collect': str(args.collect.resolve()),
                   'note': 'Only winlogon.exe content changed; its NTFS security descriptor is preserved (ntfscp overwrite).'},
    }
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=1) + '\n')
    print(json.dumps({'image': str(image), 'sha256': digest}))


if __name__ == '__main__':
    main()
