#!/usr/bin/env python3
"""Build the Milestone 8.2 engineering image: the accepted Milestone 8.1 image with the
rebuilt (patched) lsasrv.dll in place of the installed one. The 8.1 image is flattened into
a standalone copy (reflink, no backing file), then the patched binary overwrites the installed
lsasrv.dll offline with ntfscp (overwriting an existing file keeps its NTFS security
descriptor; only the file's content changes). The before/after SHA-256 of lsasrv.dll, the
parent image hash and the lineage are recorded. Source/ is never touched; no other file changes.

usage: cve_package_image.py --parent <8.1 image> --parent-sha256 <hex> \
         --lsasrv <patched lsasrv.dll> --collect <collect.json> --output .work/<fresh>"""
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
NAME = 'XP25-CVE-Hardened-8.2.qcow2'
TARGET = '/WINDOWS/system32/lsasrv.dll'


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
    parser.add_argument('--lsasrv', type=Path, required=True)
    parser.add_argument('--collect', type=Path, required=True, help='collect.json of the native lsasrv build')
    parser.add_argument('--name', default=NAME)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    parent, lsasrv, out = args.parent.resolve(), args.lsasrv.resolve(), args.output.resolve()
    if not out.is_relative_to(ROOT / '.work'):
        parser.error('private .work/ output required')
    if not parent.is_relative_to(ROOT / '.work') or parent.stat().st_mode & 0o222:
        parser.error('parent must be a frozen standalone .work/ image')
    info = json.loads(subprocess.check_output(['qemu-img', 'info', '--output=json', str(parent)]))
    if 'backing-filename' in info or sha(parent) != args.parent_sha256:
        parser.error('parent must be the unchanged standalone image matching --parent-sha256')
    collect = json.loads(args.collect.read_text())
    patched_sha = sha(lsasrv)
    recorded = next((v['sha256'] for k, v in collect.get('outputs', {}).items() if k.endswith('lsasrv.dll')), None)
    if collect.get('status') != 'accepted' or recorded != patched_sha:
        parser.error('lsasrv.dll does not match an accepted native build collection')
    out.mkdir(parents=True, exist_ok=False)
    os.chdir(out)   # lab.partition writes mbr/partition scratch files into the cwd; keep them out of the repo root
    image = out / args.name
    subprocess.run(['cp', '--reflink=always', str(parent), str(image)], check=True)
    image.chmod(0o644)
    with lab.partition(image, True) as device:
        before = lab.run(['ntfscat', device, TARGET])
        lab.run(['ntfscp', device, str(lsasrv), TARGET])
        after = lab.run(['ntfscat', device, TARGET])
    if hashlib.sha256(after).hexdigest() != patched_sha or after == before:
        raise SystemExit('offline replacement of lsasrv.dll did not take effect')
    check = subprocess.run(['qemu-img', 'check', str(image)], capture_output=True, text=True)
    (out / 'image-check.log').write_text(check.stdout + check.stderr)
    info = json.loads(subprocess.check_output(['qemu-img', 'info', '--output=json', str(image)]))
    if check.returncode or 'backing-filename' in info:
        raise SystemExit('flattened image failed verification')
    image.chmod(0o444)
    digest = sha(image)
    if sha(parent) != args.parent_sha256:
        raise SystemExit('parent changed during packaging')
    parent_manifest = json.loads((parent.parent / 'manifest.json').read_text()) if (parent.parent / 'manifest.json').is_file() else {}
    manifest = {
        'image': str(image), 'image_sha256': digest, 'bytes': image.stat().st_size, 'virtual_size': info['virtual-size'],
        'backing_file': None, 'milestone': '8.2',
        'parent_image': str(parent), 'parent_image_sha256': args.parent_sha256, 'parent_image_unchanged': True,
        'change': {'file': TARGET, 'installed_sha256_before': hashlib.sha256(before).hexdigest(),
                   'patched_sha256_after': patched_sha, 'bytes': len(after),
                   'cve': 'MS04-011 / CVE-2003-0533', 'build': collect.get('disk'),
                   'note': 'Only lsasrv.dll content changed; its NTFS security descriptor is preserved (ntfscp overwrite).'},
        'native_lsasrv_build': collect,
        'lineage': (parent_manifest.get('lineage') or []) + [{'image': str(parent), 'sha256': args.parent_sha256},
                                                             {'image': str(image), 'sha256': digest,
                                                              'change': 'patched lsasrv.dll (MS04-011)'}],
        'image_check': check.stdout.strip().splitlines()[-1:],
        'rollback': 'Boot an overlay of the parent Milestone 8.1 image (lsasrv.dll is a binary replacement, '
                    'not part of the XP25Sec baseline rollback).',
        'scope': 'Private engineering disk: the Milestone 8.1 hardened image with the rebuilt lsasrv.dll that fixes '
                 'MS04-011 (CVE-2003-0533). Not Windows Setup media; no redistribution claim. Keep off unrestricted networks.'}
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (out / 'README.txt').write_text(
        'XP25 Milestone 8.2 engineering disk: ' + args.name + '\n\nSHA-256 ' + digest + '\n'
        'Parent (Milestone 8.1, unchanged): ' + str(parent) + '\n  SHA-256 ' + args.parent_sha256 + '\n\n'
        'Change from the parent: lsasrv.dll replaced by the rebuilt binary that fixes MS04-011 (CVE-2003-0533).\n'
        'Keep this QCOW2 read-only; boot only an overlay. Use an isolated network.\n'
        'Shut down through Start > Turn Off Computer. Do not run sfc /scannow.\n'
        'See docs/historical-cve-audit.md and docs/historical-cve-remediation.md.\n')
    print(json.dumps({k: manifest[k] for k in ('image', 'image_sha256', 'bytes', 'change')}, indent=2))


if __name__ == '__main__':
    main()
