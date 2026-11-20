#!/usr/bin/env python3
"""Build an engineering image with a set of rebuilt files: a standalone reflink copy of a
frozen image with only the named guest files overwritten offline (ntfscp keeps each file's
NTFS security descriptor; only its content changes). For every file the installed copy must
be the expected one before the change and the rebuilt one after it, and the rebuilt file
must appear in its native build's collection record: a read_guest files.json, or a
cve_collect_native collect.json with status "accepted" and no problems. The parent image is
never written. Source/ is never touched. build/winlogon_package_image.py is the
winlogon.exe-only form of this tool.

usage: package_image.py --parent <frozen .work/ image> --parent-sha256 <hex> \
         --replace /WINDOWS/system32/NAME=<file>,<expected installed sha256>,<collection json> [...] \
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


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 22), b''):
            h.update(block)
    return h.hexdigest()


def collected(record, digest):
    """Whether a build collection record lists this SHA-256 as one of its outputs."""
    data = json.loads(Path(record).read_text())
    if 'status' in data and (data['status'] != 'accepted' or data.get('problems')):
        return False
    hashes = [f.get('sha256') for f in data.get('files', [])]
    hashes += [o.get('sha256') for o in data.get('outputs', {}).values()] if isinstance(data.get('outputs'), dict) else []
    return digest in hashes


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--parent', type=Path, required=True)
    parser.add_argument('--parent-sha256', required=True)
    parser.add_argument('--replace', action='append', required=True, metavar='GUEST=FILE,EXPECTED,COLLECTION')
    parser.add_argument('--name', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    parent, out = args.parent.resolve(), args.output.resolve()
    if not out.is_relative_to(ROOT / '.work'):
        parser.error('private .work/ output required')
    if not parent.is_relative_to(ROOT / '.work') or parent.stat().st_mode & 0o222:
        parser.error('parent must be a frozen standalone .work/ image')
    changes = []
    for item in args.replace:
        target, _, rest = item.partition('=')
        parts = rest.split(',')
        if not target.startswith('/WINDOWS/') or '..' in Path(target).parts or len(parts) != 3:
            parser.error('--replace takes /WINDOWS/...=FILE,EXPECTED_SHA256,COLLECTION_JSON: ' + item)
        source, expected, record = Path(parts[0]).resolve(), parts[1].lower(), Path(parts[2]).resolve()
        if not source.is_relative_to(ROOT / '.work') or not source.is_file() or not record.is_file():
            parser.error('replacement and collection must be private .work/ files: ' + item)
        digest = sha(source)
        if not collected(record, digest):
            parser.error('%s does not match its native build collection %s' % (source, record))
        changes.append({'file': target, 'source': str(source), 'rebuilt_sha256': digest,
                        'installed_sha256_before': expected, 'collection': str(record)})
    if len({c['file'].lower() for c in changes}) != len(changes):
        parser.error('a guest file is named twice')
    info = json.loads(subprocess.check_output(['qemu-img', 'info', '--output=json', str(parent)]))
    if 'backing-filename' in info or sha(parent) != args.parent_sha256:
        parser.error('parent must be the unchanged standalone image matching --parent-sha256')
    out.mkdir(parents=True, exist_ok=False)
    os.chdir(out)   # lab.partition writes mbr/partition scratch files into the cwd
    image = out / args.name
    subprocess.run(['cp', '--reflink=always', str(parent), str(image)], check=True)
    image.chmod(0o644)
    with lab.partition(image, True) as device:
        for change in changes:
            before = lab.run(['ntfscat', device, change['file']])
            if hashlib.sha256(before).hexdigest() != change['installed_sha256_before']:
                raise SystemExit('installed %s is not the expected one' % change['file'])
        for change in changes:
            lab.run(['ntfscp', device, change['source'], change['file']])
        for change in changes:
            after = lab.run(['ntfscat', device, change['file']])
            if hashlib.sha256(after).hexdigest() != change['rebuilt_sha256']:
                raise SystemExit('offline replacement of %s did not take effect' % change['file'])
            change['bytes'] = len(after)
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
        'changes': changes,
        'note': 'Only the listed files changed content; their NTFS security descriptors are preserved (ntfscp overwrite).',
    }
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=1) + '\n')
    print(json.dumps({'image': str(image), 'sha256': digest}))


if __name__ == '__main__':
    main()
