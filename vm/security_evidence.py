#!/usr/bin/env python3
"""Storage management for the XP25 security evidence roots.

  inventory ROOT...   classify every file, map every QCOW2 backing chain on the
                      volume (headers are read directly, nothing is opened by
                      QEMU), and report shared/exclusive space (btrfs)
  reclaim ROOT...     --report FILE: do only what the inventory proved safe,
                      and record every action with hashes:
                        * delete a screenshot .ppm whose .png twin holds the
                          same pixels (checked pixel by pixel first)
                        * compress, with btrfs zstd, files that share no extent
                          with another file (frozen run disks, logs), keeping
                          their bytes: SHA-256 before and after must match and
                          the read-only mode is restored
                      Never deleted: QCOW2 files, anything a QCOW2 backs, any
                      image, manifest, result, serial log, capture or
                      failure.json. Accepted images and the reference base are
                      shared with each other through reflinks and are left as
                      they are (compressing them would un-share them).

usage: security_evidence.py inventory|reclaim ROOT [ROOT...] --report FILE"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
VOLUME = ROOT.parent
NEVER_DELETE = re.compile(r'\.(qcow2|iso|json|jsonl|log|pcap|txt|exe|dll|sys|pdb|map|cmd)$', re.I)


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 22), b''):
            h.update(block)
    return h.hexdigest()


def backing(path):
    try:
        with open(path, 'rb') as f:
            head = f.read(32)
            if head[:4] != b'QFI\xfb':
                return None
            offset, size = struct.unpack('>QI', head[8:20])
            if not offset or not size:
                return ''
            f.seek(offset)
            return f.read(size).decode('utf-8', 'replace')
    except OSError:
        return None


def all_qcow2():
    """Every QCOW2 file on the volume except the container stores, with its backing file."""
    found = {}
    skip = {VOLUME / 'containers', VOLUME / 'containers-snapshots'}
    for directory, subdirs, files in os.walk(VOLUME):
        here = Path(directory)
        subdirs[:] = [d for d in subdirs if here / d not in skip]
        for name in files:
            if name.endswith('.qcow2'):
                path = here / name
                found[str(path)] = backing(path)
    return found


def btrfs_usage(path):
    out = subprocess.run(['btrfs', 'filesystem', 'du', '-s', '--raw', str(path)], capture_output=True, text=True)
    numbers = out.stdout.strip().splitlines()[-1].split() if out.returncode == 0 else []
    return {'total': int(numbers[0]), 'exclusive': int(numbers[1]), 'shared': int(numbers[2])} if len(numbers) >= 3 else None


def exclusive(path):
    usage = btrfs_usage(path)
    return usage is not None and usage['shared'] == 0


def same_pixels(ppm, png):
    from PIL import Image
    a, b = Image.open(ppm), Image.open(png)
    return a.size == b.size and a.convert('RGB').tobytes() == b.convert('RGB').tobytes()


def inventory(roots):
    chains = all_qcow2()
    backs = {}
    for overlay, base in chains.items():
        if base:
            backs.setdefault(str(Path(base).resolve()), []).append(overlay)
    report = {'roots': [str(r) for r in roots], 'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'usage_before': {},
              'qcow2_on_volume': len(chains), 'backing_files_in_roots': {}, 'outside_dependents': {},
              'ppm_with_png_twin': [], 'compressible': [], 'kept_shared': [], 'images': []}
    for root in roots:
        report['usage_before'][str(root)] = btrfs_usage(root)
        for path in sorted(root.rglob('*')):
            if not path.is_file() or path.is_symlink():
                continue
            text = str(path)
            dependents = backs.get(str(path.resolve()), [])
            if dependents:
                report['backing_files_in_roots'][text] = dependents
                outside = [d for d in dependents if not any(d.startswith(str(r)) for r in roots)]
                if outside:
                    report['outside_dependents'][text] = outside
            if path.suffix == '.qcow2' and path.parent.name.startswith('image'):
                report['images'].append(text)
            if path.suffix == '.ppm' and path.with_suffix('.png').is_file():
                report['ppm_with_png_twin'].append(text)
            elif path.stat().st_size >= 64 << 20:
                (report['compressible'] if exclusive(path) else report['kept_shared']).append(text)
    return report


def reclaim(roots, plan):
    actions = []
    for text in plan['ppm_with_png_twin']:
        ppm = Path(text)
        png = ppm.with_suffix('.png')
        if NEVER_DELETE.search(ppm.name) or not ppm.is_file() or not png.is_file():
            continue
        if same_pixels(ppm, png):
            size = ppm.stat().st_size
            ppm.unlink()
            actions.append({'action': 'deleted duplicate screenshot', 'path': text, 'bytes': size, 'kept': str(png)})
        else:
            actions.append({'action': 'kept (pixels differ)', 'path': text})
    for text in plan['compressible']:
        path = Path(text)
        if text in plan['backing_files_in_roots'] and plan['outside_dependents'].get(text):
            actions.append({'action': 'skipped (backs an overlay outside the roots)', 'path': text})
            continue
        if not exclusive(path):
            actions.append({'action': 'skipped (shares extents now)', 'path': text})
            continue
        before_hash, mode = sha(path), path.stat().st_mode
        before = btrfs_usage(path)
        path.chmod(mode | 0o200)
        try:
            run = subprocess.run(['btrfs', 'filesystem', 'defragment', '-czstd', str(path)], capture_output=True, text=True)
        finally:
            path.chmod(mode)
        after_hash = sha(path)
        if after_hash != before_hash:
            raise SystemExit('content changed while compressing ' + text)
        actions.append({'action': 'compressed (zstd)', 'path': text, 'sha256': after_hash, 'mode': oct(mode & 0o777), 'returncode': run.returncode,
                        'stderr': run.stderr.strip()[:200], 'usage_before': before, 'usage_after': btrfs_usage(path)})
    return actions


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('action', choices=('inventory', 'reclaim'))
    parser.add_argument('roots', nargs='+', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    roots = [r.resolve() for r in args.roots]
    for root in roots:
        if not root.is_relative_to(ROOT / '.work') or not root.is_dir():
            parser.error('roots must be directories under .work/')
    report = inventory(roots)
    if args.action == 'reclaim':
        if report['outside_dependents']:
            print(json.dumps(report['outside_dependents'], indent=1))
        report['actions'] = reclaim(roots, report)
        subprocess.run(['sync'])
        report['usage_after'] = {str(r): btrfs_usage(r) for r in roots}
    args.report.write_text(json.dumps(report, indent=1) + '\n')
    summary = {k: (len(v) if isinstance(v, (list, dict)) else v) for k, v in report.items() if k not in ('usage_before', 'usage_after')}
    print(json.dumps({'summary': summary, 'usage_before': report['usage_before'], 'usage_after': report.get('usage_after')}, indent=1))


if __name__ == '__main__':
    sys.exit(main())
