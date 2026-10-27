#!/usr/bin/env python3
"""Pause a lab guest, save its registers and raw physical memory, then resume it.

Read-only with respect to the guest; pass --keep-paused to leave it stopped.
Output files are written into a fresh private directory under .work/.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import xp_lab as lab

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path, help='experiment directory containing qmp.sock')
    parser.add_argument('output', type=Path)
    parser.add_argument('--size', type=lambda v: int(v, 0), default=0x20000000)
    parser.add_argument('--keep-paused', action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / '.work'):
        parser.error('private .work/ output required')
    output.mkdir(parents=True, exist_ok=False)
    os.chdir(args.directory.resolve())
    with lab.QMP() as q:
        before = q.call('query-status')
        q.call('stop')
        (output / 'registers.txt').write_text(q.hmp('info registers'))
        q.call('pmemsave', {'val': 0, 'size': args.size, 'filename': str(output / 'memory.raw')})
        if not args.keep_paused and before.get('running'):
            q.call('cont')
    digest = hashlib.sha256((output / 'memory.raw').read_bytes()).hexdigest()
    (output / 'capture.json').write_text(json.dumps({'directory': str(args.directory.resolve()), 'status_before': before,
        'size': args.size, 'memory_sha256': digest, 'resumed': bool(before.get('running')) and not args.keep_paused}, indent=2) + '\n')
    print(output)


if __name__ == '__main__':
    main()
