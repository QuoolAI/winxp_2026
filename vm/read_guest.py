#!/usr/bin/env python3
"""Extract recorded files from a frozen private NTFS guest without booting it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import xp_lab as lab

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('disk', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('files', nargs='+')
    args = parser.parse_args()
    disk, output = args.disk.resolve(), args.output.resolve()
    if not disk.is_relative_to(ROOT / '.work') or disk.stat().st_mode & 0o222:
        parser.error('disk must be a frozen private image')
    if not output.is_relative_to(ROOT / '.work'):
        parser.error('private extraction must remain under .work/')
    for name in args.files:
        if not name.startswith('/') or '..' in Path(name).parts:
            parser.error('absolute guest paths without traversal required')
    output.mkdir(parents=True, exist_ok=False)
    os.chdir(output)
    records = []
    try:
        with lab.partition(disk, False) as device:
            for name in args.files:
                try:
                    data = lab.run(['ntfscat', device, name])
                except RuntimeError as error:
                    records.append({'guest_path': name, 'error': str(error)})
                    continue
                target = output / name.lstrip('/')
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                records.append({'guest_path': name, 'bytes': len(data),
                                'sha256': hashlib.sha256(data).hexdigest()})
    finally:
        (output / 'files.json').write_text(json.dumps({'disk': str(disk), 'files': records}, indent=2) + '\n')
    return 2 if any('error' in row for row in records) else 0


if __name__ == '__main__':
    raise SystemExit(main())
