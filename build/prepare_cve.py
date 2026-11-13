#!/usr/bin/env python3
"""Prepare native build media for Milestone 8.2 source fixes.

The media carries, for the selected patches (components/cve/patches.json), every
audited original file and its patched copy, the build directories and the expected
outputs, and build/native-cve-build.cmd. In the build VM the driver checks every
original against the disposable C:\\nt copy byte for byte, installs the patched
copies, and rebuilds only the listed directories with build -cZ.

--control produces the same media without patched copies: the same directories are
rebuilt from the unchanged sources, so a control and a patched build differ only by
the patch (plus link time stamps). Source/ is never written.

usage: prepare_cve.py --output .work/<fresh> --patch ID [--patch ID ...] [--control]"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build'))
import cve_source


def crlf(lines):
    return ''.join(line + '\r\n' for line in lines).encode('latin-1')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--patch', action='append', required=True)
    parser.add_argument('--control', action='store_true')
    args = parser.parse_args()
    out = args.output.resolve()
    if not out.is_relative_to(ROOT / '.work'):
        parser.error('private .work/ output required')
    entries = cve_source.patch_entries(args.patch)
    files = cve_source.patched_files(args.patch)
    dirs, outputs = [], []
    for entry in entries:
        dirs += [d for d in entry['build_dirs'] if d not in dirs]
        outputs += [o for o in entry['outputs'] if o not in outputs]
    out.mkdir(parents=True, exist_ok=False)
    media = out / 'media'
    record = {'patches': [e['id'] for e in entries], 'control': args.control, 'dirs': dirs, 'outputs': outputs, 'files': {}}
    for path, (original, patched, applied) in sorted(files.items()):
        (media / 'original' / path).parent.mkdir(parents=True, exist_ok=True)
        (media / 'original' / path).write_bytes(original.encode('latin-1'))
        record['files'][path] = {'original_sha256': cve_source.sha256_text(original), 'patches': applied}
        if not args.control:
            (media / 'patched' / path).parent.mkdir(parents=True, exist_ok=True)
            (media / 'patched' / path).write_bytes(patched.encode('latin-1'))
            record['files'][path]['patched_sha256'] = cve_source.sha256_text(patched)
    windows = [p.replace('/', '\\') for p in sorted(files)]
    (media / 'originals.txt').write_bytes(crlf(windows))
    (media / 'files.txt').write_bytes(crlf([] if args.control else windows))
    (media / 'dirs.txt').write_bytes(crlf(dirs))
    (media / 'outputs.txt').write_bytes(crlf(outputs))
    (media / 'build.cmd').write_bytes((ROOT / 'build/native-cve-build.cmd').read_bytes()
                                      .replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))
    iso = out / 'native-cve.iso'
    command = ['xorriso', '-as', 'mkisofs', '-quiet', '-iso-level', '3', '-J', '-R', '-V', 'XP25CVE', '-o', str(iso), str(media)]
    subprocess.run(command, check=True)
    record['command'] = command
    record['iso_sha256'] = hashlib.sha256(iso.read_bytes()).hexdigest()
    record['scope'] = 'Listed files only; build -cZ in the listed directories of the build VM copy; Source/ unchanged.'
    (out / 'manifest.json').write_text(json.dumps(record, indent=1) + '\n')
    print(iso)


if __name__ == '__main__':
    main()
