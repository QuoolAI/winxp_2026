#!/usr/bin/env python3
"""Prepare native NT build media for the XP25 security components: only
components/security and the build driver, as an ISO for the private build VM.
The reference tree under Source/ is not copied or modified."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def make_tree(source, out, media):
    """The security build tree media/security from the repository at source (CR LF line ends)."""
    tree = media / 'security'
    shutil.copytree(source / 'components/security', tree, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    for f in tree.rglob('*'):
        if f.is_file():
            f.write_bytes(f.read_bytes().replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))
    return {}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    if not out.is_relative_to(ROOT / '.work'):
        parser.error('private .work/ output required')
    out.mkdir(parents=True, exist_ok=False)
    media = out / 'media'
    make_tree(ROOT, out, media)
    (media / 'build.cmd').write_bytes((ROOT / 'build/native-security-build.cmd').read_bytes()
                                      .replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))
    iso = out / 'native-security.iso'
    command = ['xorriso', '-as', 'mkisofs', '-quiet', '-iso-level', '3', '-J', '-R', '-V', 'XP25SEC', '-o', str(iso), str(media)]
    subprocess.run(command, check=True)
    files = {str(f.relative_to(media)): hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(media.rglob('*')) if f.is_file()}
    sources = {str(f.relative_to(ROOT)): hashlib.sha256(f.read_bytes()).hexdigest()
               for f in sorted((ROOT / 'components/security').rglob('*')) if f.is_file()}
    (out / 'manifest.json').write_text(json.dumps({'command': command, 'iso_sha256': hashlib.sha256(iso.read_bytes()).hexdigest(),
                                                   'files': files, 'repository_sources': sources,
                                                   'scope': 'XP25 security sources only (CR LF line ends on the media); Source/ unchanged.'},
                                                  indent=2) + '\n')
    print(iso)


if __name__ == '__main__':
    main()
