#!/usr/bin/env python3
"""Make the regression media usable on an image without the VBScript engine.

The frozen native-tests.iso builds its fixture MSI with msi-build.vbs, which needs
vbscript.dll. On an image with IE removed (build/ie_removal.py) this copy runs the
native msibuild_probe.exe instead, which imports the same .idt tables through
msi.dll. Every other file is byte-identical to the frozen media; the manifest
records both hashes of the one changed file."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SCRIPTED = b'cscript //nologo D:\\msi-build.vbs > C:\\xp25\\msi-build.log 2>&1'
NATIVE = b'D:\\msibuild_probe.exe > C:\\xp25\\msi-build.log 2>&1'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base-iso', type=Path, required=True)
    p.add_argument('--base-sha256', required=True)
    p.add_argument('--msi-build', type=Path, required=True, help='msibuild_probe.exe from build/guest.py')
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    out = a.output.resolve()
    if not out.is_relative_to(ROOT / '.work'):
        p.error('private .work output required')
    if sha(a.base_iso) != a.base_sha256:
        p.error('base ISO does not match --base-sha256')
    out.mkdir(parents=True, exist_ok=False)
    media = out / 'media'
    subprocess.run(['xorriso', '-osirrox', 'on', '-indev', str(a.base_iso), '-extract', '/', str(media)],
                   check=True, capture_output=True)
    for f in media.rglob('*'):
        f.chmod(0o755 if f.is_dir() else 0o644)
    before = {str(f.relative_to(media)): sha(f) for f in sorted(media.rglob('*')) if f.is_file()}
    test = media / 'msi-test.cmd'
    text = test.read_bytes()
    if text.count(SCRIPTED) != 1:
        raise SystemExit('msi-test.cmd is not the expected scripted build')
    test.write_bytes(text.replace(SCRIPTED, NATIVE))
    shutil.copy2(a.msi_build, media / 'msibuild_probe.exe')
    iso = out / 'regression-noscript.iso'
    command = ['genisoimage', '-quiet', '-J', '-joliet-long', '-r', '-o', str(iso), str(media)]
    subprocess.run(command, check=True)
    after = {str(f.relative_to(media)): sha(f) for f in sorted(media.rglob('*')) if f.is_file()}
    changed = {k: {'before': before.get(k), 'after': v} for k, v in after.items() if before.get(k) != v}
    manifest = {'base_iso': str(a.base_iso.resolve()), 'base_sha256': a.base_sha256, 'iso': str(iso), 'iso_sha256': sha(iso),
                'command': command, 'changed_or_added': changed, 'files': after}
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'iso': str(iso), 'sha256': manifest['iso_sha256'], 'changed_or_added': sorted(changed)}))


if __name__ == '__main__':
    main()
