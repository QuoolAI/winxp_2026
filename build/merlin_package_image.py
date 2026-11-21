#!/usr/bin/env python3
"""Package an XP25 image with MerlinAI installed by its own installer.

The input is a finished install run (vm/merlin_lab.py --scenario install): its
frozen overlay, backed by the frozen parent image, after a guest-requested
shutdown. The output is a standalone image: a reflink copy of the parent with
the overlay committed into it (only the clusters the installation changed take
new space). The parent and the run's overlay are never written; the overlay is
committed from a reflink copy. The manifest records the parent, the run, the
installed MerlinAI files with their SHA-256 (read back offline) and the image
revision written to C:\\xp25\\image-revision.txt.

usage: merlin_package_image.py --parent IMG --parent-sha256 H --run RUN_DIR --name NAME.qcow2 --output .work/<fresh>"""
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

FILES = ['/Program Files/XP25/MerlinAI/' + n for n in ('MerlinClient.dll', 'MerlinCrash.exe', 'MerlinAI.exe', 'MerlinAI.cpl',
                                                       'MerlinSvc.exe', 'MerlinTest.exe')] + \
        ['/WINDOWS/system32/MerlinAI.cpl', '/xp25/merlintest.ini', '/xp25/image-revision.txt']


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 22), b''):
            h.update(block)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--parent', type=Path, required=True)
    parser.add_argument('--parent-sha256', required=True)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--name', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    parent, run, out = args.parent.resolve(), args.run.resolve(), args.output.resolve()
    if not out.is_relative_to(ROOT / '.work') or parent.stat().st_mode & 0o222:
        parser.error('fresh .work/ output and a frozen parent required')
    overlay = run / 'disk.qcow2'
    if overlay.stat().st_mode & 0o222 or not (run / 'guest-shutdown-event.json').exists():
        parser.error('the install run must have ended with a guest shutdown and be frozen')
    info = json.loads(subprocess.check_output(['qemu-img', 'info', '-U', '--output=json', str(overlay)]))
    if Path(info.get('full-backing-filename', '')).resolve() != parent:
        parser.error('the run overlay is not backed by the parent image')
    inputs = json.loads((run / 'inputs.json').read_text())
    if inputs.get('scenario') != 'install':
        parser.error('not an install run')
    if sha(parent) != args.parent_sha256:
        parser.error('parent hash mismatch')
    out.mkdir(parents=True, exist_ok=False)
    os.chdir(out)
    image = out / args.name
    subprocess.run(['cp', '--reflink=always', str(parent), str(image)], check=True)
    image.chmod(0o644)
    work = out / 'commit-overlay.qcow2'
    subprocess.run(['cp', '--reflink=always', str(overlay), str(work)], check=True)
    work.chmod(0o644)
    subprocess.run(['qemu-img', 'rebase', '-u', '-F', 'qcow2', '-b', str(image), str(work)], check=True)
    subprocess.run(['qemu-img', 'commit', '-q', str(work)], check=True)
    work.unlink()
    check = subprocess.run(['qemu-img', 'check', str(image)], capture_output=True, text=True)
    (out / 'image-check.log').write_text(check.stdout + check.stderr)
    if check.returncode:
        raise SystemExit('image check failed')
    files = {}
    with lab.partition(image, False) as device:
        for name in FILES:
            try:
                data = lab.run(['ntfscat', device, name])
                files[name] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
                if name.endswith('image-revision.txt'):
                    files[name]['text'] = data.decode('latin-1').strip()
            except RuntimeError as e:
                files[name] = {'error': str(e)[:200]}
    image.chmod(0o444)
    digest = sha(image)
    if sha(parent) != args.parent_sha256 or (overlay.stat().st_mode & 0o222):
        raise SystemExit('an input changed during packaging')
    manifest = {'image': str(image), 'image_sha256': digest, 'bytes': image.stat().st_size, 'backing_file': None,
                'parent_image': str(parent), 'parent_image_sha256': args.parent_sha256, 'install_run': str(run),
                'install_run_staged': inputs.get('staged'), 'installed_files': files,
                'note': 'MerlinAI installed by MerlinAI.exe /install in the guest; endpoints preset to the XP25 host services, '
                        'no credentials (they are issued per installation).'}
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=1) + '\n')
    print(json.dumps({'image': str(image), 'sha256': digest, 'missing': [n for n, f in files.items() if 'error' in f]}))


if __name__ == '__main__':
    main()
