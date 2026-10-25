#!/usr/bin/env python3
"""Flatten a frozen, normally shut down XP25 AI install-only run into a
standalone experimental engineering QCOW2 (no backing file), then verify it
sector-for-sector against the source chain and with qemu-img check. Guest
files and boot settings are not edited. The result is private engineering
media, not a Windows Setup image or a redistribution artifact."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 22), b''):
            h.update(block)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True, help='install-only run directory (frozen)')
    parser.add_argument('--collect', type=Path, required=True, help='native collect.json of the installed binaries')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run, out = args.run.resolve(), args.output.resolve()
    if not out.is_relative_to(ROOT / '.work'):
        parser.error('private .work/ output required')
    inputs = json.loads((run / 'inputs.json').read_text())
    disk = run / 'disk.qcow2'
    if inputs.get('role') != 'install_only' or not (run / 'normal-shutdown.json').is_file() or disk.stat().st_mode & 0o222:
        parser.error('a frozen install-only run that shut down normally is required')
    serial = (run / 'serial.log').read_bytes().decode('utf-8', 'replace').replace('\r', '')
    install = [l.strip() for l in serial.splitlines() if l.startswith('XP25_AI_')]
    needed = ['XP25_AI_BROKER_INSTALL=0', 'XP25_AI_BAND_REGISTER=0', 'XP25_AI_SEARCH_REPLACED=0', 'XP25_AI_SHORTCUTS=0']
    if not all(n in install for n in needed):
        parser.error('install records are incomplete: ' + str(install))
    out.mkdir(parents=True, exist_ok=False)
    image = out / 'XP25-AI-Engineering.qcow2'
    source_sha = sha(disk)
    base = Path(inputs['base'])
    base_info = json.loads(subprocess.check_output(['qemu-img', 'info', '--output=json', str(base)]))
    if 'backing-filename' in base_info or sha(base) != inputs['base_sha256']:
        raise SystemExit('the reference base must be the unchanged standalone image')
    # Space-efficient flattening on a copy-on-write volume: a reflink copy of the
    # standalone reference receives the install run's changed clusters through a
    # reflinked copy of the frozen overlay; neither original file is written.
    subprocess.run(['cp', '--reflink=always', str(base), str(image)], check=True)
    image.chmod(0o644)
    staging = out / 'install-overlay-copy.qcow2'
    subprocess.run(['cp', '--reflink=always', str(disk), str(staging)], check=True)
    staging.chmod(0o644)
    subprocess.run(['qemu-img', 'rebase', '-u', '-F', 'qcow2', '-b', str(image), str(staging)], check=True)
    subprocess.run(['qemu-img', 'commit', str(staging)], check=True, capture_output=True)
    staging.unlink()
    compare = subprocess.run(['qemu-img', 'compare', str(disk), str(image)], capture_output=True, text=True)
    (out / 'sector-compare.log').write_text(compare.stdout + compare.stderr)
    check = subprocess.run(['qemu-img', 'check', str(image)], capture_output=True, text=True)
    (out / 'image-check.log').write_text(check.stdout + check.stderr)
    info = json.loads(subprocess.check_output(['qemu-img', 'info', '--output=json', str(image)]))
    if compare.returncode or check.returncode or 'backing-filename' in info:
        raise SystemExit('flattened image failed verification')
    image.chmod(0o444)
    digest = sha(image)
    if sha(disk) != source_sha:
        raise SystemExit('source overlay changed during packaging')
    manifest = {'image': str(image), 'image_sha256': digest, 'bytes': image.stat().st_size,
                'virtual_size': info['virtual-size'], 'backing_file': None,
                'source_run': str(run), 'source_overlay_sha256': source_sha,
                'reference_base': inputs['base'], 'reference_base_sha256': inputs['base_sha256'],
                'staged_installer_payload': inputs['staged'], 'install_records': install,
                'native_build': json.loads(args.collect.read_text()),
                'sector_compare': compare.stdout.strip(), 'image_check': check.stdout.strip().splitlines()[-1:],
                'scope': 'Private experimental engineering disk: accepted engineering image plus the XP25 AI '
                         'components installed by their own installer at logon. Not Windows Setup media; no '
                         'licensing or redistribution claim.'}
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({k: manifest[k] for k in ('image', 'image_sha256', 'bytes', 'sector_compare')}, indent=2))


if __name__ == '__main__':
    main()
