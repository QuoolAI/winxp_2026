#!/usr/bin/env python3
"""Flatten a frozen, normally shut down XP25 security image-install run into
the standalone engineering image XP25-Security-Baseline.qcow2 (no backing
file), then verify it sector-for-sector against the source chain and with
qemu-img check. The run must have passed every gate of
vm/security_results.py. Guest files are not edited here. The result is
private engineering media, not a Windows Setup image or a redistribution
artifact."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
NAME = 'XP25-Security-Baseline.qcow2'


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 22), b''):
            h.update(block)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True, help='frozen image-install run directory')
    parser.add_argument('--tools', type=Path, required=True, help='collect.json of the native XP25Sec/XP25Audit build')
    parser.add_argument('--ai', type=Path, required=True, help='collect.json of the native XP25 AI build installed in the run')
    parser.add_argument('--kernel', type=Path, required=True, help='manifest.json of build/prepare_kernel_exports.py')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run, out = args.run.resolve(), args.output.resolve()
    if not out.is_relative_to(ROOT / '.work'):
        parser.error('private .work/ output required')
    inputs = json.loads((run / 'inputs.json').read_text())
    results = json.loads((run / 'results.json').read_text())
    disk = run / 'disk.qcow2'
    if inputs.get('role') != 'image-install' or not (run / 'normal-shutdown.json').is_file() or disk.stat().st_mode & 0o222:
        parser.error('a frozen image-install run that shut down normally is required')
    if not results.get('all_passed'):
        parser.error('the run did not pass every gate: ' + str([g['gate'] for g in results['gates'] if not g['passed']]))
    out.mkdir(parents=True, exist_ok=False)
    image = out / NAME
    source_sha = sha(disk)
    if source_sha != results.get('disk_sha256'):
        raise SystemExit('the run disk changed after its results were recorded')
    base = Path(inputs['base'])
    base_info = json.loads(subprocess.check_output(['qemu-img', 'info', '--output=json', str(base)]))
    if 'backing-filename' in base_info or sha(base) != inputs['base_sha256']:
        raise SystemExit('the reference base must be the unchanged standalone image')
    # Space-efficient flattening on a copy-on-write volume: a reflink copy of the
    # standalone reference receives the run's changed clusters through a
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
    if sha(disk) != source_sha or sha(base) != inputs['base_sha256']:
        raise SystemExit('a source file changed during packaging')
    serial = (run / 'serial.log').read_bytes().decode('utf-8', 'replace').replace('\r', '')
    manifest = {
        'image': str(image), 'image_sha256': digest, 'bytes': image.stat().st_size, 'virtual_size': info['virtual-size'],
        'backing_file': None, 'source_run': str(run), 'source_overlay_sha256': source_sha,
        'previous_verified_image': inputs['base'], 'previous_verified_image_sha256': inputs['base_sha256'],
        'previous_verified_image_unchanged': True,
        'offline_file_writes': inputs['staged'], 'original_winlogon_recovery': inputs.get('recovery'),
        'install_records': [line.strip() for line in serial.splitlines() if line.startswith('XP25_SEC_')],
        'install_gates': results['gates'],
        'native_security_tools': json.loads(args.tools.read_text()),
        'native_ai_build': {k: v for k, v in json.loads(args.ai.read_text()).items() if k != 'probe'},
        'kernel_export_change': json.loads(args.kernel.read_text()),
        'in_image_records': 'C:\\WINDOWS\\XP25\\Security: baseline-backup.txt (original configuration), install-apply.jsonl, '
                            'install-plan.jsonl, install-services-before.jsonl, install-verify.jsonl, audit-snapshot.txt',
        'rollback': 'XP25Sec.exe rollback inside the guest, or a new overlay of the previous verified image',
        'sector_compare': compare.stdout.strip(), 'image_check': check.stdout.strip().splitlines()[-1:],
        'scope': 'Private engineering disk: verified XP25 AI image plus the natively built XP25 Winlogon, the relinked checked '
                 'kernel exporting KeFlushQueuedDpcs, the rebuilt XP25 AI binaries, the XP25 security tools and the applied '
                 'security baseline. Not Windows Setup media; no licensing or redistribution claim. Keep it off unrestricted networks.'}
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (out / 'README.txt').write_text(
        'XP25 private hardened engineering disk: ' + NAME + '\n\n'
        'SHA-256 ' + digest + '\n'
        'Parent (unchanged, still bootable): ' + inputs['base'] + '\n  SHA-256 ' + inputs['base_sha256'] + '\n\n'
        'This is an importable disk, not Windows Setup and not a redistribution artifact.\n'
        'Keep this QCOW2 read-only; boot only a qemu-img overlay or a converted copy.\n'
        'Use an isolated network. It is not hardened for unrestricted Internet access.\n'
        'The daily account XP25 is an administrator with a blank password (unchanged).\n'
        'Do not run sfc /scannow: it would replace the source-built system files.\n'
        'Shut down through Start > Turn Off Computer; shutdown.exe does not work under the XP25 Winlogon.\n'
        'Rollback: XP25Sec.exe rollback in C:\\Program Files\\XP25\\Security, then restart; or use the parent image.\n'
        'See docs/security-baseline.md, docs/security-threat-model.md and docs/security-regression.md.\n')
    print(json.dumps({k: manifest[k] for k in ('image', 'image_sha256', 'bytes', 'sector_compare')}, indent=2))


if __name__ == '__main__':
    main()
