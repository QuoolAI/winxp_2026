#!/usr/bin/env python3
"""Flatten a verified private desktop into a self-contained engineering image.

This is an importable preinstalled disk, not Windows Setup or a license grant.
Only an already tested component stack is packaged. No guest files are edited.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def verify_report(directory, name):
    report = json.loads((directory / name).read_text())
    if (report.get('passed') is not True or not report.get('checks') or
            not all(value is True for value in report['checks'].values()) or not report.get('evidence_sha256')):
        raise ValueError('incomplete runtime acceptance: ' + str(directory / name))
    for relative, expected in report['evidence_sha256'].items():
        path = (directory / relative).resolve()
        if not path.is_relative_to(directory) or sha(path) != expected:
            raise ValueError('stale runtime evidence: ' + str(path))
    return report


def verify_run(directory):
    directory = directory.resolve()
    if not directory.is_relative_to(ROOT / '.work'):
        raise ValueError('private runtime directory required')
    checkpoint = json.loads((directory / 'checkpoint.json').read_text())
    disk = directory / 'disk.qcow2'
    if (checkpoint['stage'] != 'normal_shutdown_frozen' or disk.stat().st_mode & 0o222 or
            sha(disk) != checkpoint['disk_sha256']):
        raise ValueError('runtime disk is not the accepted frozen checkpoint')
    core = verify_report(directory, 'component-results.json')
    extensions = verify_report(directory, 'extension-results.json')
    gui = verify_report(directory, 'gui-review.json')
    return {'directory': str(directory), 'disk_sha256': checkpoint['disk_sha256'],
            'component_checks': core['checks'], 'extension_checks': extensions['checks'],
            'gui_checks': gui['checks'], 'report_sha256': {name: sha(directory / name) for name in
                ('component-results.json', 'extension-results.json', 'gui-review.json')}}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run', type=Path, required=True, help='accepted one-vCPU source image')
    p.add_argument('--matrix', type=Path, action='append', required=True, help='other accepted regression configurations')
    p.add_argument('--provenance', type=Path, required=True, help='private original-media provenance record; does not establish entitlement')
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    output, source = a.output.resolve(), a.run.resolve()
    if not output.is_relative_to(ROOT / '.work') or not a.provenance.resolve().is_relative_to(ROOT / '.work'):
        p.error('image and provenance records must stay private under .work/')
    runs = [source, *(d.resolve() for d in a.matrix)]
    reports = [verify_run(d) for d in runs]
    configs = set()
    stack = None
    for d in runs:
        argv = json.loads((d / 'qemu-command.json').read_text())
        configs.add((argv[argv.index('-accel') + 1], argv[argv.index('-smp') + 1]))
        retained = {str(f.relative_to(d / 'retention')): sha(f) for f in
                    (d / 'retention/WINDOWS').rglob('*') if f.is_file()}
        if stack is not None and retained != stack:
            raise ValueError('the accepted component/branding stack differs between configurations')
        stack = retained
    if configs != {('kvm', '1'), ('kvm', '2'), ('tcg', '1')}:
        p.error('one-vCPU KVM, two-vCPU KVM and one-vCPU TCG evidence is required')
    provenance = json.loads(a.provenance.read_text())
    # Check every backing file before conversion. No writable/live image is accepted.
    chain = json.loads(subprocess.check_output(['qemu-img', 'info', '--output=json', '--backing-chain', str(source / 'disk.qcow2')]))
    chain_hashes = {}
    for row in chain:
        path = Path(row['filename']).resolve()
        if not path.is_relative_to(ROOT / '.work') or path.stat().st_mode & 0o222:
            raise ValueError('backing chain must contain only frozen private images')
        chain_hashes[str(path)] = sha(path)
    output.mkdir(parents=True, exist_ok=False)
    commands = []
    def run(argv):
        commands.append(list(map(str, argv)))
        with (output / 'commands.json').open('w') as f:
            json.dump(commands, f, indent=2); f.write('\n')
        return subprocess.run(argv, capture_output=True, check=True).stdout
    destination = output / 'XP25-Components-Engineering.qcow2'
    run(['qemu-img', 'convert', '-f', 'qcow2', '-O', 'qcow2', str(source / 'disk.qcow2'), str(destination)])
    (output / 'sector-compare.log').write_bytes(run(['qemu-img', 'compare', '-f', 'qcow2', '-F', 'qcow2', str(source / 'disk.qcow2'), str(destination)]))
    (output / 'image-check.log').write_bytes(run(['qemu-img', 'check', str(destination)]))
    info = json.loads(run(['qemu-img', 'info', '--output=json', str(destination)]))
    if info.get('backing-filename'):
        raise ValueError('installation candidate must have no reference backing dependency')
    if any(sha(Path(path)) != digest for path, digest in chain_hashes.items()):
        raise ValueError('source chain changed during packaging')
    destination.chmod(0o444)
    result = {'schema': 1, 'command': [sys.executable, *sys.argv],
        'kind': 'private_preinstalled_engineering_disk', 'license_entitlement_established': False,
        'windows_setup_iso': False, 'source_complete': False, 'redistribution_approved': False,
        'provenance_record': provenance, 'provenance_sha256': sha(a.provenance),
        'source_chain_sha256': chain_hashes, 'regression_matrix': reports,
        'retained_component_sha256': stack, 'image': destination.name,
        'image_sha256': sha(destination), 'virtual_size': info['virtual-size'],
        'content_reproduction': 'qemu-img compare verifies identical virtual sectors; QCOW2 metadata bytes need not be reproducible.',
        'guest_file_changes': [], 'boot_configuration_changes': [],
        'profile': {'architecture': 'i686', 'machine': 'pc-i440fx-8.2', 'cpu': 'qemu32', 'vcpus': 1,
                    'memory_mib': 512, 'disk': 'IDE', 'vga': 'std', 'nic': 'rtl8139'},
        'limitations': ['Contains the existing private engineering desktop, including its source/build payload and recovery files.',
            'Preserves installed original Windows binaries and activation state; no new media entitlement is inferred.',
            'Use a new writable copy for every boot. Do not attach the frozen artifact writable.',
            'Native UserEnv and Explorer failed boot/shell integration and are excluded.',
            'A clean licensed installation image still requires identified authorized installation media and license/provenance records.']}
    (output / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    (output / 'README.txt').write_text(
        'XP25 private preinstalled engineering disk\n\n'
        'This is an importable disk, not Windows Setup and not a redistribution artifact.\n'
        'License/provenance acceptance is pending. Source completeness is not established.\n'
        'Keep the supplied QCOW2 read-only; use qemu-img convert to make a new writable\n'
        'private copy before boot. Import that copy using the profile in manifest.json.\n'
        'Use an isolated network and a unique MAC/IP; preserve existing VM disks.\n'
        'The verified original SCM, SMSS, Regsvc and MSGINA stack is included.\n'
        'The working installed UserEnv, Explorer and Winlogon are retained.\n')
    print(json.dumps({'image': str(destination), 'sha256': result['image_sha256'],
                      'licensed_installation_complete': False}))


if __name__ == '__main__':
    main()
