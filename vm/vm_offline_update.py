#!/usr/bin/env python3
"""Offline update of a shut-off registered libvirt VM's own writable disk.

Replaces reviewed branding files (an upgrade between two packages prepared by
build/prepare_branding.py) and/or system32\\OEMINFO.INI. Nothing is written
unless the domain is shut off (or, with --disk, the disposable rehearsal
overlay under .work/ is not held by a running QEMU), the disk is writable and not a frozen (0444)
image, the NTFS volume is clean, every current file has its expected hash and
every required guest file exists. Each replaced file is backed up on the host
and in the guest (/xp25), read back after writing, and a preserved file set
must hash the same before and after. ntfs-3g refuses an unclean or hibernated
volume; that refusal is never forced. --rollback writes the backups of an
earlier run back after checking the current files are that run's output.

usage: vm_offline_update.py (--domain NAME | --disk REHEARSAL.qcow2) --output DIR
         [--branding PKG --upgrade-from PKG] [--oeminfo FILE --oeminfo-current SHA256]
         [--require-guest PATH ...] [--preserve-record JSON] | --rollback RESULT_JSON
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vm'))
sys.path.insert(0, str(ROOT / 'build'))
import xp_lab as lab
from install_branding_overlay import verify_pair

URI = ['virsh', '-c', 'qemu:///system']
PRESERVED = ['/WINDOWS/system32/' + n for n in (
    'xpsp1res.dll', 'winver.exe', 'shell32.dll', 'logonui.exe', 'msgina.dll', 'winlogon.exe', 'ntdll.dll', 'kernel32.dll',
    'oembios.bin', 'oembios.dat', 'oembios.sig', 'licdll.dll', 'wpa.dbl', 'dllcache/sysdm.cpl')] + ['/WINDOWS/explorer.exe', '/boot.ini']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def virsh(*args):
    return subprocess.run(URI + list(args), capture_output=True, text=True, check=True).stdout


def domain_disk(domain):
    rows = [line.split() for line in virsh('domblklist', domain, '--details').splitlines()]
    disks = [row[3] for row in rows if len(row) == 4 and row[1] == 'disk']
    if len(disks) != 1:
        raise ValueError('expected exactly one disk: %r' % disks)
    return Path(disks[0])


def cat(device, path):
    r = subprocess.run(['ntfscat', str(device), path], capture_output=True)
    return r.stdout if r.returncode == 0 else None


def digest(device, path):
    data = cat(device, path)
    return sha(data) if data is not None else None


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--domain')
    target.add_argument('--disk', type=Path, help='disposable rehearsal overlay instead of a registered VM')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--branding', type=Path)
    parser.add_argument('--upgrade-from', type=Path)
    parser.add_argument('--oeminfo', type=Path)
    parser.add_argument('--oeminfo-current')
    parser.add_argument('--require-guest', nargs='*', default=[])
    parser.add_argument('--preserve-record', type=Path, help='JSON with components [{guest_path, expected}]')
    parser.add_argument('--rollback', type=Path, help='result.json of an earlier run to undo')
    args = parser.parse_args()
    for name in ('branding', 'upgrade_from', 'oeminfo', 'preserve_record', 'rollback', 'disk'):
        if getattr(args, name):
            setattr(args, name, getattr(args, name).resolve())
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / '.work'):
        parser.error('evidence must stay under .work/')
    if bool(args.branding) != bool(args.upgrade_from) or bool(args.oeminfo) != bool(args.oeminfo_current):
        parser.error('--branding needs --upgrade-from and --oeminfo needs --oeminfo-current')
    if not (args.branding or args.oeminfo or args.rollback) or (args.rollback and (args.branding or args.oeminfo)):
        parser.error('choose updates or --rollback')
    if args.domain and virsh('domstate', args.domain).strip() != 'shut off':
        parser.error('domain must be shut off')
    disk = domain_disk(args.domain).resolve() if args.domain else args.disk.resolve()
    if args.disk and not disk.is_relative_to(ROOT / '.work'):
        parser.error('rehearsal overlays must be under this checkout\'s .work/')
    if '/.work/' not in str(disk) or not os.access(disk, os.W_OK) or disk.stat().st_mode & 0o222 == 0:
        parser.error('refusing a disk outside .work/ or a frozen read-only image: %s' % disk)
    output.mkdir(parents=True, exist_ok=False)
    os.chdir(output)
    xml_before = virsh('dumpxml', '--inactive', args.domain) if args.domain else None

    # Planned writes: guest path -> (current sha256 required, new bytes, guest backup path, review)
    plan = {}
    if args.rollback:
        earlier = json.loads(args.rollback.read_text())
        for target, row in earlier['targets'].items():
            plan[target] = (row['new_sha256'], Path(row['host_backup']).read_bytes(), None, 'rollback')
    if args.branding:
        manifest = json.loads((args.branding / 'manifest.json').read_text())
        previous = json.loads((args.upgrade_from / 'manifest.json').read_text())['components']
        originals = Path(manifest['inputs'])
        for name, row in manifest['components'].items():
            if previous[name]['original_sha256'] != row['original_sha256']:
                raise ValueError('packages were prepared from different originals: ' + name)
            if previous[name]['sha256'] == row['sha256']:
                continue
            new = (args.branding / name).read_bytes()
            if sha(new) != row['sha256'] or sha((originals / name).read_bytes()) != row['original_sha256']:
                raise ValueError('unverified package file: ' + name)
            verify_pair(originals / name, args.branding / name, row['changed_resources'])
            plan['/WINDOWS/' + name] = (previous[name]['sha256'], new,
                                         '/xp25/brand-%s-%s' % (previous[name]['sha256'][:12], Path(name).name), 'branding upgrade')
    if args.oeminfo:
        plan['/WINDOWS/system32/OEMINFO.INI'] = (args.oeminfo_current, args.oeminfo.read_bytes(),
                                                 '/xp25/oeminfo-%s.ini' % args.oeminfo_current[:12], 'oeminfo')
    record = json.loads(args.preserve_record.read_text())['components'] if args.preserve_record else []
    preserved = sorted(set(PRESERVED + [c['guest_path'] for c in record]) - set(plan))

    result = {'domain': args.domain, 'disk': str(disk), 'targets': {}, 'checks': {}, 'written': [],
              'command': [sys.executable, *sys.argv]}
    checks = result['checks']
    with lab.partition(disk, True) as device:
        info = subprocess.run(['ntfsinfo', '-m', str(device)], capture_output=True, text=True)
        (output / 'ntfsinfo-m.log').write_text(info.stdout + info.stderr)
        flags = next((l.split(':', 1)[1].strip() for l in info.stdout.splitlines() if 'Volume Flags' in l), None)
        checks['volume_not_dirty'] = flags == '0x0000'
        before = {p: digest(device, p) for p in preserved}
        # A recorded component that is also a target must instead be the expected previous version.
        checks['preserve_record_matches'] = all(before[c['guest_path']] == c['expected'] if c['guest_path'] in before
                                                else plan[c['guest_path']][0] == c['expected'] for c in record)
        checks['required_guest_files_present'] = all(cat(device, p) for p in args.require_guest)
        current = {t: cat(device, t) for t in plan}
        checks['current_files_expected'] = all(current[t] is not None and sha(current[t]) == plan[t][0] for t in plan)
        if not all(checks.values()):
            result['failed'] = [k for k, v in checks.items() if not v]
            result['current'] = {t: sha(current[t]) if current[t] is not None else None for t in plan}
            (output / 'failure.json').write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps(result, indent=2))
            return 1
        for target, (expected, new, guest_backup, review) in plan.items():
            host_backup = output / ('previous-' + Path(target).name)
            host_backup.write_bytes(current[target])
            if guest_backup:
                lab.run(['ntfscp', device, host_backup, guest_backup])
                if cat(device, guest_backup) != current[target]:
                    raise RuntimeError('guest backup readback differs: ' + guest_backup)
            staged = output / ('new-' + Path(target).name)
            staged.write_bytes(new)
            lab.run(['ntfscp', device, staged, target])
            result['written'].append(target)
            result['targets'][target] = {'review': review, 'previous_sha256': expected, 'new_sha256': sha(new),
                                         'host_backup': str(host_backup), 'guest_backup': guest_backup,
                                         'readback_matches': cat(device, target) == new}
        after = {p: digest(device, p) for p in preserved}
        checks['readback_matches'] = all(row['readback_matches'] for row in result['targets'].values())
        checks['preserved_files_unchanged'] = after == before
        result['preserved'] = before
    image = subprocess.run(['qemu-img', 'check', str(disk)], capture_output=True, text=True)
    (output / 'image-check.log').write_text(image.stdout + image.stderr)
    checks['qemu_img_check'] = image.returncode == 0
    if args.domain:
        checks['definition_unchanged'] = virsh('dumpxml', '--inactive', args.domain) == xml_before
        checks['domain_still_shut_off'] = virsh('domstate', args.domain).strip() == 'shut off'
    result['all_passed'] = all(checks.values())
    (output / ('result.json' if result['all_passed'] else 'failure.json')).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'preserved'}, indent=2))
    return 0 if result['all_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
