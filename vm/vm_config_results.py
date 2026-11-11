#!/usr/bin/env python3
"""Read-only gates for an interactive VM after tests/guest/vmconfig ran in it.

Reads a shut-off disk (a registered domain's, or a rehearsal overlay) and
decides from the guest's own records (before.log, verify.log, the oem probe's
check-after.json) plus offline facts: sysdm.cpl and OEMINFO.INI hashes, the
computer and DHCP host names in the SYSTEM hive, Help and Support's OEM copy,
and Windows activation data (wpa.dbl, OOBETimer, ProductId, DigitalProductId)
compared with a frozen baseline image.
usage: vm_config_results.py (--domain NAME | --disk PATH) --output DIR --name NAME
         --sysdm SHA256 --oeminfo SHA256 --baseline FROZEN.qcow2 [--ip A.B.C.D --peer-name NAME]
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vm'))
import xp_lab as lab
import regf

URI = ['virsh', '-c', 'qemu:///system']
CHECK = '/xp25/vmconfig-20261025/check/'
BEFORE_STEPS = ('COPY_EXIT', 'REG_EXPORT_OEM_EXIT', 'REG_EXPORT_NAME_EXIT', 'REG_EXPORT_TCPIP_EXIT',
                'RESTORE_SCRIPT_COPY_EXIT', 'PROBE_COPY_EXIT', 'PROBE_EXIT', 'REG_MANUFACTURER_EXIT', 'REG_MODEL_EXIT',
                'RENAME_EXIT', 'REG_HOSTNAME_EXIT')


def sha(data):
    return hashlib.sha256(data).hexdigest() if data is not None else None


def cat(device, path):
    r = subprocess.run(['ntfscat', str(device), path], capture_output=True)
    return r.stdout if r.returncode == 0 else None


def text(data):
    if data is None:
        return ''
    if data[:2] == b'\xff\xfe':
        return data.decode('utf-16', 'replace').replace('\r', '')
    return data.decode('cp437', 'replace').replace('\x00', '').replace('\r', '')


def activation(device):
    software = cat(device, '/WINDOWS/system32/config/software')
    current = regf.values(software, 'Microsoft\\Windows NT\\CurrentVersion')
    events = regf.values(software, 'Windows NT\\CurrentVersion\\WPAEvents')
    pick = lambda found, name: sha(found[name][1]) if name in found else None
    return {'wpa_dbl': sha(cat(device, '/WINDOWS/system32/wpa.dbl')), 'oobe_timer': pick(events, 'OOBETimer'),
            'product_id': pick(current, 'ProductId'), 'digital_product_id': pick(current, 'DigitalProductId')}, software


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--domain')
    target.add_argument('--disk', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--name', required=True)
    parser.add_argument('--sysdm', required=True)
    parser.add_argument('--oeminfo', required=True)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--ip')
    parser.add_argument('--peer-name')
    args = parser.parse_args()
    baseline = args.baseline.resolve()
    if args.domain:
        if subprocess.run(URI + ['domstate', args.domain], capture_output=True, text=True).stdout.strip() != 'shut off':
            parser.error('domain must be shut off')
        rows = [l.split() for l in subprocess.run(URI + ['domblklist', args.domain, '--details'], capture_output=True, text=True).stdout.splitlines()]
        disk = Path(next(r[3] for r in rows if len(r) == 4 and r[1] == 'disk'))
    else:
        disk = args.disk.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    os.chdir(output)
    (output / 'baseline').mkdir()
    os.chdir(output / 'baseline')
    with lab.partition(baseline, False) as device:
        reference, _ = activation(device)
    os.chdir(output)
    with lab.partition(disk, False) as device:
        files = {name: cat(device, CHECK + name) for name in ('before.log', 'verify.log', 'check-after.json', 'rename.json')}
        for name, data in files.items():
            if data is not None:
                (output / name).write_bytes(data)
        sysdm = sha(cat(device, '/WINDOWS/system32/sysdm.cpl'))
        oeminfo = sha(cat(device, '/WINDOWS/system32/OEMINFO.INI'))
        actual, software = activation(device)
        system = cat(device, '/WINDOWS/system32/config/system')
    select = regf.values(system, 'Select')
    current = struct_dword(select['Current'][1])
    controlset = 'ControlSet%03d' % current
    name = regf.string(regf.values(system, controlset + '\\Control\\ComputerName\\ComputerName')['ComputerName'])
    tcpip = regf.values(system, controlset + '\\Services\\Tcpip\\Parameters')
    helpsvc = {k: regf.string(v) for k, v in regf.values(software, 'PCHealth\\HelpSvc\\OEMInfo').items()}
    before, verify = text(files['before.log']), text(files['verify.log'])
    records = [json.loads(l) for l in text(files['check-after.json']).splitlines() if l.strip()]
    cases = {r['oem_case']: r['status'] for r in records if 'oem_case' in r}
    gateway = re.findall(r'Default Gateway[ .]*: *(\S*)', verify)
    gates = {
        'before_steps_exit_zero': all(step + '=0' in before for step in BEFORE_STEPS) and 'XP25_VM_BEFORE_DONE' in before,
        'rename_succeeded': '"ok":true' in text(files['rename.json']) and '"requested":"%s"' % args.name in text(files['rename.json']),
        'verify_completed': 'XP25_VM_VERIFY_DONE' in verify and 'PROBE_EXIT=0' in verify,
        'oem_probe_all_pass': bool(cases) and all(v == 'pass' for v in cases.values()) and '"oem_probe_done":true' in text(files['check-after.json']),
        'guest_reports_new_name': 'COMPUTERNAME=%s\n' % args.name.upper() in verify,
        'hive_computer_name': name == args.name.upper(),
        'hive_dhcp_host_name': regf.string(tcpip.get('NV Hostname', (1, None))) == args.name and regf.string(tcpip.get('Hostname', (1, None))) == args.name,
        'sysdm_cpl_retained': sysdm == args.sysdm,
        'oeminfo_retained': oeminfo == args.oeminfo,
        'helpsvc_quoolai': helpsvc == {'Manufacturer': 'QuoolAI', 'Model': 'Windows XP 25th Anniversary Edition'},
        'activation_data_unchanged': actual == reference,
    }
    if args.ip:
        gates['no_default_gateway'] = bool(gateway) and all(g == '' for g in gateway)
        gates['guest_address'] = re.search(r'IP Address[ .]*: *%s\n' % re.escape(args.ip), verify) is not None
        gates['isolated_dns_host_reachable'] = 'PING_HOST_EXIT=0' in verify
        gates['outside_address_unreachable'] = 'PING_OUTSIDE_EXIT=1' in verify
    if args.peer_name:
        gates['peer_netbios_name_seen'] = re.search(r'^\s*%s\s+<00>\s+UNIQUE' % re.escape(args.peer_name.upper()), verify, re.M) is not None
    result = {'disk': str(disk), 'controlset': controlset, 'computer_name': name,
              'nv_hostname': regf.string(tcpip.get('NV Hostname', (1, None))), 'sysdm_sha256': sysdm,
              'oeminfo_sha256': oeminfo, 'helpsvc': helpsvc, 'activation': actual, 'activation_baseline': reference,
              'baseline': str(baseline), 'oem_cases': cases, 'gates': gates,
              'observations': {'peer_ping_exit': (re.findall(r'PING_PEER_EXIT=(\d+)', verify) or [None])[0],
                               'outside_ping_exit': (re.findall(r'PING_OUTSIDE_EXIT=(\d+)', verify) or [None])[0]},
              'all_passed': all(gates.values())}
    (output / ('results.json' if result['all_passed'] else 'failure.json')).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'all_passed': result['all_passed'], 'failed': [k for k, v in gates.items() if not v],
                      'computer_name': name, 'observations': result['observations']}, indent=2))
    return 0 if result['all_passed'] else 1


def struct_dword(raw):
    return int.from_bytes(raw[:4], 'little')


if __name__ == '__main__':
    raise SystemExit(main())
