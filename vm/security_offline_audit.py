#!/usr/bin/env python3
"""Read-only security inventory of a frozen XP25 engineering image.

Nothing is booted and nothing is written to the image: the NTFS partition is
exported read-only (vm/xp_lab.py) and files are read with ntfscat. The result
is static evidence only: installed binaries with their version resources and
compile-time mitigations, the service table and security settings of the
offline hives, and the local accounts. Listening ports, tokens and live
object permissions need the in-guest audit (components/security).

usage: security_offline_audit.py <frozen .work image> <fresh .work output dir>"""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vm'))
import regf
import xp_lab as lab

PE_SUFFIXES = ('.exe', '.dll', '.sys', '.cpl', '.ocx', '.ax', '.scr', '.drv', '.acm', '.tsp', '.com')
DIRECTORIES = ('/WINDOWS', '/WINDOWS/system32', '/WINDOWS/system32/drivers', '/WINDOWS/system32/wbem',
               '/Program Files/XP25', '/Program Files/Internet Explorer', '/Program Files/Outlook Express',
               '/Program Files/Windows Media Player', '/Program Files/Messenger', '/Program Files/NetMeeting',
               '/Program Files/Movie Maker', '/Program Files/MSN Gaming Zone/Windows',
               '/Program Files/Common Files/System', '/Program Files/Common Files/Microsoft Shared/MSInfo')
START = {0: 'boot', 1: 'system', 2: 'auto', 3: 'manual', 4: 'disabled'}
HIVES = {'system': '/WINDOWS/system32/config/system', 'software': '/WINDOWS/system32/config/software',
         'sam': '/WINDOWS/system32/config/SAM', 'default': '/WINDOWS/system32/config/default'}


def pe_facts(data):
    """Version resource and compile-time mitigation facts of one PE32 image."""
    if data[:2] != b'MZ' or len(data) < 0x100:
        return None
    pe, = struct.unpack_from('<I', data, 60)
    if pe + 0x100 > len(data) or data[pe:pe + 4] != b'PE\0\0':
        return None
    machine, nsec, stamp = struct.unpack_from('<HHI', data, pe + 4)
    opt = pe + 24
    if struct.unpack_from('<H', data, opt)[0] != 0x10b:
        return {'machine': hex(machine), 'pe32': False}
    optsize, = struct.unpack_from('<H', data, pe + 20)
    base, = struct.unpack_from('<I', data, opt + 28)
    headers, = struct.unpack_from('<I', data, opt + 60)
    subsystem, dllchar = struct.unpack_from('<HH', data, opt + 68)
    sections = [struct.unpack_from('<IIII', data, opt + optsize + n * 40 + 8) for n in range(nsec)]

    def offset(rva):
        if rva < headers:
            return rva
        for size, start, rawsize, raw in sections:
            if start <= rva < start + max(size, rawsize) and rva - start < rawsize:
                return raw + rva - start
        return None

    def directory(index):
        if index >= struct.unpack_from('<I', data, opt + 92)[0]:
            return 0, 0
        return struct.unpack_from('<II', data, opt + 96 + index * 8)

    facts = {'timestamp': stamp, 'linker': '%d.%d' % struct.unpack_from('<BB', data, opt + 2),
             'subsystem': subsystem, 'dll_characteristics': dllchar,
             'nx_compat': bool(dllchar & 0x100), 'dynamic_base': bool(dllchar & 0x40),
             'no_seh': bool(dllchar & 0x400), 'gs_cookie': False, 'safeseh': False}
    rva, size = directory(10)                      # load configuration: /GS cookie and SafeSEH table
    at = offset(rva) if rva else None
    if at is not None and at + 0x48 <= len(data):
        declared, = struct.unpack_from('<I', data, at)
        declared = declared or size
        if declared >= 0x40:
            facts['gs_cookie'] = struct.unpack_from('<I', data, at + 0x3c)[0] != 0
        if declared >= 0x48:
            table, count = struct.unpack_from('<II', data, at + 0x40)
            facts['safeseh'] = bool(table and count)
    marker = data.find(b'\xbd\x04\xef\xfe')         # VS_FIXEDFILEINFO signature
    if marker >= 0 and marker + 52 <= len(data):
        _, _, fms, fls, pms, pls, mask, flags = struct.unpack_from('<IIIIIIII', data, marker)
        facts['file_version'] = '%d.%d.%d.%d' % (fms >> 16, fms & 0xffff, fls >> 16, fls & 0xffff)
        facts['product_version'] = '%d.%d.%d.%d' % (pms >> 16, pms & 0xffff, pls >> 16, pls & 0xffff)
        facts['debug_build'] = bool(flags & mask & 1)
        facts['private_build'] = bool(flags & mask & 8)
    return facts


def origin(facts):
    """Which code base a Microsoft system binary was built from, by its own version resource."""
    parts = facts.get('file_version', '').split('.')
    if len(parts) != 4 or parts[2] != '2600':      # 5.1.2600.x system files and 6.0.2600.x shell files
        return 'other'
    build = int(parts[3])
    if build == 1106 and facts.get('private_build'):
        return 'xp25_source_built_sp1_qfe1106'     # QFE 1106 with the private-build flag: this project's own build
    return 'sp3' if build >= 5512 else 'sp2' if build >= 2180 else 'sp1' if build >= 1106 else 'rtm'


def hive_values(data, prefix):
    """{subkey path below prefix: {value name: decoded}} for one hive subtree."""
    found = collections.OrderedDict()
    low = prefix.lower()
    for path, name, vtype, raw in regf.walk(data):
        at = path.lower().find(low)
        if at < 0:
            continue
        key = found.setdefault(path[at + len(low):].lstrip('\\'), collections.OrderedDict())
        if name is None or raw is None:
            continue
        if vtype == 4 and len(raw) == 4:
            key[name] = struct.unpack('<I', raw)[0]
        elif vtype in (1, 2):
            key[name] = raw.decode('utf-16-le', 'replace').rstrip('\0')
        elif vtype == 7:
            key[name] = [x for x in raw.decode('utf-16-le', 'replace').split('\0') if x]
        else:
            key[name] = {'type': vtype, 'hex': raw.hex()[:128]}
    return found


def services(system):
    table = collections.OrderedDict()
    for key, values in hive_values(system, 'ControlSet001\\Services\\').items():
        parts = key.split('\\')
        row = table.setdefault(parts[0], {})
        if len(parts) == 1:
            for name in ('Type', 'Start', 'ErrorControl', 'ImagePath', 'ObjectName', 'DisplayName',
                         'DependOnService', 'DependOnGroup', 'Group'):
                if name in values:
                    row[name] = values[name]
        elif len(parts) == 2 and parts[1].lower() == 'parameters' and 'ServiceDll' in values:
            row['ServiceDll'] = values['ServiceDll']
        elif len(parts) == 2 and parts[1].lower() == 'security' and 'Security' in values:
            row['has_explicit_security_descriptor'] = True
    result = []
    for name, row in table.items():
        kind = row.get('Type')
        if not isinstance(kind, int):
            continue
        row.update(name=name, start=START.get(row.get('Start'), row.get('Start')),
                   kind='driver' if kind & 0xf else 'win32' if kind & 0x130 else 'other')
        result.append(row)
    return result


def accounts(sam):
    """Local account names, account-control flags and Administrators membership (no hashes are read)."""
    users = {}
    for key, values in hive_values(sam, 'SAM\\Domains\\Account\\Users\\').items():
        parts = key.split('\\')
        if len(parts) == 1 and len(parts[0]) == 8 and 'F' in values and isinstance(values['F'], dict):
            raw = bytes.fromhex(values['F']['hex'])
            if len(raw) >= 0x3a:
                acb, = struct.unpack_from('<H', raw, 0x38)
                users[int(parts[0], 16)] = {'rid': int(parts[0], 16), 'disabled': bool(acb & 1),
                                           'password_not_required': bool(acb & 4), 'normal_account': bool(acb & 0x10),
                                           'password_never_expires': bool(acb & 0x200)}
    for path, name, vtype, raw in regf.walk(sam):
        low = path.lower()
        if '\\users\\names\\' in low and name == '':
            if vtype in users:
                users[vtype]['name'] = path.rsplit('\\', 1)[1]
    admins = []
    for path, name, vtype, raw in regf.walk(sam):
        if path.lower().endswith('builtin\\aliases\\00000220') and name == 'C' and raw:
            offset, length, count = struct.unpack_from('<III', raw, 0x28)[0], struct.unpack_from('<I', raw, 0x2c)[0], struct.unpack_from('<I', raw, 0x30)[0]
            at = 0x34 + offset
            for _ in range(count):
                if at + 8 > len(raw):
                    break
                subs = raw[at + 1]
                authority = int.from_bytes(raw[at + 2:at + 8], 'big')
                values = struct.unpack_from('<' + 'I' * subs, raw, at + 8)
                admins.append('S-1-%d-%s' % (authority, '-'.join(map(str, values))))
                at += 8 + 4 * subs
    for user in users.values():
        user['administrator'] = any(sid.endswith('-%d' % user['rid']) for sid in admins)
    return sorted(users.values(), key=lambda row: row['rid']), admins


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('disk', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    disk, output = args.disk.resolve(), args.output.resolve()
    if not disk.is_relative_to(ROOT / '.work') or disk.stat().st_mode & 0o222:
        parser.error('disk must be a frozen private image')
    if not output.is_relative_to(ROOT / '.work'):
        parser.error('private output must remain under .work/')
    output.mkdir(parents=True, exist_ok=False)
    os.chdir(output)
    digest = hashlib.sha256()
    with disk.open('rb') as f:
        for block in iter(lambda: f.read(1 << 22), b''):
            digest.update(block)
    binaries, hives, errors = [], {}, []
    with lab.partition(disk, False) as device:
        for name, path in HIVES.items():
            hives[name] = lab.run(['ntfscat', device, path])
        for directory in DIRECTORIES:
            try:
                names = lab.run(['ntfsls', '-p', directory, device]).decode('utf-8', 'replace').splitlines()
            except RuntimeError as error:
                errors.append({'directory': directory, 'error': str(error).strip()[:200]})
                continue
            for name in sorted(names):
                if not name.lower().endswith(PE_SUFFIXES):
                    continue
                path = directory + '/' + name
                try:
                    data = lab.run(['ntfscat', device, path])
                    facts = pe_facts(data)
                except (RuntimeError, struct.error) as error:
                    errors.append({'path': path, 'error': str(error).strip()[:200]})
                    continue
                if not facts:
                    continue
                facts.update(path=path, bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
                if 'file_version' in facts:
                    facts['origin'] = origin(facts)
                binaries.append(facts)
    Path('journal.jsonl').unlink()                 # thousands of identical ntfscat records; inventory.json is the evidence
    system, software = hives['system'], hives['software']
    users, admins = accounts(hives['sam'])
    settings = {
        'lsa': hive_values(system, 'ControlSet001\\Control\\Lsa').get('', {}),
        'terminal_server': hive_values(system, 'ControlSet001\\Control\\Terminal Server').get('', {}),
        'session_manager': hive_values(system, 'ControlSet001\\Control\\Session Manager').get('', {}),
        'lanmanserver_parameters': hive_values(system, 'ControlSet001\\Services\\lanmanserver\\Parameters').get('', {}),
        'lanmanworkstation_parameters': hive_values(system, 'ControlSet001\\Services\\lanmanworkstation\\Parameters').get('', {}),
        'netbt_parameters': hive_values(system, 'ControlSet001\\Services\\NetBT\\Parameters').get('', {}),
        'rpc_ole': hive_values(software, 'Microsoft\\Ole').get('', {}),
        'firewall_standard': hive_values(system, 'ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile'),
        'firewall_domain': hive_values(system, 'ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile'),
        'winlogon': hive_values(software, 'Microsoft\\Windows NT\\CurrentVersion\\Winlogon').get('', {}),
        'explorer_policies': hive_values(software, 'Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer').get('', {}),
        'run': hive_values(software, 'Microsoft\\Windows\\CurrentVersion\\Run').get('', {}),
        'appinit': {k: v for k, v in hive_values(software, 'Microsoft\\Windows NT\\CurrentVersion\\Windows').get('', {}).items()
                    if k.lower().startswith('appinit')},
        'wsh_settings': hive_values(software, 'Microsoft\\Windows Script Host\\Settings').get('', {}),
        'safer_code_identifiers': hive_values(software, 'Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers').get('', {}),
        'schannel_protocols': hive_values(system, 'ControlSet001\\Control\\SecurityProviders\\SCHANNEL\\Protocols'),
        'crypto_providers': sorted(hive_values(software, 'Microsoft\\Cryptography\\Defaults\\Provider\\')),
        'ie_version': hive_values(software, 'Microsoft\\Internet Explorer').get('', {}).get('Version'),
        'current_version': {k: v for k, v in hive_values(software, 'Microsoft\\Windows NT\\CurrentVersion').get('', {}).items()
                            if k in ('CurrentVersion', 'CurrentBuildNumber', 'CSDVersion', 'ProductName', 'BuildLab')},
    }
    table = services(system)
    by_origin = collections.Counter(row.get('origin', 'no_version_resource') for row in binaries)
    summary = {
        'binaries': len(binaries), 'by_origin': dict(by_origin),
        'gs_cookie': sum(row.get('gs_cookie', False) for row in binaries),
        'safeseh': sum(row.get('safeseh', False) for row in binaries),
        'nx_compat': sum(row.get('nx_compat', False) for row in binaries),
        'dynamic_base': sum(row.get('dynamic_base', False) for row in binaries),
        'debug_builds': sorted(row['path'] for row in binaries if row.get('debug_build')),
        'source_built': sorted(row['path'] for row in binaries if row.get('origin') == 'xp25_source_built_sp1_qfe1106'),
        'win32_services': {start: sorted(row['name'] for row in table if row['kind'] == 'win32' and row['start'] == start)
                           for start in ('auto', 'manual', 'disabled')},
        'drivers_by_start': dict(collections.Counter(row['start'] for row in table if row['kind'] == 'driver')),
    }
    Path('inventory.json').write_text(json.dumps({
        'schema': 1, 'evidence': 'static offline inspection; no guest was booted',
        'image': str(disk), 'image_sha256': digest.hexdigest(), 'summary': summary, 'accounts': users,
        'administrators_alias_members': admins, 'settings': settings, 'services': table,
        'binaries': binaries, 'errors': errors}, indent=1) + '\n')
    print(json.dumps(summary, indent=1))


if __name__ == '__main__':
    main()
