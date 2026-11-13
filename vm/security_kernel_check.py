#!/usr/bin/env python3
"""Offline check of the kernel a frozen XP25 image boots and of what its
drivers need from it. Nothing is booted and nothing is written to the image.

It reads boot.ini, the kernel and HAL the boot entry names, every file in
system32\\drivers and the SYSTEM hive, and records:

  * the export table of the installed kernel and HAL (names, ordinals), and
    whether each name given with --require is exported and where it points;
  * for every driver, the kernel/HAL imports that the installed kernel and
    HAL do not export, and any import by ordinal (an ordinal import would
    make the kernel's export order part of the ABI);
  * the service entries of the Windows Firewall (SharedAccess) and of its
    driver (IPNAT) from the control set the image boots.

usage: security_kernel_check.py <frozen .work image> <fresh .work output dir>
                                [--require NAME ...] [--compare-kernel FILE]"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vm'))
import regf
import xp_lab as lab

START = {0: 'boot', 1: 'system', 2: 'auto', 3: 'manual', 4: 'disabled'}
KERNEL_NAMES = ('ntoskrnl.exe', 'ntkrnlmp.exe', 'ntkrnlpa.exe', 'ntkrpamp.exe')


class PE:
    def __init__(self, data):
        self.data = data
        pe, = struct.unpack_from('<I', data, 60)
        if data[:2] != b'MZ' or data[pe:pe + 4] != b'PE\0\0':
            raise ValueError('not a PE image')
        self.machine, nsec = struct.unpack_from('<HH', data, pe + 4)
        self.stamp, = struct.unpack_from('<I', data, pe + 8)
        optsize, = struct.unpack_from('<H', data, pe + 20)
        opt = pe + 24
        if struct.unpack_from('<H', data, opt)[0] != 0x10b:
            raise ValueError('not PE32')
        self.base, = struct.unpack_from('<I', data, opt + 28)
        self.headers, = struct.unpack_from('<I', data, opt + 60)
        self.checksum, = struct.unpack_from('<I', data, opt + 64)
        self.sections = [struct.unpack_from('<8sIIII', data, opt + optsize + n * 40) for n in range(nsec)]
        self.directories = [struct.unpack_from('<II', data, opt + 96 + n * 8) for n in range(16)]

    def offset(self, rva):
        if rva < self.headers:
            return rva
        for _, size, start, rawsize, raw in self.sections:
            if start <= rva < start + max(size, rawsize) and rva - start < rawsize:
                return raw + rva - start
        return None

    def section_of(self, rva):
        for name, size, start, rawsize, _ in self.sections:
            if start <= rva < start + max(size, rawsize):
                return name.rstrip(b'\0').decode('latin-1')
        return None

    def text(self, rva):
        at = self.offset(rva)
        return self.data[at:self.data.index(b'\0', at)].decode('latin-1') if at is not None else None

    def exports(self):
        """{name: (ordinal, rva, forwarder or None)} of the named exports."""
        rva, size = self.directories[0]
        at = self.offset(rva) if rva else None
        if at is None:
            return {}
        base, nfunc, nname, functions, names, ordinals = struct.unpack_from('<IIIIII', self.data, at + 16)
        result = {}
        for i in range(nname):
            name = self.text(struct.unpack_from('<I', self.data, self.offset(names) + 4 * i)[0])
            index, = struct.unpack_from('<H', self.data, self.offset(ordinals) + 2 * i)
            target, = struct.unpack_from('<I', self.data, self.offset(functions) + 4 * index)
            forward = self.text(target) if rva <= target < rva + size else None
            result[name] = (base + index, target, forward)
        return result

    def imports(self):
        """{dll lower-case: [name or '#ordinal', ...]}"""
        rva, _ = self.directories[1]
        at = self.offset(rva) if rva else None
        result = {}
        while at is not None:
            lookup, _, _, name, thunk = struct.unpack_from('<IIIII', self.data, at)
            if not name:
                break
            entries = result.setdefault(self.text(name).lower(), [])
            table = self.offset(lookup or thunk)
            while table is not None:
                value, = struct.unpack_from('<I', self.data, table)
                if not value:
                    break
                entries.append('#%d' % (value & 0xffff) if value & 0x80000000 else self.text(value + 2))
                table += 4
            at += 20
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('image', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--require', action='append', default=[])
    parser.add_argument('--compare-kernel', type=Path, help='a kernel file the installed one must equal byte for byte')
    args = parser.parse_args()
    image, out = args.image.resolve(), args.output.resolve()
    if not image.is_relative_to(ROOT / '.work') or image.stat().st_mode & 0o222:
        parser.error('image must be a frozen private .work file')
    if not out.is_relative_to(ROOT / '.work'):
        parser.error('private .work output required')
    reference = args.compare_kernel.resolve().read_bytes() if args.compare_kernel else None
    out.mkdir(parents=True, exist_ok=False)
    os.chdir(out)
    with lab.partition(image, False) as device:
        def cat(path):
            return lab.run(['ntfscat', device, path])
        boot_ini = cat('/boot.ini').decode('latin-1')
        default = re.search(r'^default=(.*)$', boot_ini, re.M | re.I).group(1).strip()
        boot_entry = next(line for line in boot_ini.splitlines() if line.lower().startswith(default.lower() + '='))
        kernel_name = (re.search(r'/kernel=(\S+)', boot_entry, re.I) or [None, 'ntoskrnl.exe'])[1]
        hal_name = (re.search(r'/hal=(\S+)', boot_entry, re.I) or [None, 'hal.dll'])[1]
        kernel = cat('/WINDOWS/system32/' + kernel_name)
        hal = cat('/WINDOWS/system32/' + hal_name)
        system = cat('/WINDOWS/system32/config/system')
        names = [line.strip() for line in lab.run(['ntfsls', device, '-p', '/WINDOWS/system32/drivers']).decode('latin-1').splitlines()]
        drivers = {name: cat('/WINDOWS/system32/drivers/' + name) for name in sorted(names) if name.lower().endswith('.sys')}
    (out / 'kernel').mkdir()
    (out / 'kernel' / kernel_name).write_bytes(kernel)
    (out / 'kernel' / hal_name).write_bytes(hal)
    Path('boot.ini').write_text(boot_ini)

    kpe, hpe = PE(kernel), PE(hal)
    kexp, hexp = kpe.exports(), hpe.exports()
    required = {}
    for name in args.require:
        item = kexp.get(name)
        required[name] = None if not item else {'ordinal': item[0], 'rva': '0x%x' % item[1], 'section': kpe.section_of(item[1]),
                                                'forwarder': item[2], 'first_bytes': kernel[kpe.offset(item[1]):kpe.offset(item[1]) + 16].hex()}

    # The control set the loader uses, then the service entries.
    values = list(regf.walk(system))
    select = {name: data for path, name, kind, data in values if path.lower().endswith('\\select') and name}
    current = struct.unpack('<I', select['Default'][:4])[0] if 'Default' in select else 1
    prefix = 'ControlSet%03d\\Services\\' % current
    services = {}
    for path, name, kind, data in values:
        at = path.find(prefix)
        if at < 0 or name is None:
            continue
        rest = path[at + len(prefix):].split('\\')
        if len(rest) == 1:
            services.setdefault(rest[0].lower(), {})[name] = (kind, data)

    def service(name):
        entry = services.get(name.lower())
        if entry is None:
            return None
        result = {}
        for key, (kind, data) in sorted(entry.items()):
            if data is None:
                result[key] = None
            elif kind == 4:
                result[key] = struct.unpack('<I', data[:4])[0]
            elif kind in (1, 2):
                result[key] = data.decode('utf-16-le', 'replace').rstrip('\0')
            elif kind == 7:
                result[key] = [x for x in data.decode('utf-16-le', 'replace').split('\0') if x]
            else:
                result[key] = data.hex()[:160]
        if isinstance(result.get('Start'), int):
            result['start_name'] = START.get(result['Start'])
        return result

    report = []
    by_ordinal, unresolved_enabled = [], []
    for name, data in drivers.items():
        try:
            imports = PE(data).imports()
        except (ValueError, struct.error, TypeError) as error:
            report.append({'driver': name, 'error': str(error)})
            continue
        missing, ordinals = [], []
        for dll, symbols in imports.items():
            table = kexp if dll in KERNEL_NAMES else hexp if dll == 'hal.dll' else None
            if table is None:
                continue
            for symbol in symbols:
                if symbol.startswith('#'):
                    ordinals.append(dll + symbol)
                elif symbol not in table:
                    missing.append(dll + '!' + symbol)
        entry = services.get(name[:-4].lower())
        start = struct.unpack('<I', entry['Start'][1][:4])[0] if entry and 'Start' in entry and entry['Start'][1] else None
        row = {'driver': name, 'sha256': hashlib.sha256(data).hexdigest(), 'service_start': START.get(start),
               'kernel_imports': sum(len(v) for k, v in imports.items() if k in KERNEL_NAMES),
               'unresolved': missing, 'by_ordinal': ordinals}
        report.append(row)
        if ordinals:
            by_ordinal.append(name)
        if missing and start in (0, 1, 2, 3):
            unresolved_enabled.append({'driver': name, 'start': START.get(start), 'unresolved': missing})

    result = {
        'image': str(image), 'boot_entry': boot_entry.strip(), 'kernel_file': kernel_name, 'hal_file': hal_name,
        'kernel_sha256': hashlib.sha256(kernel).hexdigest(), 'hal_sha256': hashlib.sha256(hal).hexdigest(),
        'kernel_link_time': kpe.stamp, 'kernel_export_names': len(kexp), 'hal_export_names': len(hexp),
        'required_exports': required,
        'kernel_equals_reference': None if reference is None else
            {'reference': str(args.compare_kernel), 'reference_sha256': hashlib.sha256(reference).hexdigest(), 'equal': reference == kernel},
        'control_set': current,
        'firewall_service': service('SharedAccess'), 'firewall_driver_service': service('IPNAT'),
        'firewall_driver': next((row for row in report if row['driver'].lower() == 'ipnat.sys'), None),
        'drivers_checked': len(report), 'drivers_importing_kernel_by_ordinal': by_ordinal,
        'enabled_drivers_with_unresolved_kernel_imports': unresolved_enabled,
    }
    Path('kernel-exports.json').write_text(json.dumps({name: {'ordinal': v[0], 'rva': '0x%x' % v[1], 'forwarder': v[2]}
                                                       for name, v in sorted(kexp.items())}, indent=0) + '\n')
    Path('drivers.json').write_text(json.dumps(report, indent=1) + '\n')
    Path('report.json').write_text(json.dumps(result, indent=1) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k not in ('firewall_service', 'firewall_driver_service')}, indent=1))
    return 0



if __name__ == '__main__':
    raise SystemExit(main())
