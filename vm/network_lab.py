#!/usr/bin/env python3
"""Fresh networking clone of a verified, stopped source-kernel desktop.

Requires the private Milestone 1 lab and images retained on this Linux host.
The baseline's byte hashes, every staged file and commands are recorded.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / '.work/boot-debug-20261022'
import xp_lab as lab


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    parser.add_argument('--base', type=Path, default=LAB / 'pipeline-reproduction-kvm/disk.qcow2')
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--probe', type=Path, required=True)
    parser.add_argument('--standard-probe', type=Path, required=True)
    parser.add_argument('--pointer-probe', type=Path, default=LAB / 'pointer-probe-build-01/pointer_probe.exe')
    parser.add_argument('--session-probe', type=Path, default=LAB / 'session-probe-build-01/session_probe.exe')
    parser.add_argument('--component', nargs=2, metavar=('GUEST_PATH', 'BINARY'),
                        help='replace one system32 EXE/DLL or Windows Explorer and preserve its original')
    parser.add_argument('--userenv-package', type=Path, help='reviewed UserEnv package with unchanged SP3 forwarder dependency')
    parser.add_argument('--test-media', type=Path, help='private read-only regression CD attached before boot')
    parser.add_argument('--startup-script', type=Path, help='private self-removing XP25 startup regression fixture')
    parser.add_argument('--cpus', type=int, choices=[1, 2], default=1)
    parser.add_argument('--accel', choices=['kvm', 'tcg'], default='kvm')
    parser.add_argument('--pause-for-debugger', action='store_true', help='leave the new guest paused before firmware execution')
    args = parser.parse_args()
    if '/' in args.name or args.name in ('.', '..'):
        parser.error('a new simple experiment name is required')
    base = args.base.resolve()
    if not base.is_relative_to(ROOT / '.work') or base.stat().st_mode & 0o222:
        parser.error('backing image must be a frozen private image')
    for path in (args.test_media, args.startup_script):
        if path and (not path.resolve().is_relative_to(ROOT / '.work') or not path.is_file()):
            parser.error('test media and startup fixture must be private existing files')
    if args.startup_script and not args.test_media:
        parser.error('startup fixture requires a regression CD')
    if args.test_media:
        args.test_media = args.test_media.resolve()
    if args.startup_script:
        args.startup_script = args.startup_script.resolve()
    output = LAB / args.name
    output.mkdir(exist_ok=False)
    files = {'/WINDOWS/system32/wshtcpip.dll': args.helper.resolve(),
             '/xp25/network_probe.exe': args.probe.resolve(),
             '/xp25/pointer_probe.exe': args.pointer_probe.resolve(),
             '/xp25/session_probe.exe': args.session_probe.resolve(),
             '/xp25/xp_probe.exe': args.standard_probe.resolve()}
    if args.startup_script:
        files['/Documents and Settings/XP25/Start Menu/Programs/Startup/XP25Regression.cmd'] = args.startup_script.resolve()
    component = None
    if args.component:
        import re
        target, binary = args.component
        if not re.fullmatch(r'/WINDOWS/(system32/[A-Za-z0-9_]+\.(exe|dll)|explorer\.exe)', target):
            parser.error('one explicit system32 EXE/DLL or Windows Explorer path is required')
        component = Path(binary).resolve()
        if not component.is_file() or not component.is_relative_to(ROOT / '.work'):
            parser.error('compiled component must be a private .work/ file')
        reserved = {name.casefold() for name in files} | {
            '/windows/system32/xp25krnl.exe', '/windows/system32/xp25hal.dll'}
        if target.casefold() in reserved:
            parser.error('component must not replace an existing baseline staging entry')
        files[target] = component
    support = None
    if args.userenv_package:
        package = args.userenv_package.resolve()
        if not component or target != '/WINDOWS/system32/userenv.dll' or not package.is_relative_to(ROOT / '.work'):
            parser.error('UserEnv support requires one explicit UserEnv replacement and private package')
        info = json.loads((package / 'manifest.json').read_text())
        original = package / 'ue51sp3.dll'
        if sha(component) != info['components']['userenv.dll'] or sha(original) != info['original_sp3_sha256']:
            parser.error('UserEnv package artifacts changed')
        files['/WINDOWS/system32/ue51sp3.dll'] = original
        support = {'target': '/WINDOWS/system32/ue51sp3.dll', 'package': str(package),
                   'sha256': sha(original), 'scope': 'Unchanged original SP3 dependency for three unavailable implementations.'}
    if args.cpus == 2:
        files.update({'/WINDOWS/system32/xp25krnl.exe':
                      LAB / 'build-21-final/nt/base/ntos/init/mp/obj/i386/ntkrnlmp.exe',
                      '/WINDOWS/system32/xp25hal.dll':
                      LAB / 'build-21-final/nt/base/hals/halacpi/mpapic/obj/i386/halmacpi.dll'})
    os.chdir(output)
    base_hash = sha(base)
    lab.run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', base, 'disk.qcow2'])
    staged = {}
    recovery = None
    with lab.partition(output / 'disk.qcow2', True) as device:
        if support:
            names = lab.run(['ntfsls', '-p', '/WINDOWS/system32', device]).decode().splitlines()
            matches = [name for name in names if name.casefold() == 'ue51sp3.dll']
            if matches and (matches != ['ue51sp3.dll'] or
                    lab.run(['ntfscat', device, support['target']]) != original.read_bytes()):
                raise ValueError('existing UserEnv companion name/content must not be overwritten')
        if component:
            original = lab.run(['ntfscat', device, target])
            backup = output / ('recovery-' + Path(target).name)
            backup.write_bytes(original)
            guest_backup = '/xp25/recovery-' + Path(target).name
            lab.run(['ntfscp', '-t', device, backup, guest_backup])
            assert lab.run(['ntfscat', device, guest_backup]) == original
            recovery = {'target': target, 'host_backup': str(backup),
                        'guest_backup': guest_backup,
                        'original_sha256': hashlib.sha256(original).hexdigest()}
        for target, source in files.items():
            lab.run(['ntfscp', '-t', device, source, target])
            content = lab.run(['ntfscat', device, target])
            assert content == source.read_bytes(), target
            staged[target] = {'source': str(source), 'sha256': sha(source)}
            if args.startup_script and source == args.startup_script.resolve():
                staged[target]['transient_self_removing_fixture'] = True
    assert sha(base) == base_hash
    Path('inputs.json').write_text(json.dumps({'base': str(base), 'base_sha256': base_hash,
                                             'staged': staged, 'recovery': recovery,
                                             'support_dependency': support}, indent=2) + '\n')
    machine = 'pc-i440fx-8.2' + (',kernel-irqchip=on' if args.accel == 'kvm' else '')
    command = ['qemu-system-i386', '-name', args.name, '-machine', machine,
               '-accel', args.accel, '-cpu', 'qemu32', '-m', '512', '-smp', str(args.cpus),
               '-nodefaults', '-nic', 'none', '-vga', 'std', '-display', 'none',
               '-monitor', 'none', '-qmp', 'unix:qmp.sock,server=on,wait=off',
               '-gdb', 'unix:gdb.sock,server=on,wait=off', '-serial', 'file:serial.log',
               '-rtc', 'base=localtime', '-drive', 'file=disk.qcow2,format=qcow2,if=ide,index=0',
               '-drive', ('file=' + str(args.test_media.resolve()) + ',format=raw,readonly=on,' if args.test_media else '') +
                         'if=ide,index=2,media=cdrom', '-boot', 'order=c',
               '-pidfile', 'qemu.pid', '-D', 'trace.log', '-no-reboot', '-no-shutdown', '-S']
    Path('qemu-command.json').write_text(json.dumps(command, indent=2) + '\n')
    wrapper = ['unshare', '--user', '--map-root-user', '--net', 'python3',
               str(ROOT / 'vm/isolated_network.py'), 'qemu-command.json',
               '--parent-netns', os.readlink('/proc/self/ns/net')]
    with Path('namespace.log').open('w') as log:
        process = subprocess.Popen(wrapper, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    lab.record({'argv': wrapper, 'pid': process.pid})
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError(Path('namespace.log').read_text() +
                               (Path('qemu.log').read_text() if Path('qemu.log').exists() else ''))
        if Path('qmp.sock').exists():
            try:
                with lab.QMP() as q:
                    if not args.pause_for_debugger:
                        q.call('cont')
                break
            except (ConnectionRefusedError, FileNotFoundError, EOFError):
                pass
        time.sleep(.1)
    else:
        raise TimeoutError('QMP startup')
    lab.checkpoint(stage='isolated_network_guest_paused' if args.pause_for_debugger else 'isolated_network_guest_booting', namespace_pid=process.pid,
                   qemu_pid=int(Path('qemu.pid').read_text()), base_sha256=base_hash)
    print(output)


if __name__ == '__main__':
    main()
