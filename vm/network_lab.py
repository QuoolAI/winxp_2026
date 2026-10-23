#!/usr/bin/env python3
"""Fresh networking clone of a verified, stopped source-kernel desktop.

Requires the private Milestone 1 lab and images retained on this Ubuntu host.
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
    parser.add_argument('--cpus', type=int, choices=[1, 2], default=1)
    parser.add_argument('--accel', choices=['kvm', 'tcg'], default='kvm')
    args = parser.parse_args()
    if '/' in args.name or args.name in ('.', '..'):
        parser.error('a new simple experiment name is required')
    base = args.base.resolve()
    if not base.is_relative_to(ROOT / '.work') or base.stat().st_mode & 0o222:
        parser.error('backing image must be a frozen private image')
    output = LAB / args.name
    output.mkdir(exist_ok=False)
    files = {'/WINDOWS/system32/wshtcpip.dll': args.helper.resolve(),
             '/xp25/network_probe.exe': args.probe.resolve(),
             '/xp25/pointer_probe.exe': args.pointer_probe.resolve(),
             '/xp25/session_probe.exe': args.session_probe.resolve(),
             '/xp25/xp_probe.exe': args.standard_probe.resolve()}
    if args.cpus == 2:
        files.update({'/WINDOWS/system32/xp25krnl.exe':
                      LAB / 'build-21-final/nt/base/ntos/init/mp/obj/i386/ntkrnlmp.exe',
                      '/WINDOWS/system32/xp25hal.dll':
                      LAB / 'build-21-final/nt/base/hals/halacpi/mpapic/obj/i386/halmacpi.dll'})
    os.chdir(output)
    base_hash = sha(base)
    lab.run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', base, 'disk.qcow2'])
    staged = {}
    with lab.partition(output / 'disk.qcow2', True) as device:
        for target, source in files.items():
            lab.run(['ntfscp', '-t', device, source, target])
            content = lab.run(['ntfscat', device, target])
            assert content == source.read_bytes(), target
            staged[target] = {'source': str(source), 'sha256': sha(source)}
    assert sha(base) == base_hash
    Path('inputs.json').write_text(json.dumps({'base': str(base), 'base_sha256': base_hash,
                                             'staged': staged}, indent=2) + '\n')
    machine = 'pc-i440fx-8.2' + (',kernel-irqchip=on' if args.accel == 'kvm' else '')
    command = ['qemu-system-i386', '-name', args.name, '-machine', machine,
               '-accel', args.accel, '-cpu', 'qemu32', '-m', '512', '-smp', str(args.cpus),
               '-nodefaults', '-nic', 'none', '-vga', 'std', '-display', 'none',
               '-monitor', 'none', '-qmp', 'unix:qmp.sock,server=on,wait=off',
               '-gdb', 'unix:gdb.sock,server=on,wait=off', '-serial', 'file:serial.log',
               '-rtc', 'base=localtime', '-drive', 'file=disk.qcow2,format=qcow2,if=ide,index=0',
               '-drive', 'if=ide,index=2,media=cdrom', '-boot', 'order=c',
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
            break
        time.sleep(.1)
    else:
        raise TimeoutError('QMP startup')
    with lab.QMP() as q:
        q.call('cont')
    lab.checkpoint(stage='isolated_network_guest_booting', namespace_pid=process.pid,
                   qemu_pid=int(Path('qemu.pid').read_text()), base_sha256=base_hash)
    print(output)


if __name__ == '__main__':
    main()
