#!/usr/bin/env python3
"""Start a disposable, NIC-free clone of the prepared native Windows build VM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import xp_lab as lab

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / '.work/boot-debug-20261022'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    parser.add_argument('--base', type=Path, default=ARTIFACTS / 'build-21/disk.qcow2')
    parser.add_argument('--media', type=Path, required=True)
    args = parser.parse_args()
    if '/' in args.name or args.name in ('.', '..'):
        parser.error('a fresh simple experiment name is required')
    base, media = args.base.resolve(), args.media.resolve()
    if not base.is_relative_to(ROOT / '.work') or base.stat().st_mode & 0o222:
        parser.error('backing must be a frozen private image')
    if not media.is_file() or not media.is_relative_to(ROOT / '.work'):
        parser.error('private generated media required')
    output = ARTIFACTS / args.name
    output.mkdir(exist_ok=False)
    os.chdir(output)
    hashes = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (base, media)}
    lab.run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', base, 'disk.qcow2'])
    command = ['qemu-system-i386', '-name', args.name,
               '-machine', 'pc-i440fx-8.2,kernel-irqchip=on', '-accel', 'kvm',
               '-cpu', 'qemu32', '-m', '512', '-smp', '1', '-nodefaults', '-nic', 'none',
               '-vga', 'std', '-display', 'none', '-monitor', 'none',
               '-qmp', 'unix:qmp.sock,server=on,wait=off', '-serial', 'file:serial.log',
               '-drive', 'file=disk.qcow2,format=qcow2,if=ide,index=0',
               '-drive', 'file=' + str(media) + ',format=raw,if=ide,index=2,media=cdrom,readonly=on',
               '-boot', 'order=c', '-pidfile', 'qemu.pid', '-no-reboot', '-no-shutdown']
    Path('qemu-command.json').write_text(json.dumps(command, indent=2) + '\n')
    Path('inputs.json').write_text(json.dumps(hashes, indent=2) + '\n')
    with Path('qemu.log').open('w') as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    lab.record({'argv': command, 'pid': process.pid})
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError(Path('qemu.log').read_text())
        if Path('qmp.sock').exists():
            break
        time.sleep(.1)
    else:
        raise TimeoutError('QMP startup')
    lab.checkpoint(stage='native_build_host_booting', qemu_pid=process.pid, inputs=hashes)
    print(output)


if __name__ == '__main__':
    main()
