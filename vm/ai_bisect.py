#!/usr/bin/env python3
"""Diagnostic boot: a NIC-free KVM child of one frozen private image with a
single probe staged at the volume root (nothing runs at logon). Used to bisect
platform behavior across retained XP25 checkpoints; the parent is never
opened writable."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vm'))
import xp_lab as lab


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--probe', type=Path, required=True)
    parser.add_argument('--cpus', type=int, choices=[1, 2], default=1)
    args = parser.parse_args()
    image = args.image.resolve()
    args.probe = args.probe.resolve()
    if image.stat().st_mode & 0o222:
        parser.error('parent image must be frozen (read-only)')
    out = ROOT / '.work/ai-20261025/bisect' / args.name
    out.mkdir(parents=True, exist_ok=False)
    os.chdir(out)
    digest = hashlib.sha256(image.read_bytes()).hexdigest()
    lab.run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', image, 'disk.qcow2'])
    with lab.partition(out / 'disk.qcow2', True) as device:
        lab.run(['ntfscp', '-t', device, args.probe.resolve(), '/ai_probe_dpapi.exe'])
    command = ['qemu-system-i386', '-name', args.name, '-machine', 'pc-i440fx-8.2,kernel-irqchip=on', '-accel', 'kvm',
               '-cpu', 'qemu32', '-m', '512', '-smp', str(args.cpus), '-nodefaults', '-nic', 'none', '-vga', 'std',
               '-display', 'none', '-monitor', 'none', '-qmp', 'unix:qmp.sock,server=on,wait=off',
               '-serial', 'file:serial.log', '-rtc', 'base=localtime', '-drive', 'file=disk.qcow2,format=qcow2,if=ide,index=0',
               '-boot', 'order=c', '-pidfile', 'qemu.pid', '-no-reboot', '-no-shutdown']
    Path('inputs.json').write_text(json.dumps({'parent': str(image), 'parent_sha256': digest,
                                               'probe_sha256': hashlib.sha256(args.probe.read_bytes()).hexdigest(),
                                               'command': command}, indent=2) + '\n')
    with Path('qemu.log').open('w') as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    lab.record({'argv': command, 'pid': process.pid})
    for _ in range(100):
        if Path('qmp.sock').exists():
            break
        time.sleep(0.1)
    print(out)


if __name__ == '__main__':
    main()
