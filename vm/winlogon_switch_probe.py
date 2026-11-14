#!/usr/bin/env python3
"""Verify the XP25 Winlogon paints its logon controls after a user switch (logoff).

A fresh, NIC-free overlay of a frozen XP25 image is booted. Optionally the image's
winlogon.exe is replaced offline by the one under test (the original is kept as
recovery). A Startup script in the XP25 profile logs the account off a few seconds
after each interactive logon, so the logon dialog is shown again and again. For each
cycle the driver waits for the XP25 Winlogon to show the logon dialog (its serial
`gina_dialog_edit` records), lets any repaint settle, captures the framebuffer, and
measures whether the user-name edit field is painted (a white edit box) or blank (the
grey dialog face) — the exact difference between a correct and a failed account switch.
Then it logs on with Enter (the XP25 account has a blank password) to drive the next
cycle. Nothing here writes the frozen image; the overlay and every screenshot are kept.

usage: winlogon_switch_probe.py --name RUN --image IMG --image-sha256 HEX --probe PROBE
         [--winlogon WINLOGON.exe] [--accel kvm|tcg] [--cycles N] [--settle S]
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vm'))
import xp_lab as lab

# The user-name edit field, in the 640x480 logon dialog (measured from the reference
# screenshots): white when the control is painted, the grey dialog face when it is not.
FIELD = {'x0': 205, 'x1': 425, 'y0': 199, 'y1': 211}
STARTUP = '/Documents and Settings/XP25/Start Menu/Programs/Startup/XP25WinlogonSwitch.cmd'
LOGOFF_CMD = ('@echo off\r\n'
              'rem Log the account off a few seconds after each logon so the logon dialog\r\n'
              'rem is shown again; this drives the user-switch paint test.\r\n'
              'ping -n 5 127.0.0.1 >nul\r\n'
              'C:\\xp25\\winlogon-switch-probe.exe power logoff\r\n')


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 22), b''):
            h.update(block)
    return h.hexdigest()


# The logon dialog's beige body, to tell "the logon dialog is on screen" from the black
# secure desktop between dialogs (the SAS-notice step shows nothing, so a serial marker is
# not enough — the dialog is detected on screen).
BODY = {'x0': 125, 'x1': 520, 'y0': 180, 'y1': 262}
BEIGE = (236, 233, 216)


def read_ppm(ppm):
    data = Path(ppm).read_bytes()
    assert data[:2] == b'P6', 'expected a binary PPM screendump'
    i, fields = 2, []
    while len(fields) < 3:
        while i < len(data) and data[i] in b' \t\r\n':
            i += 1
        if data[i:i + 1] == b'#':
            while data[i] not in b'\r\n':
                i += 1
            continue
        j = i
        while data[j] not in b' \t\r\n':
            j += 1
        fields.append(int(data[i:j]))
        i = j
    width, height, _maxv = fields
    return width, height, data[i + 1:]


def fraction(ppm, box, test):
    width, height, pixels = read_ppm(ppm)
    hit = total = 0
    for y in range(box['y0'], min(box['y1'], height)):
        for x in range(box['x0'], min(box['x1'], width)):
            o = (y * width + x) * 3
            total += 1
            if test(pixels[o], pixels[o + 1], pixels[o + 2]):
                hit += 1
    return round(hit / total, 3) if total else 0.0


def painted_fraction(ppm):
    """Fraction of the user-name field that is white (a painted edit's background)."""
    return fraction(ppm, FIELD, lambda r, g, b: r > 235 and g > 235 and b > 235)


def dialog_present(ppm):
    """True when the logon dialog's beige body is on screen (not the black gap between dialogs)."""
    return fraction(ppm, BODY, lambda r, g, b: abs(r - BEIGE[0]) < 24 and abs(g - BEIGE[1]) < 24 and abs(b - BEIGE[2]) < 28) > 0.3


def wait_for(predicate, timeout, poll=1.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(poll)
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--name', required=True)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--image-sha256', required=True)
    parser.add_argument('--probe', type=Path, required=True)
    parser.add_argument('--winlogon', type=Path, help='winlogon.exe to install (omit to test the image as-is)')
    parser.add_argument('--accel', choices=('kvm', 'tcg'), default='kvm')
    parser.add_argument('--cycles', type=int, default=5)
    parser.add_argument('--settle', type=float, default=3.0)
    parser.add_argument('--out-root', type=Path, default=ROOT / '.work/winlogon-ui-20261113/runs')
    args = parser.parse_args()
    if '/' in args.name or args.name in ('.', '..'):
        parser.error('a fresh simple run name is required')
    image, probe = args.image.resolve(), args.probe.resolve()
    winlogon = args.winlogon.resolve() if args.winlogon else None
    for path in (image, probe) + ((winlogon,) if winlogon else ()):
        if not path.is_relative_to(ROOT / '.work') or not path.is_file():
            parser.error('inputs must be private .work/ files: ' + str(path))
    if image.stat().st_mode & 0o222:
        parser.error('the base image must be frozen (read-only)')
    out = args.out_root.resolve() / args.name
    out.mkdir(parents=True, exist_ok=False)
    os.chdir(out)
    if sha(image) != args.image_sha256:
        raise SystemExit('base image hash mismatch')

    disk = out / 'disk.qcow2'
    lab.run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(image), str(disk)])
    (out / 'XP25WinlogonSwitch.cmd').write_bytes(LOGOFF_CMD.encode('latin-1'))
    staged = {'/xp25/winlogon-switch-probe.exe': probe, STARTUP: out / 'XP25WinlogonSwitch.cmd'}
    recovery = None
    with lab.partition(disk, True) as device:
        if winlogon:
            original = lab.run(['ntfscat', device, '/WINDOWS/system32/winlogon.exe'])
            (out / 'recovery-winlogon.exe').write_bytes(original)
            recovery = hashlib.sha256(original).hexdigest()
            staged['/WINDOWS/system32/winlogon.exe'] = winlogon
        for target, source in staged.items():
            lab.run(['ntfscp', '-t', device, str(source), target])
            if lab.run(['ntfscat', device, target]) != Path(source).read_bytes():
                raise RuntimeError('staging mismatch: ' + target)
    if sha(image) != args.image_sha256:
        raise RuntimeError('base image changed during staging')

    machine = 'pc-i440fx-8.2' + (',kernel-irqchip=on' if args.accel == 'kvm' else '')
    accel = 'kvm' if args.accel == 'kvm' else 'tcg,thread=single'
    command = ['qemu-system-i386', '-name', 'xp25wl-' + args.name, '-machine', machine, '-accel', accel,
               '-cpu', 'qemu32', '-m', '512', '-smp', '1', '-nodefaults', '-nic', 'none', '-vga', 'std',
               '-display', 'none', '-qmp', 'unix:qmp.sock,server=on,wait=off', '-serial', 'file:serial.log',
               '-rtc', 'base=localtime', '-drive', 'file=disk.qcow2,format=qcow2,if=ide,index=0',
               '-boot', 'order=c', '-pidfile', 'qemu.pid', '-no-reboot', '-no-shutdown', '-S']
    (out / 'qemu-command.json').write_text(json.dumps(command, indent=1) + '\n')
    with (out / 'qemu.log').open('w') as log:
        qemu = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    serial = out / 'serial.log'
    record = {'name': args.name, 'image': str(image), 'image_sha256': args.image_sha256, 'accel': args.accel,
              'winlogon': str(winlogon) if winlogon else None,
              'winlogon_sha256': sha(winlogon) if winlogon else 'image-original',
              'recovery_winlogon_sha256': recovery, 'field_region': FIELD, 'cycles': []}
    try:
        for _ in range(600):
            if qemu.poll() is not None:
                raise RuntimeError('qemu exited: ' + (out / 'qemu.log').read_text())
            if (out / 'qmp.sock').exists():
                break
            time.sleep(0.1)
        scratch = out / 'poll.ppm'

        def shown():
            q.call('screendump', {'filename': str(scratch)})
            return dialog_present(scratch)

        with lab.QMP() as q:
            q.call('cont')
            for cycle in range(args.cycles):
                # Wait for the logon dialog itself to be on screen (not the black SAS gap).
                if not wait_for(shown, timeout=240, poll=1.0):
                    record['cycles'].append({'cycle': cycle, 'error': 'logon dialog did not appear'})
                    break
                time.sleep(args.settle)        # let it settle and paint
                name = 'cycle-%02d-%s' % (cycle, 'boot' if cycle == 0 else 'after-switch')
                q.call('screendump', {'filename': str(out / (name + '.ppm'))})
                present = dialog_present(out / (name + '.ppm'))
                white = painted_fraction(out / (name + '.ppm')) if present else None
                subprocess.run(['qemu-img', 'convert', '-f', 'ppm', '-O', 'png', str(out / (name + '.ppm')),
                                str(out / (name + '.png'))], capture_output=True)
                record['cycles'].append({'cycle': cycle, 'screenshot': name + '.png', 'dialog_on_screen': present,
                                         'white_fraction': white, 'painted': bool(present) and white >= 0.6,
                                         'first_boot': cycle == 0})
                lab.record({'cycle': cycle, 'dialog_on_screen': present, 'white_fraction': white})
                # Log on (blank password) so the Startup logs off and the dialog returns; then
                # wait for the dialog to leave the screen so the next cycle sees a fresh one.
                q.hmp('sendkey ret')
                wait_for(lambda: not shown(), timeout=120, poll=1.0)
            try:
                q.call('quit')
            except (EOFError, RuntimeError):
                pass
    finally:
        try:
            qemu.wait(timeout=20)
        except subprocess.TimeoutExpired:
            qemu.terminate()
    switches = [c for c in record['cycles'] if not c.get('first_boot') and 'painted' in c]
    record['switch_cycles'] = len(switches)
    record['switch_cycles_painted'] = sum(c['painted'] for c in switches)
    record['all_switches_painted'] = bool(switches) and all(c['painted'] for c in switches)
    (out / 'result.json').write_text(json.dumps(record, indent=1) + '\n')
    print(json.dumps({k: record[k] for k in ('name', 'accel', 'winlogon_sha256', 'switch_cycles',
                                             'switch_cycles_painted', 'all_switches_painted')}, indent=1))
    return 0 if record['all_switches_painted'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
