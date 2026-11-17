#!/usr/bin/env python3
"""Verify the XP25 Winlogon paints its logon controls after a user switch (logoff).

A fresh, NIC-free overlay of a frozen XP25 image is booted. Optionally the image's
winlogon.exe is replaced offline by the one under test (the original is kept as
recovery). A Startup script logs the account off a few seconds after each interactive
logon, so the logon dialog is shown again and again. For each cycle the driver waits
until the logon dialog is on screen, lets any repaint settle, captures the framebuffer
twice a few seconds apart, and measures whether the user-name and password edit fields
are painted (white edit boxes) or blank (the grey dialog face) — the exact difference
between a correct and a failed account switch. Then it logs on to drive the next cycle.

By default only the XP25 account (blank password) is used. With --second-user, an All
Users Startup script creates that account (password --second-password) in the first
session and, in every session, offers the other account to MSGINA (DefaultUserName)
before logging off, so consecutive cycles switch between two distinct accounts; the
driver types only the offered account's password. --wrong-password-cycle first enters a
wrong password in that cycle and requires the logon to be refused. Each logon is
confirmed from the guest's own serial record of the logged-on account SID, and the SIDs
must alternate. Nothing here writes the frozen image; the overlay and every screenshot
are kept.

usage: winlogon_switch_probe.py --name RUN --image IMG --image-sha256 HEX --probe PROBE
         [--winlogon WINLOGON.exe] [--accel kvm|tcg] [--cpus N] [--cycles N] [--settle S]
         [--second-user NAME --second-password PW [--wrong-password-cycle N]]
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

# The user-name and password edit fields, in the 640x480 logon dialog (measured from the
# reference screenshots): white when the control is painted, the grey dialog face when not.
FIELD = {'x0': 205, 'x1': 425, 'y0': 199, 'y1': 211}
PASSWORD_FIELD = {'x0': 205, 'x1': 425, 'y0': 226, 'y1': 238}
STARTUP = '/Documents and Settings/XP25/Start Menu/Programs/Startup/XP25WinlogonSwitch.cmd'
ALL_USERS_STARTUP = '/Documents and Settings/All Users/Start Menu/Programs/Startup/XP25WinlogonSwitch.cmd'
LOGOFF_CMD = ('@echo off\r\n'
              'rem Log the account off a few seconds after each logon so the logon dialog\r\n'
              'rem is shown again; this drives the user-switch paint test.\r\n'
              'ping -n 5 127.0.0.1 >nul\r\n'
              'C:\\xp25\\winlogon-switch-probe.exe power logoff\r\n')
SWITCH_CMD = ('@echo off\r\n'
              'rem Alternate two accounts through logoff: the first session creates the second\r\n'
              'rem account; every session offers the other account to MSGINA, then logs off.\r\n'
              'set NEXT={user}\r\n'
              'if /i "%USERNAME%"=="{user}" set NEXT=XP25\r\n'
              'if exist C:\\xp25\\switch-account.created goto offer\r\n'
              'net user {user} {password} /add /comment:"XP25 account-switch test" > C:\\xp25\\switch-account.txt 2>&1\r\n'
              'echo XP25_SWITCH_ACCOUNT_CREATED=%ERRORLEVEL% > COM1\r\n'
              'rem An administrator, so that its session can offer XP25 again (HKLM).\r\n'
              'net localgroup Administrators {user} /add >> C:\\xp25\\switch-account.txt 2>&1\r\n'
              'echo XP25_SWITCH_ACCOUNT_ADMIN=%ERRORLEVEL% > COM1\r\n'
              'echo done > C:\\xp25\\switch-account.created\r\n'
              ':offer\r\n'
              'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v DefaultUserName /d %NEXT% /f >nul\r\n'
              'echo XP25_SWITCH_OFFER=%ERRORLEVEL% > COM1\r\n'
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


def painted_fraction(ppm, box=FIELD):
    """Fraction of an edit field that is white (a painted edit's background)."""
    return fraction(ppm, box, lambda r, g, b: r > 235 and g > 235 and b > 235)


def logon_sids(serial):
    """The account SID the XP25 Winlogon records for each logon, in order."""
    sids = []
    text = serial.read_bytes().decode('latin-1') if serial.exists() else ''
    for line in text.splitlines():
        if '{' not in line:
            continue
        try:
            event = json.loads(line[line.index('{'):]).get('xp25_winlogon', '')
        except ValueError:
            continue
        if event.startswith('S-1-5-21-'):
            sids.append(event)
    return sids


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
    parser.add_argument('--cpus', type=int, choices=(1, 2), default=1,
                        help='2 vCPUs need a multiprocessor kernel and HAL in the image (or staged with --stage)')
    parser.add_argument('--stage', action='append', default=[], metavar='GUEST=HOST',
                        help='also replace this guest file (e.g. the MP kernel/HAL); recorded with its hash')
    parser.add_argument('--cycles', type=int, default=5)
    parser.add_argument('--settle', type=float, default=3.0)
    parser.add_argument('--second-user', help='switch between XP25 and this account (created in the guest)')
    parser.add_argument('--second-password', help='password of the second account (lowercase letters and digits)')
    parser.add_argument('--wrong-password-cycle', type=int, help='in this second-account cycle, first enter a wrong password')
    parser.add_argument('--out-root', type=Path, default=ROOT / '.work/winlogon-ui-20261113/runs')
    args = parser.parse_args()
    if '/' in args.name or args.name in ('.', '..'):
        parser.error('a fresh simple run name is required')
    if bool(args.second_user) != bool(args.second_password):
        parser.error('--second-user and --second-password go together')
    if args.second_user and not (args.second_user.isalnum() and args.second_password.isalnum()
                                 and args.second_password == args.second_password.lower()
                                 and args.second_user.upper() != 'XP25'):
        parser.error('the second account needs an alphanumeric name other than XP25 and a lowercase alphanumeric password')
    if args.wrong_password_cycle is not None and not (args.second_user and args.wrong_password_cycle % 2 == 1
                                                      and 0 < args.wrong_password_cycle < args.cycles):
        parser.error('--wrong-password-cycle must be an odd (second-account) cycle of a --second-user run')
    image, probe = args.image.resolve(), args.probe.resolve()
    winlogon = args.winlogon.resolve() if args.winlogon else None
    extra = {}
    for item in args.stage:
        target, _, source = item.partition('=')
        if not target.startswith('/WINDOWS/system32/') or not source:
            parser.error('--stage takes /WINDOWS/system32/NAME=HOSTFILE')
        extra[target] = Path(source).resolve()
    for path in (image, probe) + ((winlogon,) if winlogon else ()) + tuple(extra.values()):
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
    if args.second_user:
        script = SWITCH_CMD.replace('{user}', args.second_user).replace('{password}', args.second_password)
        startup = ALL_USERS_STARTUP
    else:
        script, startup = LOGOFF_CMD, STARTUP
    (out / 'XP25WinlogonSwitch.cmd').write_bytes(script.encode('latin-1'))
    staged = {'/xp25/winlogon-switch-probe.exe': probe, startup: out / 'XP25WinlogonSwitch.cmd', **extra}
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
               '-cpu', 'qemu32', '-m', '512', '-smp', str(args.cpus), '-nodefaults', '-nic', 'none', '-vga', 'std',
               '-display', 'none', '-qmp', 'unix:qmp.sock,server=on,wait=off', '-serial', 'file:serial.log',
               '-rtc', 'base=localtime', '-drive', 'file=disk.qcow2,format=qcow2,if=ide,index=0',
               '-boot', 'order=c', '-pidfile', 'qemu.pid', '-no-reboot', '-no-shutdown', '-S']
    (out / 'qemu-command.json').write_text(json.dumps(command, indent=1) + '\n')
    with (out / 'qemu.log').open('w') as log:
        qemu = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    serial = out / 'serial.log'
    record = {'name': args.name, 'image': str(image), 'image_sha256': args.image_sha256, 'accel': args.accel,
              'cpus': args.cpus, 'winlogon': str(winlogon) if winlogon else None,
              'winlogon_sha256': sha(winlogon) if winlogon else 'image-original',
              'recovery_winlogon_sha256': recovery, 'field_region': FIELD, 'password_field_region': PASSWORD_FIELD,
              'second_user': args.second_user, 'staged': {t: sha(s) for t, s in extra.items()}, 'cycles': []}
    slow = 4 if args.accel == 'tcg' else 1      # TCG runs the same steps several times slower
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

        def capture(name):
            q.call('screendump', {'filename': str(out / (name + '.ppm'))})
            present = dialog_present(out / (name + '.ppm'))
            user = painted_fraction(out / (name + '.ppm')) if present else None
            password = painted_fraction(out / (name + '.ppm'), PASSWORD_FIELD) if present else None
            return {'screenshot': name + '.ppm', 'dialog_on_screen': present, 'white_fraction': user,
                    'password_white_fraction': password,
                    'painted': bool(present) and user >= 0.6 and password >= 0.6}

        def type_slowly(text):
            for c in text:
                q.hmp('sendkey ' + c)
                time.sleep(0.12 * slow)

        with lab.QMP() as q:
            q.call('cont')
            for cycle in range(args.cycles):
                account = args.second_user if args.second_user and cycle % 2 else 'XP25'
                password = args.second_password if account != 'XP25' else ''
                # Wait for the logon dialog itself to be on screen (not the black SAS gap).
                if not wait_for(shown, timeout=240 * slow, poll=1.0):
                    record['cycles'].append({'cycle': cycle, 'account': account, 'error': 'logon dialog did not appear'})
                    break
                time.sleep(args.settle * slow)  # let it settle and paint
                name = 'cycle-%02d-%s' % (cycle, 'boot' if cycle == 0 else 'after-switch')
                early = capture(name)
                time.sleep(4 * slow)            # a later capture: the controls must stay painted
                late = capture(name + '-late')
                row = {'cycle': cycle, 'account': account, 'first_boot': cycle == 0, **early,
                       'late': late, 'painted': early['painted'] and late['painted']}
                if cycle == args.wrong_password_cycle:
                    # A wrong password must be refused: no new logon, the dialog stays.
                    before = len(logon_sids(serial))
                    type_slowly('wrong' + password)
                    q.hmp('sendkey ret')
                    time.sleep(12 * slow)
                    refused = capture('cycle-%02d-wrong-password' % cycle)
                    row['wrong_password_rejected'] = len(logon_sids(serial)) == before
                    q.hmp('sendkey ret')        # dismiss MSGINA's logon message
                    time.sleep(4 * slow)
                    row['after_wrong_password'] = capture('cycle-%02d-after-wrong-password' % cycle)
                    row['refusal_screenshot'] = refused['screenshot']
                    row['painted'] = row['painted'] and row['after_wrong_password']['painted']
                # Log on with the offered account's password; the guest's serial SID record
                # confirms the logon. A lost key (TCG) fails the logon: dismiss and retype.
                before = len(logon_sids(serial))
                row['input_retries'] = 0
                for attempt in range(3):
                    type_slowly(password)
                    q.hmp('sendkey ret')
                    if wait_for(lambda: len(logon_sids(serial)) > before, timeout=90 * slow, poll=2.0):
                        break
                    capture('cycle-%02d-logon-retry-%d' % (cycle, attempt + 1))
                    row['input_retries'] += 1
                    q.hmp('sendkey ret')
                    time.sleep(4 * slow)
                row['logged_on'] = len(logon_sids(serial)) > before
                record['cycles'].append(row)
                lab.record({k: row[k] for k in ('cycle', 'account', 'dialog_on_screen', 'white_fraction',
                                                'password_white_fraction', 'painted', 'logged_on')})
                if not row['logged_on']:
                    break
                # Wait for the dialog to leave the screen so the next cycle sees a fresh one.
                wait_for(lambda: not shown(), timeout=120 * slow, poll=1.0)
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
    record['all_switches_painted'] = len(switches) == args.cycles - 1 and all(c['painted'] for c in switches)
    sids = logon_sids(serial)
    record['logon_sids'] = sids
    passed = record['all_switches_painted'] and all(c.get('logged_on') for c in record['cycles'])
    if args.second_user:
        record['distinct_accounts'] = len(set(sids))
        record['accounts_alternate'] = len(sids) >= 2 and all(a != b for a, b in zip(sids, sids[1:]))
        passed = passed and record['distinct_accounts'] == 2 and record['accounts_alternate']
        if args.wrong_password_cycle is not None:
            rejected = [c.get('wrong_password_rejected') for c in record['cycles'] if c['cycle'] == args.wrong_password_cycle]
            record['wrong_password_rejected'] = rejected == [True]
            passed = passed and record['wrong_password_rejected']
    record['passed'] = passed
    (out / 'result.json').write_text(json.dumps(record, indent=1) + '\n')
    print(json.dumps({k: record[k] for k in ('name', 'accel', 'cpus', 'winlogon_sha256', 'switch_cycles',
                                             'switch_cycles_painted', 'all_switches_painted', 'passed')
                      + (('distinct_accounts', 'accounts_alternate') if args.second_user else ())
                      + (('wrong_password_rejected',) if args.wrong_password_cycle is not None else ())}, indent=1))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
