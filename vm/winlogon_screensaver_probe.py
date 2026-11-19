#!/usr/bin/env python3
"""R-0: verify screen savers and the idle lock under the XP25 Winlogon.

A fresh, NIC-free overlay of a frozen XP25 image is booted. Optionally the image's
winlogon.exe is replaced offline by the one under test (the original is kept as recovery).
tests/guest/screensaver_probe.c is staged with a Startup script for XP25: it shortens the
idle timeout and selects ssstars.scr. This driver does what a person at the console would:
it logs on, waits for each saver, ends it with a key (or Ctrl+Alt+Del), unlocks the station
with XP25's blank password, locks it with Win+L, and logs on again after the logon desktop's
saver. Every gate is decided from the guest's own serial records (Winlogon's and the
probe's); screenshots are evidence only. Nothing here writes the frozen image.

Gates:
  logon                 the first logon reaches the desktop
  nonsecure_saver       a session saver (ssstars.scr, not secure) starts as the user; USER
                        reports it on the Screen-saver desktop; a key returns to the desktop
                        and nothing is locked
  notices_stop          USER's screen-saver notices stop within 5 s of the start of a saver
                        that ran for at least 8 s
  secure_saver_key      a secure saver ended by a key locks the session; the password unlocks it
  secure_saver_sas      a secure saver ended by Ctrl+Alt+Del is stopped and the session locked
                        before the unlock dialog; the password unlocks it
  locked_station_saver  on a station locked with Win+L the user's saver starts, and its end
                        returns to the locked station
  logon_desktop_saver   after a logoff the logon desktop's saver (.DEFAULT's logon.scr, not
                        secure) interrupts the logon dialog, and a key brings the dialog back
  relogon               a second logon reaches the desktop; the probe restores .DEFAULT
  no_failure            no Winlogon failure record and no failed probe case

usage: winlogon_screensaver_probe.py --name RUN --image IMG --image-sha256 HEX --probe PROBE
         [--winlogon WINLOGON.exe] [--accel kvm|tcg] [--cpus N] [--stage GUEST=HOST] [--timeout S]
"""
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
from winlogon_switch_probe import dialog_present, sha, wait_for

STARTUP = '/Documents and Settings/XP25/Start Menu/Programs/Startup/XP25ScreenSaver.cmd'
STARTUP_CMD = ('@echo off\r\n'
               'rem R-0 screen-saver probe: runs at each XP25 logon (see vm/winlogon_screensaver_probe.py).\r\n'
               'C:\\xp25\\screensaver-probe.exe {seconds}\r\n')


def serial_records(serial):
    rows = []
    text = serial.read_bytes().decode('latin-1') if serial.exists() else ''
    for line in text.splitlines():
        if '{' not in line:
            continue
        try:
            rows.append(json.loads(line[line.index('{'):]))
        except ValueError:
            pass
    return rows


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
    parser.add_argument('--timeout', type=int, default=20, help='idle seconds before each saver (5..600)')
    parser.add_argument('--out-root', type=Path, default=ROOT / '.work/screensaver-20261119/runs')
    args = parser.parse_args()
    if '/' in args.name or args.name in ('.', '..'):
        parser.error('a fresh simple run name is required')
    if not 5 <= args.timeout <= 600:
        parser.error('--timeout must be 5..600 seconds')
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
    (out / 'XP25ScreenSaver.cmd').write_bytes(STARTUP_CMD.replace('{seconds}', str(args.timeout)).encode('latin-1'))
    staged = {'/xp25/screensaver-probe.exe': probe, STARTUP: out / 'XP25ScreenSaver.cmd', **extra}
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
    command = ['qemu-system-i386', '-name', 'xp25ss-' + args.name, '-machine', machine, '-accel', accel,
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
              'winlogon_sha256': sha(winlogon) if winlogon else 'image-original', 'recovery_winlogon_sha256': recovery,
              'probe_sha256': sha(probe), 'timeout_s': args.timeout,
              'staged': {t: sha(s) for t, s in extra.items()}, 'gates': [], 'screenshots': []}
    slow = 4 if args.accel == 'tcg' else 1
    gates = record['gates']

    def events():
        return [r for r in serial_records(serial) if 'xp25_winlogon' in r]

    def count(name):
        return sum(1 for r in events() if r['xp25_winlogon'] == name)

    def after(name, index):
        """Winlogon records from the index-th occurrence (0-based) of an event onwards."""
        rows, seen = events(), -1
        for i, r in enumerate(rows):
            if r['xp25_winlogon'] == name:
                seen += 1
                if seen == index:
                    return rows[i:]
        return []

    def status_of(rows, name):
        for r in rows:
            if r['xp25_winlogon'] == name:
                return r['status']
        return None

    def probe_case(label):
        for r in serial_records(serial):
            if r.get('saver_case') == label or r.get('saver_probe') == label:
                return r
        return None

    def gate(label, ok, **detail):
        gates.append({'gate': label, 'passed': bool(ok), **detail})
        lab.record({'gate': label, 'passed': bool(ok), **detail})
        print(('PASS ' if ok else 'FAIL ') + label, json.dumps(detail), flush=True)

    try:
        for _ in range(600):
            if qemu.poll() is not None:
                raise RuntimeError('qemu exited: ' + (out / 'qemu.log').read_text())
            if (out / 'qmp.sock').exists():
                break
            time.sleep(0.1)
        scratch = out / 'poll.ppm'
        with lab.QMP() as q:
            def shown():
                q.call('screendump', {'filename': str(scratch)})
                return dialog_present(scratch)

            def shot(name):
                q.call('screendump', {'filename': str(out / (name + '.ppm'))})
                record['screenshots'].append(name + '.ppm')

            def key(k, pause=0.5):
                q.hmp('sendkey ' + k)
                time.sleep(pause * slow)

            def grows(name, before, seconds):
                return wait_for(lambda: count(name) > before, timeout=seconds * slow, poll=1.0)

            def unlock():
                """XP25's password is blank; MSGINA shows its unlock dialog without Ctrl+Alt+Del."""
                before = count('SensUnlockEvent')
                for attempt in range(3):
                    time.sleep(4 * slow)
                    key('ctrl-a')
                    key('backspace')
                    key('ret')
                    if grows('SensUnlockEvent', before, 45):
                        return attempt
                    shot('unlock-retry-%d' % (attempt + 1))
                    key('ret')          # dismiss a refusal, if one is shown
                return None

            saver_wait = (args.timeout * 6 + 120)
            q.call('cont')
            gate('boot_logon_dialog', wait_for(shown, timeout=240 * slow, poll=1.0))
            time.sleep(3 * slow)
            shot('00-logon-dialog')
            key('ret')
            gate('logon', grows('session_interactive', 0, 180))
            time.sleep(10 * slow)
            shot('01-desktop')

            # A: a non-secure session saver, ended by a key.
            locks = count('SensLockEvent')
            ok = grows('screen_saver_started_session', 0, saver_wait)
            time.sleep(8 * slow)
            shot('a1-saver')
            key('shift', 2)
            returned = grows('screen_saver_returned_to_desktop', 0, 60)
            case = wait_for(lambda: probe_case('nonsecure'), timeout=120 * slow, poll=2.0)
            shot('a2-desktop')
            # Records are read when the gate is decided: a line can reach serial.log after the one
            # that ended a wait. Winlogon logs a run's statistics before screen_saver_ended.
            rows = after('screen_saver_started_session', 0)
            gate('nonsecure_saver', ok and returned and status_of(rows, 'screen_saver_secure') == 0 and
                 count('screen_saver_image_ssstars.scr') >= 1 and count('SensLockEvent') == locks and
                 bool(case) and case.get('passed') == 1, probe=case,
                 pid=status_of(rows, 'screen_saver_started_session'))
            notices, last, run_ms = (status_of(rows, n) for n in
                                     ('screen_saver_notices_during_run', 'screen_saver_last_notice_ms', 'screen_saver_run_ms'))
            gate('notices_stop', run_ms is not None and run_ms >= 8000 and notices is not None and
                 (notices == 0 or (last is not None and last < 5000)),
                 notices_during_run=notices, last_notice_ms=last, run_ms=run_ms)

            # B: a secure saver, ended by a key: the session locks; the password unlocks it.
            locks = count('SensLockEvent')
            ok = grows('screen_saver_started_session', 1, saver_wait)
            time.sleep(6 * slow)
            shot('b1-saver')
            key('shift', 2)
            locked = grows('screen_saver_secure_lock', 0, 60) and grows('SensLockEvent', locks, 60)
            time.sleep(3 * slow)
            shot('b2-locked')
            retries = unlock()
            case = wait_for(lambda: probe_case('secure_key'), timeout=120 * slow, poll=2.0)
            rows = after('screen_saver_started_session', 1)
            gate('secure_saver_key', ok and status_of(rows, 'screen_saver_secure') == 1 and locked and
                 retries is not None and bool(case) and case.get('passed') == 1, probe=case, unlock_retries=retries)

            # C: a secure saver, ended by Ctrl+Alt+Del.
            locks = count('SensLockEvent')
            ok = grows('screen_saver_started_session', 2, saver_wait)
            time.sleep(6 * slow)
            shot('c1-saver')
            key('ctrl-alt-delete', 2)
            stopped = grows('screen_saver_stopped_by_sas', 0, 60) and grows('SensLockEvent', locks, 60)
            time.sleep(3 * slow)
            shot('c2-unlock-dialog')
            retries = unlock()
            case = wait_for(lambda: probe_case('secure_sas'), timeout=120 * slow, poll=2.0)
            rows = after('screen_saver_started_session', 2)
            gate('secure_saver_sas', ok and status_of(rows, 'screen_saver_secure') == 1 and stopped and
                 count('screen_saver_secure_lock') == 1 and retries is not None and bool(case) and
                 case.get('passed') == 1, probe=case, unlock_retries=retries)

            # D: the user's saver on a station locked with Win+L.
            ready = wait_for(lambda: probe_case('ready_locked'), timeout=120 * slow, poll=2.0)
            locks = count('SensLockEvent')
            key('meta_l-l', 2)
            locked = grows('SensLockEvent', locks, 60)
            shot('d1-locked')
            ok = grows('screen_saver_started_locked', 0, saver_wait)
            time.sleep(6 * slow)
            shot('d2-saver')
            key('shift', 2)
            back = grows('screen_saver_returned_to_locked', 0, 60)
            time.sleep(3 * slow)
            shot('d3-locked-again')
            retries = unlock()
            case = wait_for(lambda: probe_case('locked'), timeout=120 * slow, poll=2.0)
            rows = after('screen_saver_started_locked', 0)
            gate('locked_station_saver', bool(ready) and locked and ok and status_of(rows, 'screen_saver_secure') == 0
                 and back and retries is not None and bool(case) and case.get('passed') == 1, probe=case,
                 unlock_retries=retries)

            # E: after the probe logs off, the logon desktop's saver.
            done = wait_for(lambda: probe_case('first_session_done'), timeout=240 * slow, poll=2.0)
            unloaded = grows('profile_unloaded', 0, 240)
            dialog = wait_for(shown, timeout=120 * slow, poll=1.0)
            shot('e1-logon-dialog')
            ok = grows('screen_saver_started_logon_desktop', 0, saver_wait)
            time.sleep(6 * slow)
            shot('e2-saver')
            key('shift', 2)
            back = grows('screen_saver_returned_to_logon', 0, 60)
            dialog_back = wait_for(shown, timeout=90 * slow, poll=1.0)
            shot('e3-logon-dialog-back')
            rows = after('screen_saver_started_logon_desktop', 0)
            gate('logon_desktop_saver', bool(done) and done.get('passed') == 1 and unloaded and dialog and ok and
                 status_of(rows, 'screen_saver_secure') == 0 and count('screen_saver_image_logon.scr') >= 1 and
                 count('screen_saver_dialog_interrupted') >= 1 and back and dialog_back,
                 first_session=done, interrupted_dialogs=count('screen_saver_dialog_interrupted'))

            # F: log on again; the probe restores the logon desktop's timeout.
            time.sleep(3 * slow)
            key('ret')
            again = grows('session_interactive', 1, 180)
            case = wait_for(lambda: probe_case('restored'), timeout=180 * slow, poll=2.0)
            time.sleep(5 * slow)
            shot('f1-desktop')
            gate('relogon', again and bool(case) and case.get('passed') == 1, probe=case)
            try:
                q.call('quit')
            except (EOFError, RuntimeError, OSError):
                pass
    finally:
        try:
            qemu.wait(timeout=20)
        except subprocess.TimeoutExpired:
            qemu.terminate()
    rows = serial_records(serial)
    failures = [r for r in rows if r.get('phase') == 'failed' or
                ('xp25_winlogon' in r and r['xp25_winlogon'].startswith('screen_saver') and
                 r['xp25_winlogon'].endswith('_failed'))]
    failed_cases = [r for r in rows if ('saver_case' in r or 'saver_probe' in r) and r.get('passed') == 0]
    gate('no_failure', not failures and not failed_cases, failures=failures[:5], failed_cases=failed_cases[:5])
    record['winlogon_saver_records'] = [r for r in rows if str(r.get('xp25_winlogon', '')).startswith('screen_saver')]
    record['probe_records'] = [r for r in rows if 'saver_case' in r or 'saver_probe' in r]
    record['passed'] = all(g['passed'] for g in gates)
    (out / 'result.json').write_text(json.dumps(record, indent=1) + '\n')
    print(json.dumps({'name': args.name, 'accel': args.accel, 'cpus': args.cpus,
                      'winlogon_sha256': record['winlogon_sha256'], 'passed': record['passed'],
                      'gates': {g['gate']: g['passed'] for g in gates}}, indent=1))
    return 0 if record['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
