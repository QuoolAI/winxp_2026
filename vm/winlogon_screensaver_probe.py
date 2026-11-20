#!/usr/bin/env python3
"""R-0: verify screen savers and the idle lock under the XP25 Winlogon.

A fresh, NIC-free overlay of a frozen XP25 image is booted. Optionally the image's
winlogon.exe is replaced offline by the one under test (the original is kept as recovery).
tests/guest/screensaver_probe.c is staged with a Startup script for XP25: it shortens the
idle timeout and selects ssstars.scr. This driver does what a person at the console would:
it logs on, waits for each saver, ends it with a key (or Ctrl+Alt+Del), unlocks the station
with XP25's blank password, locks it with Win+L, and logs on again after the logon desktop's
saver, then turns the guest off normally. Every gate is decided from the guest's own
records: Winlogon's and the probe's serial lines merged with their file logs
(C:\\xp25\\native-winlogon.log, C:\\xp25\\saver-probe.log), read from the overlay afterwards,
since COM1 drops a line when the port is busy (roadmap R-0b). result.json also keeps the
serial-only verdict. Screenshots are evidence only. Nothing here writes the frozen image.

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


def json_lines(text):
    rows = []
    for line in text.splitlines():
        if '{' in line:
            try:
                rows.append(json.loads(line[line.index('{'):]))
            except ValueError:
                pass
    return rows


def guest_file_records(out):
    """Winlogon's records since this run's boot (C:\\xp25\\native-winlogon.log) and the probe's
    (C:\\xp25\\saver-probe.log), read offline from a read-only copy of the run's overlay. Both
    logs reach the disk only when the guest shuts down normally."""
    copy = out / 'records-disk.qcow2'
    subprocess.run(['cp', '--reflink=always', str(out / 'disk.qcow2'), str(copy)], check=True)
    copy.chmod(0o444)
    target = out / 'guest-records'
    result = subprocess.run([sys.executable, str(ROOT / 'vm/read_guest.py'), str(copy), str(target),
                             '/xp25/native-winlogon.log', '/xp25/saver-probe.log'], capture_output=True, text=True)
    (out / 'guest-records.log').write_text(result.stdout + result.stderr)
    winlogon_log, probe_log = target / 'xp25/native-winlogon.log', target / 'xp25/saver-probe.log'
    winlogon = [r for r in json_lines(winlogon_log.read_bytes().decode('latin-1')) if 'xp25_winlogon' in r] \
        if winlogon_log.exists() else []
    boots = [i for i, r in enumerate(winlogon) if r['xp25_winlogon'] == 'entry']
    winlogon = winlogon[boots[-1]:] if boots else []
    probe = json_lines(probe_log.read_bytes().decode('latin-1')) if probe_log.exists() else []
    return winlogon, probe


def merge_records(serial, file):
    """One ordered list of Winlogon records from its two copies: serial loses a line when COM1 is
    busy, the file loses what was not flushed. Aligned on the event names."""
    import difflib
    a = [r['xp25_winlogon'] for r in serial]
    b = [r['xp25_winlogon'] for r in file]
    merged = []
    for op, a1, a2, b1, b2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if op == 'equal':
            merged += serial[a1:a2]
        else:
            merged += serial[a1:a2] + file[b1:b2]
    return merged


def evaluate(winlogon, probe, live):
    """The gates, from Winlogon's records (in order), the probe's records and what the driver saw."""
    names = [r['xp25_winlogon'] for r in winlogon]

    def count(name, lo=0, hi=None):
        return names[lo or 0:hi].count(name)

    def at(name, index):
        seen = [i for i, n in enumerate(names) if n == name]
        return seen[index] if len(seen) > index else None

    def status_after(position, name):
        if position is None:
            return None
        for r in winlogon[position:]:
            if r['xp25_winlogon'] == name:
                return r['status']
        return None

    def case(label):
        rows = [r for r in probe if r.get('saver_case') == label or r.get('saver_probe') == label]
        return rows[0] if rows else None

    def passed(label):
        c = case(label)
        return bool(c) and c.get('passed') == 1

    def first_after(position, test):
        for i in range(position, len(winlogon)) if position is not None else ():
            if test(winlogon[i]):
                return i
        return None

    def unlocked(r):
        return r['xp25_winlogon'] == 'SensUnlockEvent' or (r['xp25_winlogon'] == 'gina_unlock_result' and r['status'] == 8)

    s0, s1, s2 = (at('screen_saver_started_session', i) for i in range(3))
    # A locked, idle station also runs the user's saver while the driver waits to unlock (slow
    # TCG timing), so the Win+L case is the first locked-station saver after the unlock that ends
    # the Ctrl+Alt+Del case.
    u2 = first_after(s2, unlocked)
    locked0 = first_after(u2, lambda r: r['xp25_winlogon'] == 'screen_saver_started_locked')
    logon0 = at('screen_saver_started_logon_desktop', 0)
    gates = []

    def gate(label, ok, **detail):
        gates.append({'gate': label, 'passed': bool(ok), **detail})

    gate('boot_logon_dialog', live.get('boot_logon_dialog'))
    gate('logon', count('session_interactive') >= 1)
    gate('nonsecure_saver', s0 is not None and status_after(s0, 'screen_saver_secure') == 0 and
         count('screen_saver_image_ssstars.scr') >= 1 and count('screen_saver_returned_to_desktop', s0, s1) >= 1 and
         count('SensLockEvent', s0, s1) == 0 and passed('nonsecure'),
         probe=case('nonsecure'), pid=status_after(s0, 'screen_saver_started_session'))
    notices, last, run_ms = (status_after(s0, n) for n in
                             ('screen_saver_notices_during_run', 'screen_saver_last_notice_ms', 'screen_saver_run_ms'))
    gate('notices_stop', run_ms is not None and run_ms >= 8000 and notices is not None and
         (notices == 0 or (last is not None and last < 5000)),
         notices_during_run=notices, last_notice_ms=last, run_ms=run_ms)
    gate('secure_saver_key', s1 is not None and status_after(s1, 'screen_saver_secure') == 1 and
         count('screen_saver_secure_lock', s1, s2) == 1 and count('SensLockEvent', s1, s2) >= 1 and
         live.get('unlock_secure_key') is not None and passed('secure_key'),
         probe=case('secure_key'), unlock_retries=live.get('unlock_secure_key'))
    gate('secure_saver_sas', s2 is not None and u2 is not None and status_after(s2, 'screen_saver_secure') == 1 and
         count('screen_saver_stopped_by_sas', s2, u2) >= 1 and count('SensLockEvent', s2, u2) >= 1 and
         count('screen_saver_secure_lock', s2, u2) == 0 and
         live.get('unlock_secure_sas') is not None and passed('secure_sas'),
         probe=case('secure_sas'), unlock_retries=live.get('unlock_secure_sas'))
    gate('locked_station_saver', live.get('ready_locked') and locked0 is not None and
         status_after(locked0, 'screen_saver_secure') == 0 and count('screen_saver_returned_to_locked', locked0, logon0) >= 1 and
         count('screen_saver_dialog_interrupted', u2, locked0) >= 1 and
         live.get('unlock_locked') is not None and passed('locked'),
         probe=case('locked'), unlock_retries=live.get('unlock_locked'))
    gate('logon_desktop_saver', passed('first_session_done') and count('profile_unloaded') >= 1 and logon0 is not None and
         status_after(logon0, 'screen_saver_secure') == 0 and count('screen_saver_image_logon.scr') >= 1 and
         count('screen_saver_returned_to_logon', logon0) >= 1 and
         count('screen_saver_dialog_interrupted', at('profile_unloaded', 0), logon0) >= 1 and
         live.get('logon_dialog_after_logoff') and live.get('logon_dialog_back'),
         first_session=case('first_session_done'))
    gate('relogon', count('session_interactive') >= 2 and passed('restored'), probe=case('restored'))
    failures = [r for r in winlogon if r.get('phase') == 'failed' or
                (r['xp25_winlogon'].startswith('screen_saver') and r['xp25_winlogon'].endswith('_failed'))]
    failed_cases = [r for r in probe if r.get('passed') == 0]
    gate('no_failure', not failures and not failed_cases, failures=failures[:5], failed_cases=failed_cases[:5])
    return gates


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

    def probe_case(label):
        for r in serial_records(serial):
            if r.get('saver_case') == label or r.get('saver_probe') == label:
                return r
        return None

    def stage(label, **detail):
        lab.record({'stage': label, **detail})
        print('STAGE ' + label, json.dumps(detail), flush=True)

    live = {}
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

            def unlocks():
                """Unlocks Winlogon recorded: SensUnlockEvent, or MSGINA's unlock action (8) that precedes
                it. COM1 is exclusive per line (roadmap R-0b), so one of the two can be lost."""
                rows = events()
                return max(sum(1 for r in rows if r['xp25_winlogon'] == 'SensUnlockEvent'),
                           sum(1 for r in rows if r['xp25_winlogon'] == 'gina_unlock_result' and r['status'] == 8))

            def unlock():
                """XP25's password is blank; MSGINA shows its unlock dialog without Ctrl+Alt+Del. Keys
                are typed only while that dialog is on screen, never into an unlocked desktop."""
                before = unlocks()
                for attempt in range(3):
                    time.sleep(4 * slow)
                    if attempt and not shown():
                        return attempt if unlocks() > before else None
                    key('ctrl-a')
                    key('backspace')
                    key('ret')
                    if wait_for(lambda: unlocks() > before, timeout=45 * slow, poll=1.0):
                        return attempt
                    shot('unlock-retry-%d' % (attempt + 1))
                    if shown():
                        key('ret')      # dismiss a refusal shown over the unlock dialog
                return None

            # The live phase only sequences the console input; serial records can lose a line
            # (COM1 is exclusive per line, roadmap R-0b), so the gates are decided afterwards from
            # the merged serial and file records.
            saver_wait = (args.timeout * 6 + 120)
            q.call('cont')
            live['boot_logon_dialog'] = bool(wait_for(shown, timeout=240 * slow, poll=1.0))
            time.sleep(3 * slow)
            shot('00-logon-dialog')
            key('ret')
            grows('session_interactive', 0, 180)
            time.sleep(10 * slow)
            shot('01-desktop')
            stage('logged_on')

            # A: a non-secure session saver, ended by a key.
            grows('screen_saver_started_session', 0, saver_wait)
            time.sleep(8 * slow)
            shot('a1-saver')
            key('shift', 2)
            grows('screen_saver_returned_to_desktop', 0, 60)
            wait_for(lambda: probe_case('nonsecure'), timeout=120 * slow, poll=2.0)
            shot('a2-desktop')
            stage('nonsecure')

            # B: a secure saver, ended by a key: the session locks; the password unlocks it.
            locks = count('SensLockEvent')
            grows('screen_saver_started_session', 1, saver_wait)
            time.sleep(6 * slow)
            shot('b1-saver')
            key('shift', 2)
            grows('screen_saver_secure_lock', 0, 60) or grows('SensLockEvent', locks, 30)
            time.sleep(3 * slow)
            shot('b2-locked')
            live['unlock_secure_key'] = unlock()
            wait_for(lambda: probe_case('secure_key'), timeout=120 * slow, poll=2.0)
            stage('secure_key', unlock_retries=live['unlock_secure_key'])

            # C: a secure saver, ended by Ctrl+Alt+Del.
            grows('screen_saver_started_session', 2, saver_wait)
            time.sleep(6 * slow)
            shot('c1-saver')
            key('ctrl-alt-delete', 2)
            grows('screen_saver_stopped_by_sas', 0, 60)
            time.sleep(3 * slow)
            shot('c2-unlock-dialog')
            live['unlock_secure_sas'] = unlock()
            wait_for(lambda: probe_case('secure_sas'), timeout=120 * slow, poll=2.0)
            stage('secure_sas', unlock_retries=live['unlock_secure_sas'])

            # D: the user's saver on a station locked with Win+L.
            live['ready_locked'] = bool(wait_for(lambda: probe_case('ready_locked'), timeout=120 * slow, poll=2.0))
            key('meta_l-l', 2)
            time.sleep(4 * slow)
            shot('d1-locked')
            grows('screen_saver_started_locked', 0, saver_wait)
            time.sleep(6 * slow)
            shot('d2-saver')
            key('shift', 2)
            grows('screen_saver_returned_to_locked', 0, 60)
            time.sleep(3 * slow)
            shot('d3-locked-again')
            live['unlock_locked'] = unlock()
            wait_for(lambda: probe_case('locked'), timeout=120 * slow, poll=2.0)
            stage('locked', unlock_retries=live['unlock_locked'])

            # E: after the probe logs off, the logon desktop's saver.
            wait_for(lambda: probe_case('first_session_done'), timeout=240 * slow, poll=2.0)
            grows('profile_unloaded', 0, 240)
            live['logon_dialog_after_logoff'] = bool(wait_for(shown, timeout=120 * slow, poll=1.0))
            shot('e1-logon-dialog')
            grows('screen_saver_started_logon_desktop', 0, saver_wait)
            time.sleep(6 * slow)
            shot('e2-saver')
            key('shift', 2)
            grows('screen_saver_returned_to_logon', 0, 60)
            live['logon_dialog_back'] = bool(wait_for(shown, timeout=90 * slow, poll=1.0))
            shot('e3-logon-dialog-back')
            stage('logon_desktop')

            # F: log on again; the probe restores the logon desktop's timeout.
            time.sleep(3 * slow)
            key('ret')
            grows('session_interactive', 1, 180)
            wait_for(lambda: probe_case('restored'), timeout=180 * slow, poll=2.0)
            time.sleep(5 * slow)
            shot('f1-desktop')
            stage('relogon')

            # Turn the guest off normally, so Winlogon's and the probe's file logs reach the disk.
            key('esc', 1)
            key('ctrl-esc', 3)
            key('u', 4)
            shot('g1-turn-off-dialog')
            key('u', 2)
            live['guest_shutdown'] = bool(wait_for(lambda: q.call('query-status')['status'] == 'shutdown',
                                                   timeout=180 * slow, poll=2.0))
            stage('turn_off', guest_shutdown=live['guest_shutdown'])
            try:
                q.call('quit')
            except (EOFError, RuntimeError, OSError):
                pass
    finally:
        try:
            qemu.wait(timeout=20)
        except subprocess.TimeoutExpired:
            qemu.terminate()

    serial_rows = serial_records(serial)
    file_winlogon, file_probe = guest_file_records(out)
    record['guest_file_records'] = {'winlogon_since_boot': len(file_winlogon), 'probe': len(file_probe)}
    serial_winlogon = [r for r in serial_rows if 'xp25_winlogon' in r]
    serial_probe = [r for r in serial_rows if 'saver_case' in r or 'saver_probe' in r]
    merged_winlogon = merge_records(serial_winlogon, file_winlogon)
    merged_probe = serial_probe + [r for r in file_probe if r not in serial_probe]
    record['serial_only_gates'] = evaluate(serial_winlogon, serial_probe, live)
    gates.extend(evaluate(merged_winlogon, merged_probe, live))
    for g in gates:
        lab.record({'gate': g['gate'], 'passed': g['passed']})
        print(('PASS ' if g['passed'] else 'FAIL ') + g['gate'], json.dumps({k: v for k, v in g.items() if k not in ('gate', 'passed')}))
    record['live'] = live
    record['winlogon_saver_records'] = [r for r in merged_winlogon if str(r.get('xp25_winlogon', '')).startswith('screen_saver')]
    record['probe_records'] = merged_probe
    record['passed'] = all(g['passed'] for g in gates)
    (out / 'result.json').write_text(json.dumps(record, indent=1) + '\n')
    print(json.dumps({'name': args.name, 'accel': args.accel, 'cpus': args.cpus,
                      'winlogon_sha256': record['winlogon_sha256'], 'passed': record['passed'],
                      'gates': {g['gate']: g['passed'] for g in gates}}, indent=1))
    return 0 if record['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
