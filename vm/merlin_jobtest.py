#!/usr/bin/env python3
"""Test one XP25 image for the MerlinAI Builder: boot a disposable, NIC-free
overlay, log on through the XP25 Winlogon, run fixed check commands (from the
builder's component map, never from a report), check the desktop and
MerlinAI, then turn the guest off from the Start menu and freeze the overlay.

Gates come from COM1 records and QMP events:
  boot_to_logon_prompt    Winlogon core_ready
  logon_completed         Winlogon session_interactive
  desktop_started         explorer.exe running in the session (tasklist)
  checks_ran              every check command returned
  merlin_status_ok        MerlinAI.exe /status listed its queue (when installed)
  turned_off_normally     QMP SHUTDOWN guest=true reason=guest-shutdown
results.json also lists every XP25_* line the guest wrote (serial_markers).

usage: merlin_jobtest.py --name RUN --mode up|mp|tcg --image FROZEN.qcow2 --checks '["cmd", ...]' --runs DIR
                         [--mp-kernel FILE --mp-hal FILE] [--timeout 2400]"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vm'))
import xp_lab as lab

PROFILE = '/Documents and Settings/XP25'
STARTUP = PROFILE + '/Start Menu/Programs/Startup/XP25JobTest.cmd'
MERLIN = r'C:\Program Files\XP25\MerlinAI\MerlinAI.exe'


def suite(checks):
    lines = ['@echo off', 'echo XP25_JOBTEST_STARTED > COM1', 'ping -n 6 127.0.0.1 >nul']
    for i, command in enumerate(checks):
        if any(c in command for c in '&|<>^%\r\n') or len(command) > 400:
            raise SystemExit('check commands must be plain command lines')
        lines += [command, 'echo XP25_JOBTEST_CHECK_%d_EXIT=%%ERRORLEVEL%% > COM1' % i]
    lines += ['tasklist /fi "imagename eq explorer.exe" | find /i "explorer.exe" >nul && echo XP25_JOBTEST_EXPLORER=1 > COM1 || echo XP25_JOBTEST_EXPLORER=0 > COM1',
              'if exist "%s" "%s" /status' % (MERLIN, MERLIN),
              'if not exist "%s" echo XP25_JOBTEST_MERLIN=absent > COM1' % MERLIN,
              'del "%USERPROFILE%\\Start Menu\\Programs\\Startup\\XP25JobTest.cmd"',
              'echo XP25_JOBTEST_DONE > COM1']
    return '\r\n'.join(lines) + '\r\n'


def winlogon_events(text):
    events = []
    for line in text.splitlines():
        at = line.find('{"xp25_winlogon"')
        if at >= 0:
            try:
                events.append(json.loads(line[at:])['xp25_winlogon'])
            except (ValueError, KeyError):
                pass
    return events


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--name', required=True)
    parser.add_argument('--mode', choices=('up', 'mp', 'tcg'), required=True)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--checks', default='[]')
    parser.add_argument('--runs', type=Path, required=True)
    parser.add_argument('--mp-kernel', type=Path)
    parser.add_argument('--mp-hal', type=Path)
    parser.add_argument('--timeout', type=int, default=2400)
    args = parser.parse_args()
    if '/' in args.name or args.name in ('.', '..'):
        parser.error('a fresh simple run name is required')
    image = args.image.resolve()
    if image.stat().st_mode & 0o222:
        parser.error('the image under test must be frozen (read-only)')
    checks = json.loads(args.checks)
    if not isinstance(checks, list) or not all(isinstance(c, str) for c in checks):
        parser.error('--checks is a JSON list of command lines')
    out = args.runs.resolve() / args.name
    out.mkdir(parents=True, exist_ok=False)
    os.chdir(out)
    image_sha = hashlib.sha256(image.read_bytes()).hexdigest() if image.stat().st_size < (1 << 31) else None
    Path('jobtest-suite.cmd').write_bytes(suite(checks).encode())
    Path('XP25JobTest.cmd').write_bytes(b'@call C:\\xp25\\jobtest-suite.cmd\r\n')
    fmt = json.loads(subprocess.check_output(['qemu-img', 'info', '-U', '--output=json', str(image)]))['format']
    lab.run(['qemu-img', 'create', '-f', 'qcow2', '-F', fmt, '-b', str(image), 'disk.qcow2'])
    files = {'/xp25/jobtest-suite.cmd': out / 'jobtest-suite.cmd', STARTUP: out / 'XP25JobTest.cmd'}
    if args.mode == 'mp':
        if not args.mp_kernel or not args.mp_hal:
            parser.error('two vCPUs need --mp-kernel and --mp-hal (the images ship the uniprocessor kernel)')
        files['/WINDOWS/system32/xp25krnl.exe'] = args.mp_kernel.resolve()
        files['/WINDOWS/system32/xp25hal.dll'] = args.mp_hal.resolve()
    staged = {}
    with lab.partition(out / 'disk.qcow2', True) as device:
        for target, source in sorted(files.items()):
            lab.run(['ntfscp', '-t', device, source, target])
            staged[target] = hashlib.sha256(Path(source).read_bytes()).hexdigest()
    Path('inputs.json').write_text(json.dumps({'mode': args.mode, 'image': str(image), 'image_sha256': image_sha, 'checks': checks,
                                               'staged': staged}, indent=1) + '\n')
    machine, accel, cpus = (('pc-i440fx-8.2', 'tcg,thread=single', '1') if args.mode == 'tcg' else
                            ('pc-i440fx-8.2,kernel-irqchip=on', 'kvm', '2' if args.mode == 'mp' else '1'))
    command = ['qemu-system-i386', '-name', 'merlinjob-' + args.name, '-machine', machine, '-accel', accel, '-cpu', 'qemu32',
               '-m', '512', '-smp', cpus, '-nodefaults', '-nic', 'none', '-vga', 'std', '-display', 'none', '-monitor', 'none',
               '-qmp', 'unix:qmp.sock,server=on,wait=off', '-serial', 'file:serial.log', '-rtc', 'base=localtime',
               '-drive', 'file=disk.qcow2,format=qcow2,if=ide,index=0', '-boot', 'order=c', '-pidfile', 'qemu.pid',
               '-no-reboot', '-no-shutdown']
    Path('qemu-command.json').write_text(json.dumps(command, indent=1) + '\n')
    with Path('qemu.log').open('w') as log:
        qemu = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    for _ in range(200):
        if Path('qmp.sock').exists():
            break
        time.sleep(0.1)
    scale = 4 if args.mode == 'tcg' else 1
    deadline = time.time() + args.timeout * (3 if args.mode == 'tcg' else 1)
    outcome, logons, sent_at, sent_results, next_off, off_tries = None, 0, 0.0, -1, 0.0, 0
    with lab.QMP() as q:
        while time.time() < deadline and not outcome:
            time.sleep(2)
            q.call('query-status')
            while q.events and not outcome:
                event = q.events.pop(0)
                if event.get('event') == 'SHUTDOWN':
                    outcome = 'guest_shutdown' if event.get('data') == {'guest': True, 'reason': 'guest-shutdown'} else \
                        'unexpected_shutdown: ' + json.dumps(event.get('data'))
                elif event.get('event') in ('GUEST_PANICKED', 'RESET'):
                    outcome = event['event'].lower()
            if outcome:
                break
            text = Path('serial.log').read_bytes().decode('latin-1') if Path('serial.log').exists() else ''
            events = winlogon_events(text)
            ready, interactive = events.count('core_ready'), events.count('session_interactive')
            results = events.count('gina_logged_out_result')
            if interactive >= ready and ready > logons:
                logons = ready
            elif ready > logons and (sent_results < 0 or (results == sent_results and time.time() - sent_at > 40 * scale)):
                if sent_results < 0:
                    time.sleep(8 * scale)
                for name in ('ctrl-a', 'backspace', 'ret'):
                    lab.key(q, name)
                    time.sleep(0.3)
                sent_at, sent_results = time.time(), results
            if 'XP25_JOBTEST_DONE' in text and time.time() > next_off:
                time.sleep(3 * scale)
                for name, pause in (('esc', 1), ('ctrl-esc', 2), ('u', 3), ('u', 1)):
                    lab.key(q, name)
                    time.sleep(pause * scale)
                off_tries += 1
                next_off = time.time() + 90 * scale
                if off_tries > 6:
                    outcome = 'turn_off_not_accepted'
        outcome = outcome or 'timeout'
        try:
            lab.screen(q, 'end-' + outcome.split(':')[0])
        except Exception:
            pass
        if outcome != 'guest_shutdown':
            try:
                q.call('quit')
            except Exception:
                pass
        else:
            q.call('quit')
    qemu.wait(timeout=60)
    Path('disk.qcow2').chmod(0o444)
    text = Path('serial.log').read_bytes().decode('latin-1') if Path('serial.log').exists() else ''
    events = winlogon_events(text)
    markers = [m.strip() for m in re.findall(r'XP25_[A-Z0-9_]+(?:=| )[^\r\n]*', text)]
    gates = {
        'boot_to_logon_prompt': 'core_ready' in events,
        'logon_completed': 'session_interactive' in events,
        'desktop_started': 'XP25_JOBTEST_EXPLORER=1' in text,
        'checks_ran': all('XP25_JOBTEST_CHECK_%d_EXIT=' % i in text for i in range(len(checks))),
        'merlin_status_ok': 'XP25_MERLIN_STATUS_QUEUE=0' in text or 'XP25_JOBTEST_MERLIN=absent' in text,
        'turned_off_normally': outcome == 'guest_shutdown',
    }
    result = {'run': args.name, 'mode': args.mode, 'image': str(image), 'outcome': outcome, 'gates': gates,
              'passed': sum(gates.values()), 'total': len(gates), 'serial_markers': markers}
    Path('results.json').write_text(json.dumps(result, indent=1) + '\n')
    if outcome != 'guest_shutdown':
        Path('failure.json').write_text(json.dumps({'reason': outcome, 'preserved': True}, indent=1) + '\n')
    print(json.dumps({k: result[k] for k in ('outcome', 'passed', 'total')}))
    return 0 if result['passed'] == result['total'] else 1


if __name__ == '__main__':
    sys.exit(main())
