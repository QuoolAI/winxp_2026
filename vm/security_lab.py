#!/usr/bin/env python3
"""XP25 security lab: boot a disposable overlay of a hash-verified engineering
image in the isolated namespace, drive it from its own serial records, and
observe it from outside.

  launch  create the overlay, stage files, start QEMU (vm/security_network.py)
  wait    log on when the XP25 Winlogon asks, wait for a serial marker or a
          guest-requested shutdown, and freeze the run (vm/xp_lab.py finish)
  scan    ask the namespace-side scanner for a port scan of the guest
  fail    freeze a failed run with failure.json (never repaired or deleted)

The backing image is opened read-only and must be frozen (0444). Guest file
changes are limited to the explicit --winlogon/--stage/--startup arguments
and are recorded with hashes in inputs.json. Gates are decided from guest
serial records and QMP events, not from screenshots.

usage:
  security_lab.py launch --name RUN --mode up|mp|tcg [--base IMG --base-sha256 H]
                  [--winlogon EXE] [--stage /guest/path=HOSTFILE ...] [--startup CMD] [--provider]
  security_lab.py wait RUN [--marker TEXT] [--timeout SECONDS] [--no-finish]
  security_lab.py scan RUN LABEL
  security_lab.py fail RUN REASON"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vm'))
import security_fixtures as fixtures
import xp_lab as lab

WORK = ROOT / '.work/security-20261111'
REFERENCE = WORK / 'reference'
RUNS = WORK / 'runs'
PROFILE = '/Documents and Settings/XP25'
STARTUP = PROFILE + '/Start Menu/Programs/Startup/XP25Security.cmd'


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 22), b''):
            h.update(block)
    return h.hexdigest()


def reference(name):
    """A frozen input with the hash recorded when it was copied into the lab."""
    record = json.loads((REFERENCE / 'manifest.json').read_text())['files'][name]
    return REFERENCE / name, record['sha256']


def launch(args):
    if '/' in args.name or args.name in ('.', '..'):
        raise SystemExit('a fresh simple run name is required')
    if args.base:
        if not args.base_sha256:
            raise SystemExit('--base needs --base-sha256')
        base, base_sha = args.base.resolve(), args.base_sha256
    else:
        base, base_sha = reference('XP25-AI-Engineering.qcow2')
    if not base.is_relative_to(ROOT / '.work') or base.stat().st_mode & 0o222:
        raise SystemExit('backing image must be a frozen private .work/ file')
    iso, iso_sha = reference('native-tests.iso')
    files = {}
    for item in args.stage or []:
        target, _, source = item.partition('=')
        source = Path(source).resolve()
        if not target.startswith('/') or '..' in Path(target).parts or not source.is_file() or \
                not source.is_relative_to(ROOT / '.work'):
            raise SystemExit('--stage needs /guest/path=<private .work file>: ' + item)
        files[target] = source
    winlogon = None
    if args.winlogon:
        winlogon = args.winlogon.resolve()
        if not winlogon.is_file() or not winlogon.is_relative_to(ROOT / '.work'):
            raise SystemExit('--winlogon must be a private .work/ file')
    # --kernel base keeps the image's own uniprocessor kernel (two-vCPU runs then get the verified
    # multiprocessor kernel and HAL); --kernel kx01 installs the relinked kernels that also export
    # KeFlushQueuedDpcs (build/prepare_kernel_exports.py). The multiprocessor HAL is the verified one in both cases.
    kernel = None
    if args.kernel == 'kx01':
        kernel = 'kernel-kx01/ntkrnlmp.exe' if args.mode == 'mp' else 'kernel-kx01/ntoskrnl.exe'
    elif args.mode == 'mp':
        kernel = 'mp/ntkrnlmp.exe'
    for target, name in (('/WINDOWS/system32/xp25krnl.exe', kernel),
                         ('/WINDOWS/system32/xp25hal.dll', 'mp/halmacpi.dll' if args.mode == 'mp' else None)):
        if name:
            files[target], expected = reference(name)
            if sha(files[target]) != expected:
                raise SystemExit('kernel/HAL reference changed: ' + name)
    startup = None
    if args.startup:
        startup = args.startup.resolve()
        if not startup.is_file() or not startup.is_relative_to(ROOT / '.work'):
            raise SystemExit('--startup must be a private .work/ file')
    xp25_winlogon = bool(winlogon) or args.xp25_winlogon_installed
    if args.role:
        if args.startup:
            raise SystemExit('--role generates its own Startup fixture')
        args.provider = args.role in fixtures.PROVIDER
        for name in fixtures.PAYLOAD[args.role]:
            if name == 'ai_probe.exe':
                source, expected = reference('ai_probe.exe')
                if sha(source) != expected:
                    raise SystemExit('AI probe reference changed')
            else:
                if not args.build:
                    raise SystemExit('--role ' + args.role + ' needs --build with ' + name)
                source = args.build.resolve() / name
                if not source.is_file() or not source.is_relative_to(ROOT / '.work'):
                    raise SystemExit('missing private build output: ' + str(source))
            files[PROFILE + '/xp25sec-' + name] = source
    if args.ai_build:
        # Rebuilt XP25 AI binaries replace the installed ones in place; paths and registrations do not change.
        collect = json.loads((args.ai_build.resolve().parent / 'collect.json').read_text())
        if collect.get('status') != 'native_binaries_collected':
            raise SystemExit('--ai-build needs an accepted native collection')
        for name, info in collect['binaries'].items():
            source = args.ai_build.resolve() / name
            if not source.is_relative_to(ROOT / '.work') or sha(source) != info['sha256']:
                raise SystemExit('AI binary does not match its collection record: ' + name)
            files['/Program Files/XP25/' + name] = source
    out = RUNS / args.name
    out.mkdir(parents=True, exist_ok=False)
    os.chdir(out)
    actual = {'base': sha(base), 'regression_iso': sha(iso)}
    if actual['base'] != base_sha or actual['regression_iso'] != iso_sha:
        Path('failure.json').write_text(json.dumps({'reason': 'reference hash mismatch', 'actual': actual}, indent=2) + '\n')
        raise SystemExit('reference hash mismatch')
    secret = mock_key = None
    if args.provider:
        secret = secrets.token_hex(32)
        mock_key = 'sk-xp25-isolated-test-' + secrets.token_hex(8)
        Path('gateway-clients.json').write_text(json.dumps({'xp25': {'secret_hex': secret}}) + '\n')
        Path('gateway-secret.cmd').write_bytes(('@set XP25_GW_SECRET=%s\r\n' % secret).encode())
        files[PROFILE + '/xp25sec-gateway-secret.cmd'] = out / 'gateway-secret.cmd'
    if args.role:
        Path('xp25sec-suite.cmd').write_bytes(fixtures.suite(args.role, args.mode, xp25_winlogon, args.provider).encode())
        Path('XP25Security.cmd').write_bytes(fixtures.STARTUP.encode())
        files[PROFILE + '/xp25sec-suite.cmd'] = out / 'xp25sec-suite.cmd'
        files[STARTUP] = out / 'XP25Security.cmd'
    if startup:
        files[STARTUP] = startup
    lab.run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', base, 'disk.qcow2'])
    staged, recovery = {}, None
    with lab.partition(out / 'disk.qcow2', True) as device:
        if winlogon:
            original = lab.run(['ntfscat', device, '/WINDOWS/system32/winlogon.exe'])
            Path('recovery-winlogon.exe').write_bytes(original)
            recovery = {'target': '/WINDOWS/system32/winlogon.exe', 'host_backup': str(out / 'recovery-winlogon.exe'),
                        'original_sha256': hashlib.sha256(original).hexdigest()}
            files['/WINDOWS/system32/winlogon.exe'] = winlogon
        for target, source in sorted(files.items()):
            lab.run(['ntfscp', '-t', device, source, target])
            if lab.run(['ntfscat', device, target]) != source.read_bytes():
                raise RuntimeError('staging mismatch: ' + target)
            staged[target] = {'source': str(source), 'sha256': sha(source)}
    if sha(base) != base_sha:
        raise RuntimeError('reference image changed during staging')
    Path('inputs.json').write_text(json.dumps({
        'mode': args.mode, 'base': str(base), 'base_sha256': base_sha, 'regression_iso': str(iso),
        'regression_iso_sha256': iso_sha, 'staged': staged, 'recovery': recovery,
        'role': args.role, 'kernel': args.kernel, 'ai_build': str(args.ai_build.resolve()) if args.ai_build else None, 'xp25_winlogon': xp25_winlogon, 'provider_checks': bool(args.provider),
        'gateway_secret_scope': 'per-run test secret, isolated namespace only' if args.provider else None}, indent=2) + '\n')
    machine, accel, cpus = (('pc-i440fx-8.2', 'tcg,thread=single', '1') if args.mode == 'tcg' else
                            ('pc-i440fx-8.2,kernel-irqchip=on', 'kvm', '2' if args.mode == 'mp' else '1'))
    command = ['qemu-system-i386', '-name', 'xp25sec-' + args.name, '-machine', machine, '-accel', accel, '-cpu', 'qemu32',
               '-m', '512', '-smp', cpus, '-nodefaults', '-nic', 'none', '-vga', 'std', '-display', 'none', '-monitor', 'none',
               '-qmp', 'unix:qmp.sock,server=on,wait=off', '-serial', 'file:serial.log', '-rtc', 'base=localtime',
               '-drive', 'file=disk.qcow2,format=qcow2,if=ide,index=0',
               '-drive', 'file=' + str(iso) + ',format=raw,readonly=on,if=ide,index=2,media=cdrom',
               '-boot', 'order=c', '-pidfile', 'qemu.pid', '-no-reboot', '-no-shutdown', '-S']
    Path('qemu-command.json').write_text(json.dumps(command, indent=2) + '\n')
    wrapper = ['unshare', '--user', '--map-root-user', '--net', sys.executable, str(ROOT / 'vm/security_network.py'),
               'qemu-command.json', '--parent-netns', os.readlink('/proc/self/ns/net')]
    logged = list(wrapper)
    if args.provider:
        wrapper += ['--gateway-clients', 'gateway-clients.json', '--mock-key', mock_key]
        logged += ['--gateway-clients', 'gateway-clients.json', '--mock-key', '<per-run test key>']
    with Path('namespace.log').open('w') as log:
        process = subprocess.Popen(wrapper, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    lab.record({'argv': logged, 'pid': process.pid})
    for _ in range(300):
        if process.poll() is not None:
            raise RuntimeError(Path('namespace.log').read_text())
        if Path('qmp.sock').exists():
            try:
                with lab.QMP() as q:
                    q.call('cont')
                    q.call('set-action', {'reboot': 'reset'})     # hardening restarts the guest
                break
            except (ConnectionRefusedError, FileNotFoundError, EOFError):
                pass
        time.sleep(0.1)
    else:
        raise TimeoutError('QMP startup')
    lab.checkpoint(stage='security_guest_booting', mode=args.mode, namespace_pid=process.pid,
                   qemu_pid=int(Path('qemu.pid').read_text()), base_sha256=base_sha)
    print(out)


def serial_text():
    path = Path('serial.log')
    return path.read_bytes().decode('utf-8', 'replace') if path.exists() else ''


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


def wait(args):
    out = RUNS / args.run
    os.chdir(out)
    inputs = json.loads(Path('inputs.json').read_text())
    scale = 6 if inputs['mode'] == 'tcg' else 1
    deadline = time.time() + args.timeout * (3 if inputs['mode'] == 'tcg' else 1)
    logons = attempts = shots = 0
    sent_at, sent_results, next_shot = 0.0, -1, time.time() + 120
    ui_tries, next_ui = 0, 0.0
    outcome = None
    # One monitor connection for the whole wait, so no QMP event is missed.
    with lab.QMP() as q:
        while time.time() < deadline and not outcome:
            # Every QMP call also collects the events that arrived before its reply
            # (xp_lab.QMP keeps them); a socket timeout would make the stream unusable.
            time.sleep(2)
            q.call('query-status')
            while q.events and not outcome:
                event = q.events.pop(0)
                if event.get('event') == 'SHUTDOWN':
                    # A guest restart also raises SHUTDOWN (reason guest-reset) before RESET; only a power-off ends the run.
                    if event.get('data') == {'guest': True, 'reason': 'guest-shutdown'}:
                        Path('guest-shutdown-event.json').write_text(json.dumps(event, indent=2) + '\n')
                        outcome = 'guest_shutdown'
                    elif event.get('data', {}).get('reason') != 'guest-reset':
                        outcome = 'unexpected_shutdown: ' + json.dumps(event.get('data'))
                elif event.get('event') == 'GUEST_PANICKED':
                    outcome = 'guest_panicked'
            if outcome:
                break
            text = serial_text()
            if args.marker and args.marker in text:
                outcome = 'marker'
                break
            if args.ui_shutdown_after and args.ui_shutdown_after in text and time.time() > next_ui:
                for name, pause in (('esc', 1), ('ctrl-esc', 2), ('u', 3), ('u', 1)):
                    lab.key(q, name)
                    time.sleep(pause * scale)
                ui_tries += 1
                next_ui = time.time() + 90 * scale
                lab.record({'ui_shutdown_keys_sent': ui_tries})
                if ui_tries > 6:
                    outcome = 'ui_shutdown_not_accepted'
            if inputs.get('xp25_winlogon'):
                events = winlogon_events(text)
                ready, interactive = events.count('core_ready'), events.count('session_interactive')
                results = events.count('gina_logged_out_result')
                if interactive >= ready and ready > logons:
                    logons, attempts, sent_at, sent_results = ready, 0, 0.0, -1
                    lab.record({'session_interactive_boot': ready})
                # One logon per boot: core_ready, then the MSGINA dialog. Keys are repeated only
                # while MSGINA has not reported a result for the previous attempt (lost keys).
                elif ready > logons and (sent_results < 0 or (results == sent_results and time.time() - sent_at > 40 * scale)):
                    if sent_results < 0:
                        time.sleep(8 * scale)
                    for name in ('ctrl-a', 'backspace', 'ret'):
                        lab.key(q, name)
                        time.sleep(0.3)
                    attempts += 1
                    sent_at, sent_results = time.time(), results
                    lab.record({'logon_keys_sent': attempts, 'boot': ready})
                    if attempts > 8:
                        outcome = 'logon_keys_not_accepted'
            if shots < 60 and time.time() > next_shot:
                try:
                    lab.screen(q, 'progress-%03d' % shots)
                except Exception as error:               # evidence only; never a gate
                    lab.record({'screenshot_failed': shots, 'error': str(error)})
                shots += 1
                next_shot = time.time() + 120
        outcome = outcome or 'timeout'
        if outcome not in ('guest_shutdown', 'marker'):
            try:
                lab.screen(q, 'wait-' + outcome.split(':')[0])
            except Exception:
                pass
    lab.checkpoint(stage='wait_' + outcome.split(':')[0], logons=logons)
    print(outcome)
    if outcome == 'guest_shutdown' and not args.no_finish:
        subprocess.run([sys.executable, str(ROOT / 'vm/xp_lab.py'), str(out), 'finish'], check=True)
        print('frozen', json.loads(Path('checkpoint.json').read_text()).get('disk_sha256'))
    if outcome not in ('guest_shutdown', 'marker'):
        raise SystemExit(1)


def scan(args):
    out = RUNS / args.run
    os.chdir(out)
    request, result = Path('scan-request-%s.json' % args.label), Path('scan-result-%s.json' % args.label)
    if request.exists() or result.exists():
        raise SystemExit('scan label already used')
    request.write_text(json.dumps({'requested': time.time()}) + '\n')
    for _ in range(600):
        if result.exists():
            data = json.loads(result.read_text())
            # The guest announces a window in which it only waits; the scan counts when it finished inside it.
            text = serial_text()
            Path('scan-check-%s.json' % args.label).write_text(json.dumps({
                'window_opened': 'XP25_SEC_SCAN_WINDOW_OPEN' in text, 'window_closed_when_scan_finished': 'XP25_SEC_SCAN_WINDOW_CLOSED' in text,
                'inside_window': 'XP25_SEC_SCAN_WINDOW_OPEN' in text and 'XP25_SEC_SCAN_WINDOW_CLOSED' not in text,
                'guest_lease': Path('dhcp.leases').read_text().strip() if Path('dhcp.leases').exists() else None}, indent=1) + '\n')
            print(json.dumps({k: data.get(k) for k in ('label', 'icmp_echo_reply', 'tcp_open', 'tcp_closed_count',
                                                       'tcp_filtered_count', 'udp', 'error')}, indent=1))
            return
        time.sleep(0.5)
    raise SystemExit('scanner did not answer')


def fail(args):
    out = RUNS / args.run
    os.chdir(out)
    record = {'reason': args.reason, 'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'preserved': True}
    if Path('qmp.sock').exists():
        try:
            with lab.QMP() as q:
                record['qemu_status'] = q.call('query-status')
                lab.screen(q, 'failure')
                q.call('quit')
        except Exception as error:
            record['qmp_error'] = str(error)
    time.sleep(1)
    if Path('disk.qcow2').exists():
        Path('disk.qcow2').chmod(0o444)
    Path('failure.json').write_text(json.dumps(record, indent=2) + '\n')
    lab.checkpoint(stage='failed_frozen', reason=args.reason)
    print(out / 'failure.json')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('launch')
    p.add_argument('--name', required=True)
    p.add_argument('--mode', choices=('up', 'mp', 'tcg'), required=True)
    p.add_argument('--base', type=Path)
    p.add_argument('--base-sha256')
    p.add_argument('--winlogon', type=Path, help='install this natively built XP25 Winlogon; the original is kept as recovery-winlogon.exe')
    p.add_argument('--xp25-winlogon-installed', action='store_true', help='the base image already carries the XP25 Winlogon')
    p.add_argument('--kernel', choices=('base', 'kx01'), default='base')
    p.add_argument('--ai-build', type=Path, help='build/ directory of a native XP25 AI collection to install over the image\'s AI binaries')
    p.add_argument('--role', choices=fixtures.ROLES, help='generate and stage the Startup fixture of this role (vm/security_fixtures.py)')
    p.add_argument('--build', type=Path, help='directory with XP25Sec.exe, XP25Audit.exe and security_probe.exe')
    p.add_argument('--stage', action='append')
    p.add_argument('--startup', type=Path, help='self-removing Startup fixture for the XP25 account')
    p.add_argument('--provider', action='store_true', help='run the XP25 gateway and the OpenAI test double in the namespace')
    p.set_defaults(handler=launch)
    p = sub.add_parser('wait')
    p.add_argument('run')
    p.add_argument('--marker')
    p.add_argument('--timeout', type=int, default=3600)
    p.add_argument('--no-finish', action='store_true')
    p.add_argument('--ui-shutdown-after', metavar='TEXT',
                   help='once this serial marker appears, shut down through Start > Turn Off Computer (the image-install role leaves no tool to do it)')
    p.set_defaults(handler=wait)
    p = sub.add_parser('scan')
    p.add_argument('run')
    p.add_argument('label')
    p.set_defaults(handler=scan)
    p = sub.add_parser('fail')
    p.add_argument('run')
    p.add_argument('reason')
    p.set_defaults(handler=fail)
    args = parser.parse_args()
    args.handler(args)


if __name__ == '__main__':
    main()
