#!/usr/bin/env python3
"""MerlinAI lab (Milestone 9A): boot a disposable overlay of a hash-verified
XP25 image in the isolated namespace with the real MerlinAI Builder API
(vm/merlin_network.py), install MerlinAI with its own installer, and drive
the error-reporting and Control Panel workflow.

  launch   create the overlay, register a lab installation with the builder,
           stage MerlinAI and the Startup suite, start QEMU
  wait     log on through the XP25 Winlogon, answer the scenario's dialogs by
           keyboard (screenshots are evidence only), turn the guest off from
           the Start menu, freeze the run
  results  decide the gates from COM1 records, the builder's own data and the
           frozen disk (queue files and registry hives read offline)

The backing image is opened read-only and must be frozen. Every staged file is
recorded with its hash in inputs.json. Gates never come from screenshots.

usage:
  merlin_lab.py launch --name RUN --mode up|mp|tcg --image m9|<manifest dir> --build DIR [--scenario 9a]
  merlin_lab.py wait RUN [--timeout SECONDS]
  merlin_lab.py results RUN
  merlin_lab.py fail RUN REASON"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vm'))
sys.path.insert(0, str(ROOT / 'components/merlin/builder'))
import security_paths
import xp_lab as lab

WORK = Path(os.environ.get('XP25_MERLIN_WORK', ROOT / '.work/merlin-20261121')).resolve()
RUNS = WORK / 'runs'
PROFILE = '/Documents and Settings/XP25'
STARTUP = PROFILE + '/Start Menu/Programs/Startup/XP25Merlin.cmd'
BINARIES = ('MerlinClient.dll', 'MerlinCrash.exe', 'MerlinAI.exe', 'MerlinAI.cpl', 'MerlinSvc.exe', 'MerlinTest.exe', 'merlin_probe.exe')
INSTALLATION = 'lab-merlin'

SUITE = r'''@echo off
rem MerlinAI 9A lab suite (vm/merlin_lab.py). Runs once at the XP25 logon.
set P=C:\Program Files\XP25\MerlinAI
set Q=%ALLUSERSPROFILE%\Application Data\XP25\MerlinAI\Queue
set K=HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug
call :mark XP25_MERLIN_SUITE_STARTED
mkdir "%P%" 2>nul
for %%F in (MerlinClient.dll MerlinCrash.exe MerlinAI.exe MerlinAI.cpl MerlinSvc.exe MerlinTest.exe) do copy /y C:\xp25\merlin-%%F "%P%\%%F" >nul
copy /y C:\xp25\merlin-merlintest.ini C:\xp25\merlintest.ini >nul
rem What the shell's Control Panel shows before MerlinAI is installed.
C:\xp25\merlin-merlin_probe.exe cpl
"%P%\MerlinAI.exe" /install
call :check AEDEBUG "%K%" Debugger MerlinCrash.exe
call :check AEDEBUG_AUTO "%K%" Auto 1
call :check MS_DOREPORT "HKLM\SOFTWARE\Microsoft\PCHealth\ErrorReporting" DoReport 0x0
call :check MS_SHOWUI "HKLM\SOFTWARE\Microsoft\PCHealth\ErrorReporting" ShowUI 0x0
call :check CPL "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" MerlinAI MerlinAI.cpl
call :check HIDE_WSCUI "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\don't load" wscui.cpl no
call :check HIDE_WUAUCPL "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\don't load" wuaucpl.cpl no
call :check SC_NOTIFY "HKLM\SOFTWARE\Microsoft\Security Center" FirewallDisableNotify 0x1
call :check AU_POLICY "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" NoAutoUpdate 0x1
call :check SAVED "HKLM\SOFTWARE\XP25\MerlinAI\Saved" AeDebug.Debugger drwtsn32
rem Security Center link removed by the per-user policy; MerlinAI in Performance and Maintenance.
rem CALL expands percent signs a second time: %%%%SystemRoot%%%% reaches reg.exe as %SystemRoot%.
set X=HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
set C=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\Extended Properties\{305CA226-D286-468e-B848-2B2E8E697B74} 2
call :check CPL_CATEGORY "%C%" "%%%%SystemRoot%%%%\system32\MerlinAI.cpl" 0x5
call :check USER_DISALLOWCPL "%X%" DisallowCPL 0x1
call :check USER_HIDE_WSCUI "%X%\DisallowCpl" "XP25 MerlinAI: Security Center" wscui.cpl
call :check USER_HIDE_WUAUCPL "%X%\DisallowCpl" "XP25 MerlinAI: Automatic Updates" wuaucpl.cpl
reg load HKU\XP25MerlinCheck "%ALLUSERSPROFILE%\..\Default User\NTUSER.DAT" >nul
call :check DEFAULT_USER_HIDE_WSCUI "HKU\XP25MerlinCheck\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl" "XP25 MerlinAI: Security Center" wscui.cpl
reg unload HKU\XP25MerlinCheck >nul
sc query SharedAccess | findstr /i RUNNING >nul && call :mark XP25_MERLIN_FIREWALL_RUNNING=1 || call :mark XP25_MERLIN_FIREWALL_RUNNING=0
"%P%\MerlinAI.exe" /configure http://10.25.0.1:8740 http://10.25.0.1:8746 {installation} {builder_key} {deploy_key}
"%P%\MerlinTest.exe" /check
call :mark XP25_MERLINTEST_CHECK_EXIT=%ERRORLEVEL%
rem A crash in a LocalSystem process: no dialog may appear, the report is queued silently.
sc create MerlinCrashSvc binPath= "%P%\MerlinTest.exe" type= own start= demand >nul
sc start MerlinCrashSvc >nul
set N=0
:svcwait
ping -n 3 127.0.0.1 >nul
findstr /m /c:"owner=SYSTEM" "%Q%\C-*.txt" >nul 2>&1 && goto svcdone
set /a N+=1
if %N% LSS 40 goto svcwait
:svcdone
findstr /m /c:"owner=SYSTEM" "%Q%\C-*.txt" >nul 2>&1 && call :mark XP25_MERLIN_SERVICE_CRASH_QUEUED=1 || call :mark XP25_MERLIN_SERVICE_CRASH_QUEUED=0
sc delete MerlinCrashSvc >nul
rem A controlled service failure for local discovery (Service Control Manager event 7000).
sc create MerlinLabSvc binPath= "C:\xp25\no-such-service.exe" type= own start= demand DisplayName= "MerlinAI Lab Service" >nul
sc start MerlinLabSvc >nul 2>&1
call :mark XP25_MERLIN_LAB_SERVICE_START=%ERRORLEVEL%
sc delete MerlinLabSvc >nul
rem The interactive crash: the harness answers the MerlinAI dialog (Transfer + Send to MerlinAI).
call :mark XP25_MERLIN_STEP=crash_dialog
start "" "%P%\MerlinTest.exe"
set N=0
:crashwait
ping -n 3 127.0.0.1 >nul
findstr /m /c:"submitted=1" "%Q%\C-*.txt" >nul 2>&1 && goto crashdone
set /a N+=1
if %N% LSS 90 goto crashwait
:crashdone
findstr /m /c:"submitted=1" "%Q%\C-*.txt" >nul 2>&1 && call :mark XP25_MERLIN_CRASH_QUEUED=1 || call :mark XP25_MERLIN_CRASH_QUEUED=0
ping -n 8 127.0.0.1 >nul
"%P%\MerlinAI.exe" /collect
"%P%\MerlinAI.exe" /collect
"%P%\MerlinAI.exe" /status
rem Uninstall restores the saved settings; then install again for the Control Panel steps.
"%P%\MerlinAI.exe" /uninstall
call :check RESTORED_AEDEBUG "%K%" Debugger drwtsn32
call :check RESTORED_DOREPORT "HKLM\SOFTWARE\Microsoft\PCHealth\ErrorReporting" DoReport 0x1
call :absent RESTORED_USER_DISALLOWCPL "%X%" DisallowCPL
call :absent RESTORED_USER_HIDE_WSCUI "%X%\DisallowCpl" "XP25 MerlinAI: Security Center"
call :absent RESTORED_CPL_CATEGORY "%C%" "%%%%SystemRoot%%%%\system32\MerlinAI.cpl"
"%P%\MerlinAI.exe" /install
C:\xp25\merlin-merlin_probe.exe cpl
{control_panel}
call :mark XP25_MERLIN_STEP=ui
start "" "%P%\MerlinAI.exe"
del "%USERPROFILE%\Start Menu\Programs\Startup\XP25Merlin.cmd"
call :mark XP25_MERLIN_SUITE_DONE
goto :eof

rem A space before >> keeps "X=1" from becoming "X=" plus a handle-1 redirection.
:mark
echo %* > COM1
echo %* >> C:\xp25\merlin-suite.log
goto :eof

:check
reg query %2 /v %3 2>nul | findstr /i /c:"%4" >nul && call :mark XP25_MERLIN_REG_%1=ok || call :mark XP25_MERLIN_REG_%1=bad
goto :eof

:absent
reg query %2 /v %3 >nul 2>&1 && call :mark XP25_MERLIN_REG_%1=bad || call :mark XP25_MERLIN_REG_%1=ok
goto :eof
'''

# Image preparation: install like an administrator would, preset the endpoints of the XP25 host
# services (no credentials: those are per installation), remove the payload, turn off.
INSTALL_SUITE = r'''@echo off
set P=C:\Program Files\XP25\MerlinAI
call :mark XP25_MERLIN_SUITE_STARTED
mkdir "%P%" 2>nul
for %%F in (MerlinClient.dll MerlinCrash.exe MerlinAI.exe MerlinAI.cpl MerlinSvc.exe MerlinTest.exe) do copy /y C:\xp25\merlin-%%F "%P%\%%F" >nul
copy /y C:\xp25\merlin-merlintest.ini C:\xp25\merlintest.ini >nul
"%P%\MerlinAI.exe" /install
reg add "HKLM\SOFTWARE\XP25\MerlinAI" /v Builder /t REG_SZ /d http://10.25.0.1:8740 /f >nul
reg add "HKLM\SOFTWARE\XP25\MerlinAI" /v Deploy /t REG_SZ /d http://10.25.0.1:8746 /f >nul
call :mark XP25_MERLIN_ENDPOINTS=%ERRORLEVEL%
for %%F in (MerlinClient.dll MerlinCrash.exe MerlinAI.exe MerlinAI.cpl MerlinSvc.exe MerlinTest.exe merlin_probe.exe merlintest.ini) do del /q C:\xp25\merlin-%%F
del "%USERPROFILE%\Start Menu\Programs\Startup\XP25Merlin.cmd"
call :mark XP25_MERLIN_SUITE_DONE
del C:\xp25\merlin-suite.cmd & goto :eof

:mark
echo %* > COM1
echo %* >> C:\xp25\merlin-install.log
goto :eof
'''

STARTUP_CMD = '@call C:\\xp25\\merlin-suite.cmd\r\n'


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 22), b''):
            h.update(block)
    return h.hexdigest()


def image(name):
    if name in security_paths.IMAGES:
        return security_paths.image(name)
    manifest = json.loads((Path(name) / 'manifest.json').read_text())
    return Path(manifest['image']), manifest['image_sha256']


def launch(args):
    if '/' in args.name or args.name in ('.', '..'):
        raise SystemExit('a fresh simple run name is required')
    base, base_sha = image(args.image)
    base = base.resolve()
    if not base.is_relative_to(ROOT / '.work') or base.stat().st_mode & 0o222:
        raise SystemExit('backing image must be a frozen private .work/ file')
    build = args.build.resolve()
    for name in BINARIES:
        if not (build / name).is_file():
            raise SystemExit('missing ' + name + ' in ' + str(build))
    out = RUNS / args.name
    out.mkdir(parents=True, exist_ok=False)
    os.chdir(out)
    if sha(base) != base_sha:
        Path('failure.json').write_text(json.dumps({'reason': 'reference hash mismatch'}) + '\n')
        raise SystemExit('reference hash mismatch')
    from merlin_builder.store import Store
    from merlin_builder.server import DEFAULT_LIMITS
    data = out / 'builder-data'
    store = Store(data, DEFAULT_LIMITS)
    builder_key = store.register_installation(INSTALLATION, 'lab')
    deploy_key = secrets.token_hex(32)
    Path('builder-config.json').write_text(json.dumps({'data': str(data), 'log': str(out / 'builder-api.jsonl')}, indent=1) + '\n')
    Path('deploy-config.json').write_text(json.dumps({'installation': INSTALLATION, 'deploy_key': deploy_key,
                                                      'log': str(out / 'deploy-requests.jsonl')}, indent=1) + '\n')
    template = INSTALL_SUITE if args.scenario == 'install' else SUITE
    # The Control Panel window is evidence only (the probe gates registration); under TCG it opens too late
    # for keyboard steps, so TCG runs skip it.
    template = template.replace('{control_panel}', 'call :mark XP25_MERLIN_STEP=cpl_window_skipped_tcg' if args.mode == 'tcg' else
                                'call :mark XP25_MERLIN_STEP=control_panel\nstart "" control.exe\nping -n 25 127.0.0.1 >nul')
    Path('merlin-suite.cmd').write_bytes(template.replace('{installation}', INSTALLATION).replace('{builder_key}', builder_key)
                                         .replace('{deploy_key}', deploy_key).replace('\n', '\r\n').encode())
    Path('XP25Merlin.cmd').write_bytes(STARTUP_CMD.encode())
    Path('image-revision.txt').write_bytes(((args.revision or '%s %s' % (Path(args.image).name, base_sha[:16])) + '\r\n').encode())
    # ntfscp cannot create directories: files go flat into C:\xp25, which every XP25 image has.
    files = {'/xp25/merlin-' + n: build / n for n in BINARIES}
    files['/xp25/merlin-merlintest.ini'] = ROOT / 'components/merlin/testapp/merlintest.ini'
    files['/xp25/merlin-suite.cmd'] = out / 'merlin-suite.cmd'
    files['/xp25/image-revision.txt'] = out / 'image-revision.txt'
    files[STARTUP] = out / 'XP25Merlin.cmd'
    lab.run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', base, 'disk.qcow2'])
    staged = {}
    with lab.partition(out / 'disk.qcow2', True) as device:
        for target, source in sorted(files.items()):
            lab.run(['ntfscp', '-t', device, source, target])
            if lab.run(['ntfscat', device, target]) != Path(source).read_bytes():
                raise RuntimeError('staging mismatch: ' + target)
            staged[target] = {'source': str(source), 'sha256': sha(source)}
    if sha(base) != base_sha:
        raise RuntimeError('reference image changed during staging')
    kernel = None
    if args.mode == 'mp':
        # The packaged images ship the uniprocessor kernel; two vCPUs need the verified MP kernel and HAL.
        manifest = json.loads((security_paths.REFERENCE / 'manifest.json').read_text())['files']
        mp_kernel, hal = security_paths.REFERENCE / 'kernel-kx01/ntkrnlmp.exe', security_paths.REFERENCE / 'mp/halmacpi.dll'
        for f, name in ((mp_kernel, 'kernel-kx01/ntkrnlmp.exe'), (hal, 'mp/halmacpi.dll')):
            if sha(f) != manifest[name]['sha256']:
                raise SystemExit('kernel/HAL reference changed: ' + name)
        with lab.partition(out / 'disk.qcow2', True) as device:
            for target, source in (('/WINDOWS/system32/xp25krnl.exe', mp_kernel), ('/WINDOWS/system32/xp25hal.dll', hal)):
                lab.run(['ntfscp', '-t', device, source, target])
                staged[target] = {'source': str(source), 'sha256': sha(source)}
        kernel = 'kernel-kx01/ntkrnlmp.exe + mp/halmacpi.dll'
    Path('inputs.json').write_text(json.dumps({'mode': args.mode, 'image': args.image, 'base': str(base), 'base_sha256': base_sha,
                                               'build': str(build), 'scenario': args.scenario, 'installation': INSTALLATION,
                                               'kernel': kernel, 'staged': staged,
                                               'secret_scope': 'per-run lab keys; the builder runs inside the isolated namespace'},
                                              indent=2) + '\n')
    machine, accel, cpus = (('pc-i440fx-8.2', 'tcg,thread=single', '1') if args.mode == 'tcg' else
                            ('pc-i440fx-8.2,kernel-irqchip=on', 'kvm', '2' if args.mode == 'mp' else '1'))
    command = ['qemu-system-i386', '-name', 'xp25merlin-' + args.name, '-machine', machine, '-accel', accel, '-cpu', 'qemu32',
               '-m', '512', '-smp', cpus, '-nodefaults', '-nic', 'none', '-vga', 'std', '-display', 'none', '-monitor', 'none',
               '-qmp', 'unix:qmp.sock,server=on,wait=off', '-serial', 'file:serial.log', '-rtc', 'base=localtime',
               '-drive', 'file=disk.qcow2,format=qcow2,if=ide,index=0', '-boot', 'order=c', '-pidfile', 'qemu.pid',
               '-no-reboot', '-no-shutdown', '-S']
    Path('qemu-command.json').write_text(json.dumps(command, indent=2) + '\n')
    wrapper = ['unshare', '--user', '--map-root-user', '--net', sys.executable, str(ROOT / 'vm/merlin_network.py'),
               'qemu-command.json', '--parent-netns', os.readlink('/proc/self/ns/net'),
               '--builder-config', 'builder-config.json', '--deploy-config', 'deploy-config.json']
    with Path('namespace.log').open('w') as log:
        process = subprocess.Popen(wrapper, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    lab.record({'argv': wrapper, 'pid': process.pid})
    for _ in range(300):
        if process.poll() is not None:
            raise RuntimeError(Path('namespace.log').read_text())
        if Path('qmp.sock').exists():
            try:
                with lab.QMP() as q:
                    q.call('cont')
                    q.call('set-action', {'reboot': 'reset'})
                break
            except (ConnectionRefusedError, FileNotFoundError, EOFError):
                pass
        time.sleep(0.1)
    else:
        raise TimeoutError('QMP startup')
    lab.checkpoint(stage='merlin_guest_booting', mode=args.mode, base_sha256=base_sha)
    print(out)


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


class Scenario:
    """Keyboard steps keyed by COM1 markers. Each step runs once, in order."""

    def __init__(self, q, scale):
        self.q, self.scale = q, scale
        self.done = set()

    def shot(self, name):
        try:
            lab.screen(self.q, name)
        except Exception as error:                     # evidence only
            lab.record({'screenshot_failed': name, 'error': str(error)})

    def keys(self, *names, pause=0.6):
        for name in names:
            lab.key(self.q, name)
            time.sleep(pause * self.scale)

    def step(self, name, text, marker):
        if name in self.done or marker not in text:
            return False
        self.done.add(name)
        lab.record({'scenario_step': name})
        return True

    def run(self, text):
        s = self.scale
        after = text.split('XP25_MERLIN_STEP=crash_dialog', 1)[1] if 'XP25_MERLIN_STEP=crash_dialog' in text else ''
        if self.step('crash_dialog', after, 'interactive=1'):
            time.sleep(6 * s)
            self.shot('01-crash-dialog')
            self.keys('alt-v')                         # View report details (the preview before transmission)
            time.sleep(3 * s)
            self.shot('02-crash-details')
            self.keys('ret')
            time.sleep(2 * s)
            self.keys('alt-t')                         # Transfer to the builder now
            time.sleep(1 * s)
            self.shot('03-crash-dialog-transfer')
            self.keys('alt-s')                         # Send to MerlinAI
        if self.step('transfer_message', text, 'XP25_MERLIN_CRASH_TRANSFER='):
            time.sleep(4 * s)
            self.shot('04-transfer-message')
            self.keys('ret')
        if self.step('control_panel', text, 'XP25_MERLIN_STEP=control_panel'):
            time.sleep(12 * s)
            self.shot('05-control-panel')
            self.keys('alt-f4')
        if self.step('ui', text, 'XP25_MERLIN_UI_READY') or self.step('ui', text, 'XP25_MERLIN_UI_COLLECTED'):
            time.sleep(10 * s)
            self.shot('06-ui-health')
            self.keys('ctrl-2')
            time.sleep(3 * s)
            self.shot('07-ui-queue')
            self.keys('spc')                            # tick the newest problem (the crash)
            time.sleep(1 * s)
            self.keys('ctrl-3')
            time.sleep(3 * s)
            self.shot('08-ui-build')
            self.keys('alt-b')
            time.sleep(4 * s)
            self.shot('09-ui-build-confirm')
            self.keys('ret')
        if self.step('build_requested', text, 'XP25_MERLIN_UI_BUILD_REQUESTED'):
            time.sleep(6 * s)
            self.shot('10-ui-build-requested')
            self.keys('ctrl-4')
            time.sleep(8 * s)
            self.shot('11-ui-previous-builds')
            self.keys('alt-f4')
            time.sleep(4 * s)
            return 'turn_off'
        return None


def wait(args):
    out = RUNS / args.run
    os.chdir(out)
    inputs = json.loads(Path('inputs.json').read_text())
    scale = 4 if inputs['mode'] == 'tcg' else 1
    deadline = time.time() + args.timeout * (3 if inputs['mode'] == 'tcg' else 1)
    logons = attempts = 0
    sent_at, sent_results = 0.0, -1
    outcome = None
    turn_off, next_off, off_tries = False, 0.0, 0
    with lab.QMP() as q:
        scenario = Scenario(q, scale)
        while time.time() < deadline and not outcome:
            time.sleep(2)
            q.call('query-status')
            while q.events and not outcome:
                event = q.events.pop(0)
                if event.get('event') == 'SHUTDOWN':
                    if event.get('data') == {'guest': True, 'reason': 'guest-shutdown'}:
                        Path('guest-shutdown-event.json').write_text(json.dumps(event, indent=2) + '\n')
                        outcome = 'guest_shutdown'
                    elif event.get('data', {}).get('reason') != 'guest-reset':
                        outcome = 'unexpected_shutdown: ' + json.dumps(event.get('data'))
                elif event.get('event') == 'GUEST_PANICKED':
                    outcome = 'guest_panicked'
            if outcome:
                break
            text = Path('serial.log').read_bytes().decode('latin-1') if Path('serial.log').exists() else ''
            events = winlogon_events(text)
            ready, interactive = events.count('core_ready'), events.count('session_interactive')
            results = events.count('gina_logged_out_result')
            if interactive >= ready and ready > logons:
                logons, attempts, sent_at, sent_results = ready, 0, 0.0, -1
                lab.record({'session_interactive_boot': ready})
            elif ready > logons and (sent_results < 0 or (results == sent_results and time.time() - sent_at > 40 * scale)):
                if sent_results < 0:
                    time.sleep(8 * scale)
                for name in ('ctrl-a', 'backspace', 'ret'):
                    lab.key(q, name)
                    time.sleep(0.3)
                attempts += 1
                sent_at, sent_results = time.time(), results
                lab.record({'logon_keys_sent': attempts})
                if attempts > 8:
                    outcome = 'logon_keys_not_accepted'
            if interactive and inputs.get('scenario') == 'install':
                if 'XP25_MERLIN_SUITE_DONE' in text and not turn_off:
                    time.sleep(10 * scale)
                    turn_off = True
            elif interactive and scenario.run(text) == 'turn_off':
                turn_off = True
            if turn_off and time.time() > next_off:
                for name, pause in (('esc', 1), ('ctrl-esc', 2), ('u', 3), ('u', 1)):
                    lab.key(q, name)
                    time.sleep(pause * scale)
                off_tries += 1
                next_off = time.time() + 90 * scale
                lab.record({'turn_off_keys_sent': off_tries})
                if off_tries > 6:
                    outcome = 'turn_off_not_accepted'
        outcome = outcome or 'timeout'
        if outcome != 'guest_shutdown':
            try:
                lab.screen(q, 'wait-' + outcome.split(':')[0])
            except Exception:
                pass
    lab.checkpoint(stage='wait_' + outcome.split(':')[0], logons=logons)
    print(outcome)
    if outcome == 'guest_shutdown':
        subprocess.run([sys.executable, str(ROOT / 'vm/xp_lab.py'), str(out), 'finish'], check=True)
    else:
        raise SystemExit(1)


def results(args):
    out = RUNS / args.run
    os.chdir(out)
    inputs = json.loads(Path('inputs.json').read_text())
    text = Path('serial.log').read_bytes().decode('latin-1')
    suite_log = ''
    if Path('disk.qcow2').exists() and not os.access('disk.qcow2', os.W_OK):
        # Suite markers are also appended to C:\xp25\merlin-suite.log: COM1 is exclusive and can drop a line.
        with lab.partition(out / 'disk.qcow2', False) as device:
            try:
                suite_log = lab.run(['ntfscat', device, '/xp25/merlin-suite.log']).decode('latin-1')
            except RuntimeError:
                suite_log = ''
        Path('merlin-suite.log').write_text(suite_log)
    text = text + '\n' + suite_log
    marks = {}
    for m in re.finditer(r'(XP25_[A-Z0-9_]+)=(\S+)', text):
        marks.setdefault(m.group(1), []).append(m.group(2))
    def last(key):
        return marks.get(key, [''])[-1]
    problems = re.findall(r'XP25_MERLIN_PROBLEM (.+)', text)
    store_root = out / 'builder-data'
    reports = sorted(p.name for p in (store_root / 'installations' / INSTALLATION / 'reports').glob('*.json'))
    jobs = []
    for d in sorted((store_root / 'jobs').glob('J-*')):
        record = json.loads((d / 'job.json').read_text())
        request = json.loads((d / 'request.json').read_text())
        jobs.append({'job': d.name, 'installation': record['installation'], 'status': record['public']['status'],
                     'problems': [p['title'] for p in request['request']['problems']],
                     'manifest_components': len(request['request']['manifest'].get('components', []))})
    queue = []
    if Path('disk.qcow2').exists() and not os.access('disk.qcow2', os.W_OK):
        queue_dir = '/Documents and Settings/All Users/Application Data/XP25/MerlinAI/Queue'
        with lab.partition(out / 'disk.qcow2', False) as device:
            names = lab.run(['ntfsls', '-p', queue_dir, device]).decode('latin-1').split()
            for n in names:
                if n.endswith('.txt'):
                    body = lab.run(['ntfscat', device, queue_dir + '/' + n]).decode('utf-8', 'replace')
                    fields = dict(l.split('=', 1) for l in body.splitlines() if '=' in l and not l.startswith(('evidence=', 'occurrence=')))
                    queue.append({'file': n, 'kind': fields.get('kind'), 'title': fields.get('title'), 'count': fields.get('count'),
                                  'submitted': fields.get('submitted'), 'owner': fields.get('owner'), 'job': fields.get('job'),
                                  'status': fields.get('status'), 'dump': fields.get('dump')})
            dumps = [n for n in names if n.endswith('.dmp')]
    else:
        dumps = []
    # One line per apply or removal of the user policy (install, uninstall, install again).
    policy_runs = re.findall(r'XP25_MERLIN_INSTALL_POLICY loaded=(\d+) offline=(\d+) default_user=(\d+) failed=(\d+)', text)
    reg_ok = [k for k, v in marks.items() if k.startswith('XP25_MERLIN_REG_') and v[-1] == 'ok']
    reg_bad = [k for k, v in marks.items() if k.startswith('XP25_MERLIN_REG_') and v[-1] != 'ok']
    crash_problem = [p for p in queue if p['file'].startswith('P-') and p['kind'] == 'crash' and p['title'] and 'MerlinTest' in p['title']]
    crash_reports = [p for p in queue if p['file'].startswith('C-') and p['kind'] == 'crash']
    gates = {
        'installer_succeeded': marks.get('XP25_MERLIN_INSTALL', [''])[0] == '0' and marks.get('XP25_MERLIN_INSTALL', [''])[-1] == '0',
        # 10 replacements and policies after install, Default User included; 5 restorations after uninstall.
        'registry_replacements_and_restore': len(reg_ok) == 20 and not reg_bad,
        'security_center_hidden_by_user_policy': all(last('XP25_MERLIN_REG_' + k) == 'ok' for k in
                                                     ('USER_DISALLOWCPL', 'USER_HIDE_WSCUI', 'USER_HIDE_WUAUCPL',
                                                      'DEFAULT_USER_HIDE_WSCUI', 'RESTORED_USER_DISALLOWCPL',
                                                      'RESTORED_USER_HIDE_WSCUI')) and
                                                 bool(policy_runs) and all(r[2] == '1' and r[3] == '0' for r in policy_runs),
        'merlin_in_performance_and_maintenance': last('XP25_MERLIN_CPL_MERLIN_CATEGORY') == '5',
        'firewall_still_running': last('XP25_MERLIN_FIREWALL_RUNNING') == '1',
        'identity_configured': last('XP25_MERLIN_CONFIGURE') == '0',
        'defect_reproduced_before_fix': marks.get('XP25_MERLINTEST_CHECK', [''])[0].startswith('crash') and
                                        last('XP25_MERLINTEST_CHECK_EXIT') == '2',
        'service_crash_no_dialog_queued': last('XP25_MERLIN_SERVICE_CRASH_QUEUED') == '1' and
                                          any('interactive=0' in l for l in re.findall(r'XP25_MERLIN_CRASH_CAPTURED.*', text)),
        'interactive_crash_dialog_send': 'interactive=1' in text and any(v.startswith('send') for v in marks.get('XP25_MERLIN_CRASH_CHOICE', [])),
        'crash_report_queued': last('XP25_MERLIN_CRASH_QUEUED') == '1',
        'report_transferred_with_consent': last('XP25_MERLIN_CRASH_TRANSFER') == '0' and len(reports) >= 1,
        'collection_ran': (marks.get('XP25_MERLIN_COLLECT') or [''])[0] == '0',
        # Each crash is reported twice (MerlinCrash's report and the event 1000 it writes); the problem counts it once.
        'crash_and_event_deduplicated': len(crash_problem) == 1 and crash_problem[0]['count'] == str(len(crash_reports)),
        'service_failure_discovered': any('MerlinAI Lab Service' in (p['title'] or '') for p in queue),
        'status_listed': bool(problems),
        'uninstall_restored': last('XP25_MERLIN_UNINSTALL') == '0',
        'control_panel_before_install': marks.get('XP25_MERLIN_CPL_SECURITY_CENTER', ['0'])[0] == '1' and
                                         marks.get('XP25_MERLIN_CPL_AUTOMATIC_UPDATES', ['0'])[0] == '1' and
                                         marks.get('XP25_MERLIN_CPL_MERLIN', ['1'])[0] == '0',
        'control_panel_replaced': marks.get('XP25_MERLIN_CPL_MERLIN', ['0'])[-1] == '1' and
                                  marks.get('XP25_MERLIN_CPL_SECURITY_CENTER', ['1'])[-1] == '0' and
                                  marks.get('XP25_MERLIN_CPL_AUTOMATIC_UPDATES', ['1'])[-1] == '0' and
                                  len(marks.get('XP25_MERLIN_CPL_MERLIN', [])) == 2,
        'control_panel_window_ready': 'XP25_MERLIN_UI_READY' in text,
        'build_requested_from_ui': 'XP25_MERLIN_UI_BUILD_REQUESTED' in text and any(j['status'] == 'queued' for j in jobs),
        'build_request_only_selected_problem': bool(jobs) and all(len(j['problems']) >= 1 for j in jobs),
        'no_build_from_send': len(jobs) == len([1 for _ in re.findall('XP25_MERLIN_UI_BUILD_REQUESTED', text)]),
        'service_health_report_authenticated': any('"/deploy/v1/health"' in l for l in
                                                   (Path('deploy-requests.jsonl').read_text().splitlines() if Path('deploy-requests.jsonl').exists() else [])),
        'guest_turned_off_normally': Path('guest-shutdown-event.json').exists(),
    }
    result = {'run': args.run, 'mode': inputs['mode'], 'image': inputs['image'], 'base_sha256': inputs['base_sha256'], 'gates': gates,
              'passed': sum(gates.values()), 'total': len(gates), 'registry_ok': sorted(reg_ok), 'registry_bad': sorted(reg_bad),
              'builder_reports': reports, 'builder_jobs': jobs, 'queue': queue, 'dumps': dumps, 'status_lines': problems[:40]}
    Path('results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'passed': result['passed'], 'total': result['total'],
                      'failed': [k for k, v in gates.items() if not v]}, indent=1))
    return 0 if result['passed'] == result['total'] else 1


def fail(args):
    """Freeze a failed run with failure.json (never repaired or deleted)."""
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
    p.add_argument('--image', default='m9')
    p.add_argument('--build', type=Path, required=True)
    p.add_argument('--scenario', default='9a', choices=('9a', 'install'))
    p.add_argument('--revision', help='text for C:\\xp25\\image-revision.txt (install scenario)')
    p = sub.add_parser('wait')
    p.add_argument('run')
    p.add_argument('--timeout', type=int, default=3600)
    p = sub.add_parser('results')
    p.add_argument('run')
    p = sub.add_parser('fail')
    p.add_argument('run')
    p.add_argument('reason')
    args = parser.parse_args()
    RUNS.mkdir(parents=True, exist_ok=True)
    if args.action == 'launch':
        launch(args)
    elif args.action == 'wait':
        wait(args)
    elif args.action == 'fail':
        fail(args)
    else:
        return results(args)


if __name__ == '__main__':
    sys.exit(main())
