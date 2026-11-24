#!/usr/bin/env python3
"""Build the frozen XP25 Newbie template behind Mise En Abyme's disposable desktops.

The template is the current XP25-Winlogon-Fix system with nothing of the
administrator's VM in it:

  * IMAGE is image-04, the MerlinAI Builder's baseline xp25wf4 as packaged,
    before the administrator's VM ran from it (its SHA-256 is checked);
  * UPDATE is a MerlinAI update the deployment agent staged for that VM
    (files 000.bin... and manifest.json), applied exactly as the agent applies
    it: every file must replace one with the manifest's expected_before hash;
  * one setup boot, without a network adapter, logs XP25 (blank password) on
    and runs a one-time Startup script that gives the template its own MerlinAI
    installation (never the administrator VM's credentials), removes the
    Supermium profile and turns on automatic logon of XP25. The guest is then
    turned off from the Start menu and its disk frozen;
  * a verification boot of a throw-away overlay must reach an interactive
    session with no key sent (automatic logon). It is then stopped.

  newbie_template.py --output DIR --baseline IMAGE --baseline-sha256 HEX \\
      --update STAGE_DIR --installation-json FILE [--relay URL] [--deploy URL]

INSTALLATION_JSON is builder_vm.py register's output for the installation
({"installation", "builder_key", "baseline"}); it is read, never copied.
The script's NTFS clusters may keep that key after the script deletes itself;
the key belongs to the Newbie installation, which every Newbie can read anyway.

Output (a fresh directory under .work/):
  base.qcow2         reflink copy of IMAGE, read-only
  setup/disk.qcow2   the template (base + update + setup boot), frozen 0444
  setup/, verify/    COM1, QMP journals, screenshots of the two boots
  template.json      hashes, update, installation id (no keys), observations"""
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
import xp_lab as lab                      # noqa: E402
import browser_wait_shutdown as session   # noqa: E402

SETUP = r'''@echo off
rem XP25 Newbie template setup: runs once at the first logon, then deletes itself.
call :mark "XP25_NEWBIE_SETUP_BEGIN"
"C:\Program Files\XP25\MerlinAI\MerlinAI.exe" /configure {relay} {deploy} {installation} {builder_key} {deploy_key}
call :mark "XP25_NEWBIE_CONFIGURE_EXIT=%ERRORLEVEL%"
set WL=HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
reg add "%WL%" /v DefaultUserName /t REG_SZ /d XP25 /f > nul && reg add "%WL%" /v DefaultPassword /t REG_SZ /d "" /f > nul && reg add "%WL%" /v AutoAdminLogon /t REG_SZ /d 1 /f > nul
call :mark "XP25_NEWBIE_AUTOLOGON_EXIT=%ERRORLEVEL%"
rem %APPDATA% is not set in an XP25 Winlogon session; the profile folder is.
set SUPERMIUM=%USERPROFILE%\Application Data\Supermium
echo profile %SUPERMIUM% >> C:\xp25\newbie-setup.log
rd /s /q "%SUPERMIUM%" 2>> C:\xp25\newbie-setup.log
dir /ad "%SUPERMIUM%" > nul 2>&1 && (call :mark "XP25_NEWBIE_PROFILE_EXIT=1") || (call :mark "XP25_NEWBIE_PROFILE_EXIT=0")
"C:\Program Files\XP25\MerlinAI\MerlinAI.exe" /status
call :mark "XP25_NEWBIE_SETUP_DONE"
del "%USERPROFILE%\Start Menu\Programs\Startup\XP25NewbieSetup.cmd"
del C:\xp25\newbie-setup.cmd & goto :eof
:mark
rem The XP25 Winlogon opens COM1 for each of its own records: retry a busy port.
for /l %%i in (1,1,15) do (
  (echo %~1 > COM1) 2> nul && (echo %~1 >> C:\xp25\newbie-setup.log) && exit /b 0
  ping -n 2 127.0.0.1 > nul
)
echo %~1 >> C:\xp25\newbie-setup.log
echo COM1 busy >> C:\xp25\newbie-setup.log
exit /b 0
'''
EXPECTED = {'XP25_NEWBIE_CONFIGURE_EXIT': '0', 'XP25_NEWBIE_AUTOLOGON_EXIT': '0', 'XP25_NEWBIE_PROFILE_EXIT': '0'}
STARTUP = '/Documents and Settings/XP25/Start Menu/Programs/Startup/XP25NewbieSetup.cmd'


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1 << 22), b''):
            h.update(block)
    return h.hexdigest()


def apply_update(device, stage, manifest):
    """The deployment agent's offline rules: replace only files whose current hash is the expected one."""
    for f in manifest['files']:
        if not f.get('expected_before'):
            raise PermissionError('the update would create %s offline, without access control' % f['guest_path'])
        found = hashlib.sha256(lab.run(['ntfscat', device, f['guest_path']])).hexdigest()
        if found != f['expected_before']:
            raise PermissionError('%s is %s, not the file the update was made for' % (f['guest_path'], found[:16]))
    for i, f in enumerate(manifest['files']):
        lab.run(['ntfscp', device, str(stage / ('%03d.bin' % i)), f['guest_path']])
        if hashlib.sha256(lab.run(['ntfscat', device, f['guest_path']])).hexdigest() != f['sha256']:
            raise RuntimeError('offline replacement of %s did not take effect' % f['guest_path'])
    return [f['guest_path'] for f in manifest['files']]


def boot(run, memory=1024):
    """Start the run's disk.qcow2 with the XP25 hardware profile, no network adapter, COM1 to serial.log."""
    command = ['qemu-system-i386', '-name', run.name, '-machine', 'pc-i440fx-8.2,kernel-irqchip=on', '-accel', 'kvm',
               '-cpu', 'qemu32', '-m', str(memory), '-smp', '1', '-nodefaults', '-nic', 'none', '-vga', 'std',
               '-usb', '-device', 'usb-tablet', '-display', 'none', '-monitor', 'none',
               '-qmp', 'unix:qmp.sock,server=on,wait=off', '-serial', 'file:serial.log', '-rtc', 'base=localtime',
               '-drive', 'file=disk.qcow2,format=qcow2,if=ide,index=0', '-boot', 'order=c', '-pidfile', 'qemu.pid',
               '-no-reboot', '-no-shutdown', '-S', '-daemonize']
    (run / 'qemu-command.json').write_text(json.dumps(command, indent=2) + '\n')
    subprocess.run(command, cwd=run, check=True)
    os.chdir(run)
    with lab.QMP() as q:
        q.call('cont')


def markers(text):
    text = text.replace('\r', '')
    return {k: v for k, _, v in (line.strip().partition('=') for line in text.splitlines()
                                 if line.startswith('XP25_NEWBIE_') or line.startswith('XP25_MERLIN_'))}


def setup_session(run, q, timeout):
    """Log XP25 (blank password) on once, let the Startup script run, then turn the guest off from the Start menu.

    The MSGINA dialog is up and idle when the Winlogon has logged its visible password field after the
    last result (vm/security_lab.py's cue). COM1 drops records under this Winlogon, so the script's own
    marker is only a hint: without it, the guest is turned off 240 s after the logon was accepted, and
    the results are read from the guest's log offline."""
    deadline = time.time() + timeout
    attempts, handled, sent_at, ui_tries, next_ui = 0, -1, 0.0, 0, None
    while time.time() < deadline:
        time.sleep(2)
        q.call('query-status')
        while q.events:
            event = q.events.pop(0)
            lab.record({'event': event})
            if session.shutdown_event(run, event):
                return
        text = (run / 'serial.log').read_text(errors='replace')
        events = session.winlogon_events(text)
        marks = {name: max((i for i, e in enumerate(events) if e == name), default=-1)
                 for name in ('gina_dialog_edit_1503_enabled_1_visible_1', 'gina_logged_out_result', 'session_interactive')}
        prompt = marks['gina_dialog_edit_1503_enabled_1_visible_1']
        idle = prompt > marks['gina_logged_out_result'] and prompt > marks['session_interactive']
        if idle and handled == prompt and time.time() - sent_at > 90:
            handled = -1                                   # no result for the keys that were sent: they were lost
        if idle and handled != prompt and next_ui is None:
            if attempts > 6:
                raise ValueError('logon keys not accepted')
            time.sleep(2)
            lab.key(q, 'alt-p')
            time.sleep(0.5)
            for name in ('end', 'shift-home', 'delete', 'ret'):
                lab.key(q, name)
            attempts += 1
            handled, sent_at = prompt, time.time()
            lab.record({'logon_keys_sent': attempts})
            continue
        if next_ui is None and attempts and not idle and time.time() - sent_at > 20:
            done = 'XP25_NEWBIE_SETUP_DONE' in text
            if done or time.time() - sent_at > 240:
                next_ui = time.time() + (30 if done else 0)
                lab.record({'setup_done_marker': done})
        if next_ui is not None and time.time() > next_ui:
            if ui_tries >= 6:
                raise ValueError('Turn Off Computer keys not accepted')
            for name, pause in (('esc', 1), ('ctrl-esc', 2), ('u', 3), ('u', 1)):
                lab.key(q, name)
                time.sleep(pause)
            ui_tries += 1
            next_ui = time.time() + 90
            lab.record({'ui_shutdown_keys_sent': ui_tries})
    raise TimeoutError('setup boot did not turn off')


def exists(device, path):
    parent, _, name = path.rpartition('/')
    listing = lab.run(['ntfsls', '-p', parent or '/', device]).decode(errors='replace')
    return name.lower() in (line.strip().lower() for line in listing.splitlines())


def registry_value(device, hive_path, key_suffix, name):
    sys.path.insert(0, str(ROOT / 'vm'))
    import regf
    data = lab.run(['ntfscat', device, hive_path])
    for path, value, _, raw in regf.walk(data):
        if path.endswith(key_suffix) and value == name:
            return None if raw is None else raw.decode('utf-16-le', 'replace').rstrip('\0')
    return None


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--baseline', type=Path, required=True)
    p.add_argument('--baseline-sha256', required=True)
    p.add_argument('--update', type=Path, required=True)
    p.add_argument('--installation-json', type=Path, required=True)
    p.add_argument('--relay', default='http://10.25.0.1:8740')
    p.add_argument('--deploy', default='http://10.25.0.1:8746')
    p.add_argument('--timeout', type=int, default=900)
    a = p.parse_args()
    out, baseline, stage = a.output.resolve(), a.baseline.resolve(), a.update.resolve()
    if not out.is_relative_to(ROOT / '.work'):
        p.error('output must be under .work/')
    if out.exists():
        p.error('output exists; use a fresh directory')
    identity = json.loads(a.installation_json.read_text())
    manifest = json.loads((stage / 'manifest.json').read_text())
    if manifest.get('schema') != 'xp25-merlin-delta/1' or manifest.get('baseline_image_sha256') != a.baseline_sha256:
        p.error('the update was not made for this baseline')
    if sha(baseline) != a.baseline_sha256:
        p.error('baseline image hash differs from --baseline-sha256')
    os.umask(0o022)
    out.mkdir(parents=True)
    record = {'baseline': str(baseline), 'baseline_sha256': a.baseline_sha256, 'update': {'job': manifest['job'],
              'revision': manifest['revision'], 'files': manifest['files']}, 'installation': identity['installation'],
              'builder_baseline': identity.get('baseline'), 'relay': a.relay, 'deploy': a.deploy}

    base = out / 'base.qcow2'
    subprocess.run(['cp', '--reflink=always', str(baseline), str(base)], check=True)
    base.chmod(0o444)
    record['base_sha256'] = sha(base)
    assert record['base_sha256'] == a.baseline_sha256

    # Setup run: update applied offline, one-time script staged, one boot with XP25 logged on.
    run = out / 'setup'
    run.mkdir()
    subprocess.run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'qcow2', '-b', str(base), str(run / 'disk.qcow2')],
                   check=True)
    offline = out / 'offline'
    offline.mkdir()
    os.chdir(offline)
    script = offline / 'newbie-setup.cmd'
    old = os.umask(0o077)
    script.write_bytes(SETUP.format(relay=a.relay, deploy=a.deploy, installation=identity['installation'],
                                    builder_key=identity['builder_key'], deploy_key=secrets.token_hex(32))
                       .replace('\n', '\r\n').encode())
    os.umask(old)
    startup = offline / 'XP25NewbieSetup.cmd'
    startup.write_bytes(b'@call C:\\xp25\\newbie-setup.cmd\r\n')
    try:
        with lab.partition(run / 'disk.qcow2', True) as device:
            record['update']['applied'] = apply_update(device, stage, manifest)
            lab.run(['ntfscp', device, script, '/xp25/newbie-setup.cmd'])
            lab.run(['ntfscp', device, startup, STARTUP])
    finally:
        script.unlink()
    boot(run)
    lab.checkpoint(stage='newbie_setup_booting')
    with lab.QMP() as q:
        setup_session(run, q, a.timeout)
    subprocess.run([sys.executable, str(ROOT / 'vm/xp_lab.py'), str(run), 'finish'], check=True)
    template = run / 'disk.qcow2'
    record['template'] = str(template)
    record['template_sha256'] = json.loads((run / 'checkpoint.json').read_text())['disk_sha256']

    # Offline checks of the frozen template; the script's results come from its own log (COM1 drops lines).
    os.chdir(offline)
    with lab.partition(template, False) as device:
        guest_log = lab.run(['ntfscat', device, '/xp25/newbie-setup.log']).decode(errors='replace')
        found = markers((run / 'serial.log').read_text(errors='replace'))
        found.update(markers(guest_log))
        record['setup_markers'] = found
        for k, v in EXPECTED.items():
            if found.get(k) != v:
                (out / 'template.json').write_text(json.dumps(record, indent=2) + '\n')
                raise SystemExit('setup result %s=%s, expected %s' % (k, found.get(k), v))
        soft, winlogon = '/WINDOWS/system32/config/software', 'Windows NT\\CurrentVersion\\Winlogon'
        checks = {'auto_admin_logon': registry_value(device, soft, winlogon, 'AutoAdminLogon'),
                  'default_user': registry_value(device, soft, winlogon, 'DefaultUserName'),
                  'merlin_installation': registry_value(device, soft, 'XP25\\MerlinAI\\Credentials', 'Installation'),
                  'revision': lab.run(['ntfscat', device, '/xp25/image-revision.txt']).decode().strip()}
        for gone in ('/xp25/newbie-setup.cmd', STARTUP, '/Documents and Settings/XP25/Application Data/Supermium'):
            if exists(device, gone):                       # ntfsinfo -F exits 0 even for a missing file
                checks['present:' + gone] = True
        for f in manifest['files']:
            checks['sha256:' + f['guest_path']] = hashlib.sha256(lab.run(['ntfscat', device, f['guest_path']])).hexdigest() \
                == f['sha256']
    record['offline_checks'] = checks
    if checks['auto_admin_logon'] != '1' or checks['default_user'] != 'XP25' or \
            checks['merlin_installation'] != identity['installation'] or checks['revision'] != manifest['revision'] or \
            any(k.startswith('present:') for k in checks) or not all(v for k, v in checks.items() if k.startswith('sha256:')):
        (out / 'template.json').write_text(json.dumps(record, indent=2) + '\n')
        raise SystemExit('offline checks failed: %s' % json.dumps(checks))

    # Verification boot: a throw-away overlay must log XP25 on by itself.
    verify = out / 'verify'
    verify.mkdir()
    subprocess.run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'qcow2', '-b', str(template),
                    str(verify / 'disk.qcow2')], check=True)
    boot(verify)
    started, interactive = time.time(), None
    while time.time() - started < 300:
        time.sleep(2)
        events = session.winlogon_events((verify / 'serial.log').read_text(errors='replace'))
        if 'session_interactive' in events or 'authenticated_token_session' in events:
            interactive = round(time.time() - started, 1)
            break
    with lab.QMP() as q:
        time.sleep(20 if interactive else 0)
        record['verify_screen'] = lab.screen(q, 'verify-desktop')
        q.call('quit')
    record['autologon_seconds'] = interactive
    record['verify_note'] = 'no key was sent; the verification overlay was stopped with QMP quit (not a guest shutdown)'
    (out / 'template.json').write_text(json.dumps(record, indent=2) + '\n')
    if interactive is None:
        raise SystemExit('no interactive session without input within 300 s; see verify/serial.log')
    print(json.dumps({'template': str(template), 'sha256': record['template_sha256'],
                      'autologon_seconds': interactive}, indent=2))


if __name__ == '__main__':
    main()
