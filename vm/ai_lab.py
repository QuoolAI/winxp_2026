#!/usr/bin/env python3
"""Boot a disposable overlay of a hash-verified XP25 engineering image with
the XP25 AI components staged into C:\\xp25 for a guest-side installer, the
frozen established regression CD as D:, and the isolated network plus the
XP25 gateway and OpenAI test double (vm/ai_network.py).

At logon a Startup fixture installs the components (installer in the guest),
runs tests/guest/ai_probe.c, the provider checks and D:\\compat-regress.cmd,
writes results to COM1 and removes itself. The reference image is never
opened writable. Usage:
  vm/ai_lab.py --name RUN --mode up|mp|tcg --build DIR [--no-provider]"""
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
import xp_lab as lab

MAIN = Path('/mnt/01962c02-074f-47e7-8ee3-699a169f4905/winxp_2026/.work')
BASES = {
    'up': (ROOT / '.work/ai-20261025/reference/XP25-Components-Engineering.qcow2',
           '39112bbd46f89308180d651a94826808dee3a6acdcc18309b9af7c6d90340296'),
    'mp': (MAIN / 'boot-debug-20261022/shell-userenv-combined-kvm-mp-02/disk.qcow2',
           'd46fa4bf039d8c08990d5b019600f99cc2b593b83089c5ccda34847016573b8f'),
}
BASES['tcg'] = BASES['up']
REGRESSION_ISO = (MAIN / 'native-shell-userenv-20261024/test-media-05/native-tests.iso',
                  'c3b851d3ebc1d3d5ef254e262665a333c208aba0f8feae9d452609360981a390')
BINARIES = ['xp25agent.dll', 'ClippyAI.exe', 'RoverAI.exe', 'RoverAIBand.dll', 'XP25Broker.exe', 'ai_probe.exe']

INSTALL = r'''@echo off
rem XP25 AI installer used by the guest tests (staged files in C:\xp25).
set P=C:\Program Files\XP25
mkdir "%P%" 2>nul
mkdir C:\xp25\ai 2>nul
for %%F in (xp25agent.dll ClippyAI.exe RoverAI.exe RoverAIBand.dll XP25Broker.exe) do copy /y C:\xp25\ai-%%F "%P%\%%F" >nul
copy /y C:\xp25\ai-ai_probe.exe C:\xp25\ai\ai_probe.exe >nul
"%P%\XP25Broker.exe" /install
echo XP25_AI_BROKER_INSTALL=%ERRORLEVEL% > COM1
"%P%\RoverAI.exe" /register
echo XP25_AI_BAND_REGISTER=%ERRORLEVEL% > COM1
"%P%\RoverAI.exe" /replace-search on
echo XP25_AI_SEARCH_REPLACED=%ERRORLEVEL% > COM1
"%P%\ClippyAI.exe" /install
echo XP25_AI_SHORTCUTS=%ERRORLEVEL% > COM1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "XP25 RoverAI Indexer" /d "\"%P%\RoverAI.exe\" /background" /f >nul
start "" "%P%\RoverAI.exe" /background
sc query XP25Broker > C:\xp25\ai\broker-state.txt
'''

INSTALL_ONLY = r'''@echo off
rem Image preparation: install like an end user, remove the installer payload, shut down.
echo XP25_AI_IMAGE_INSTALL_STARTED > COM1
call C:\xp25\ai-install.cmd > C:\xp25\ai-install.log 2>&1
del /q C:\xp25\ai-*.exe C:\xp25\ai-*.dll C:\xp25\ai-suite.cmd
del /q C:\xp25\ai\ai_probe.exe
del "C:\Documents and Settings\XP25\Start Menu\Programs\Startup\XP25AISuite.cmd"
echo XP25_AI_SUITE_DONE > COM1
'''

TESTS_ONLY = r'''@echo off
rem Independent proof of a preinstalled image: nothing is installed here.
echo XP25_AI_TESTS_STARTED > COM1
mkdir C:\xp25\ai 2>nul
copy /y C:\xp25\ai-ai_probe.exe C:\xp25\ai\ai_probe.exe >nul
C:\xp25\ai\ai_probe.exe suite {slow}
echo XP25_AI_PROBE_EXIT=%ERRORLEVEL% > COM1
{provider}
call D:\compat-regress.cmd
echo XP25_AI_REGRESSION_DONE > COM1
del "C:\Documents and Settings\XP25\Start Menu\Programs\Startup\XP25AISuite.cmd"
echo XP25_AI_SUITE_DONE > COM1
'''

SUITE = r'''@echo off
rem Phase 1 installs and restarts like a normal installer; phase 2 tests.
if exist C:\xp25\ai\phase1.done goto tests
mkdir C:\xp25\ai 2>nul
echo XP25_AI_SUITE_STARTED > COM1
call C:\xp25\ai-install.cmd > C:\xp25\ai-install.log 2>&1
echo installed > C:\xp25\ai\phase1.done
echo XP25_AI_INSTALLED_RESTARTING > COM1
shutdown.exe -r -t 5 -c "XP25 AI installation complete"
goto :eof
:tests
echo XP25_AI_TESTS_STARTED > COM1
C:\xp25\ai\ai_probe.exe suite {slow}
echo XP25_AI_PROBE_EXIT=%ERRORLEVEL% > COM1
{provider}
call D:\compat-regress.cmd
echo XP25_AI_REGRESSION_DONE > COM1
del "C:\Documents and Settings\XP25\Start Menu\Programs\Startup\XP25AISuite.cmd"
echo XP25_AI_SUITE_DONE > COM1
'''


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 22), b''):
            h.update(block)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--name', required=True)
    parser.add_argument('--mode', choices=sorted(BASES), required=True)
    parser.add_argument('--build', type=Path, required=True, help='directory with the six binaries')
    parser.add_argument('--no-provider', action='store_true', help='skip the gateway/OpenAI test double checks')
    parser.add_argument('--install-only', action='store_true', help='image preparation: install, then shut down')
    parser.add_argument('--image', type=Path, help='preinstalled image to prove (with --image-sha256); stages only the probe')
    parser.add_argument('--image-sha256')
    parser.add_argument('--no-suite', action='store_true', help='diagnostic boot: stage nothing at logon')
    args = parser.parse_args()
    if '/' in args.name or args.name in ('.', '..'):
        parser.error('a fresh simple run name is required')
    build = args.build.resolve()
    if not build.is_relative_to(ROOT / '.work'):
        parser.error('binaries must come from a private .work/ build')
    base, base_sha = BASES[args.mode]
    if args.image:
        if not args.image_sha256 or args.install_only:
            parser.error('--image needs --image-sha256 and excludes --install-only')
        base, base_sha = args.image.resolve(), args.image_sha256
    iso, iso_sha = REGRESSION_ISO
    if args.image and not args.image.resolve().is_relative_to(ROOT / '.work'):
        parser.error('images must be private .work/ files')
    if base.stat().st_mode & 0o222:
        parser.error('backing image must be frozen (read-only)')
    out = ROOT / '.work/ai-20261025/runs' / args.name
    out.mkdir(parents=True, exist_ok=False)
    os.chdir(out)
    actual = {'base': sha(base), 'regression_iso': sha(iso)}
    if actual['base'] != base_sha or actual['regression_iso'] != iso_sha:
        Path('failure.json').write_text(json.dumps({'reason': 'reference hash mismatch', 'actual': actual}, indent=2) + '\n')
        raise SystemExit('reference hash mismatch')
    secret = secrets.token_hex(32)
    mock_key = 'sk-xp25-isolated-test-' + secrets.token_hex(8)
    Path('gateway-clients.json').write_text(json.dumps({'xp25': {'secret_hex': secret}}) + '\n')
    slow = 'slow' if args.mode == 'tcg' else ''
    provider = '' if args.no_provider else ('C:\\xp25\\ai\\ai_probe.exe provider %s %s\r\necho XP25_AI_PROVIDER_EXIT=%%ERRORLEVEL%% > COM1'
                                            % (secret, slow))
    Path('ai-install.cmd').write_bytes(INSTALL.replace('\n', '\r\n').encode())
    template = INSTALL_ONLY if args.install_only else TESTS_ONLY if args.image else SUITE
    Path('ai-suite.cmd').write_bytes(template.format(slow=slow, provider=provider).replace('\n', '\r\n').encode())
    Path('XP25AISuite.cmd').write_bytes(b'@call C:\\xp25\\ai-suite.cmd\r\n')
    lab.run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', base, 'disk.qcow2'])
    names = ['ai_probe.exe'] if args.image else BINARIES
    files = {'/xp25/ai-' + name: build / name for name in names}
    files['/xp25/ai-install.cmd'] = out / 'ai-install.cmd'
    files['/xp25/ai-suite.cmd'] = out / 'ai-suite.cmd'
    if not args.no_suite:
        files['/Documents and Settings/XP25/Start Menu/Programs/Startup/XP25AISuite.cmd'] = out / 'XP25AISuite.cmd'
    staged = {}
    with lab.partition(out / 'disk.qcow2', True) as device:
        for target, source in files.items():
            lab.run(['ntfscp', '-t', device, source, target])
            if lab.run(['ntfscat', device, target]) != source.read_bytes():
                raise RuntimeError('staging mismatch: ' + target)
            staged[target] = {'source': str(source), 'sha256': sha(source)}
    if sha(base) != base_sha:
        raise RuntimeError('reference image changed during staging')
    Path('inputs.json').write_text(json.dumps({'mode': args.mode, 'base': str(base), 'base_sha256': base_sha,
                                               'regression_iso': str(iso), 'regression_iso_sha256': iso_sha,
                                               'staged': staged, 'provider_checks': not args.no_provider,
                                               'role': 'install_only' if args.install_only else 'image_proof' if args.image else 'install_and_test',
                                               'gateway_secret_scope': 'per-run test secret, isolated namespace only'},
                                              indent=2) + '\n')
    machine, accel, cpus = (('pc-i440fx-8.2', 'tcg,thread=single', '1') if args.mode == 'tcg' else
                            ('pc-i440fx-8.2,kernel-irqchip=on', 'kvm', '2' if args.mode == 'mp' else '1'))
    command = ['qemu-system-i386', '-name', args.name, '-machine', machine, '-accel', accel, '-cpu', 'qemu32', '-m', '512',
               '-smp', cpus, '-nodefaults', '-nic', 'none', '-vga', 'std', '-display', 'none', '-monitor', 'none',
               '-qmp', 'unix:qmp.sock,server=on,wait=off', '-serial', 'file:serial.log', '-rtc', 'base=localtime',
               '-drive', 'file=disk.qcow2,format=qcow2,if=ide,index=0',
               '-drive', 'file=' + str(iso) + ',format=raw,readonly=on,if=ide,index=2,media=cdrom',
               '-boot', 'order=c', '-pidfile', 'qemu.pid', '-no-reboot', '-no-shutdown', '-S']
    Path('qemu-command.json').write_text(json.dumps(command, indent=2) + '\n')
    wrapper = ['unshare', '--user', '--map-root-user', '--net', sys.executable, str(ROOT / 'vm/ai_network.py'),
               'qemu-command.json', '--parent-netns', os.readlink('/proc/self/ns/net'),
               '--gateway-clients', 'gateway-clients.json', '--mock-key', mock_key]
    with Path('namespace.log').open('w') as log:
        process = subprocess.Popen(wrapper, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    lab.record({'argv': wrapper[:-1] + ['<per-run test key>'], 'pid': process.pid})
    for _ in range(300):
        if process.poll() is not None:
            raise RuntimeError(Path('namespace.log').read_text())
        if Path('qmp.sock').exists():
            try:
                with lab.QMP() as q:
                    q.call('cont')
                    q.call('set-action', {'reboot': 'reset'})   # the installer restarts the guest once
                break
            except (ConnectionRefusedError, FileNotFoundError, EOFError):
                pass
        time.sleep(0.1)
    else:
        raise TimeoutError('QMP startup')
    lab.checkpoint(stage='ai_guest_booting', mode=args.mode, namespace_pid=process.pid,
                   qemu_pid=int(Path('qemu.pid').read_text()), base_sha256=base_sha)
    print(out)


if __name__ == '__main__':
    main()
