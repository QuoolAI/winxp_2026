#!/usr/bin/env python3
"""Media that turns an XP25 VM disk into one with Supermium and without Internet Explorer.

Combines the verified Supermium media (build/prepare_browser.py --internet gateway),
the native Help media (build/prepare_native_help.py), the XP25 User Accounts applet
and the IE removal (build/ie_removal.py). Two Startup suites drive two disposable
runs in vm/browser_lab.py, the second booting an overlay of the first:

  install-suite.cmd  installs Supermium, XP25 Help and the applet, unregisters the IE
                     engine and queues its files for deletion, then shuts down
  verify-suite.cmd   runs after the boot that deleted the files: ieremoval_probe,
                     the Help self-test and a JScript run that must fail, then shuts down

The patched Explorer (Start-menu Help) is staged offline into the first run.
Each suite ends at its DONE marker; vm/browser_wait_shutdown.py --ui-shutdown then turns
the guest off from the Start menu (shutdown.exe has no InitShutdown server under the
XP25 Winlogon).
No downloaded code runs on the host; nothing is uploaded."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build'))
import ie_removal


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


INSTALL = r'''@echo off
mkdir C:\xp25\browser 2>nul
echo XP25_VM_INSTALL_BEGIN > COM1
call D:\install.cmd > C:\xp25\browser\install.log 2>&1
echo XP25_VM_BROWSER_INSTALL_EXIT=%ERRORLEVEL% > COM1
if errorlevel 1 goto done
call D:\help\install.cmd > C:\xp25\browser\help-install.log 2>&1
echo XP25_VM_HELP_INSTALL_EXIT=%ERRORLEVEL% > COM1
if errorlevel 1 goto done
call D:\remove-ie.cmd > C:\xp25\browser\remove-ie.log 2>&1
echo XP25_VM_IE_REMOVAL_EXIT=%ERRORLEVEL% > COM1
type C:\xp25\browser\remove-ie.log > COM1
"C:\Program Files\XP25Browser\browserctl.exe" open-url "javascript:alert(1)" > COM1
echo XP25_VM_REJECT_SCRIPT_URL=%ERRORLEVEL% > COM1
:done
del "%USERPROFILE%\Start Menu\Programs\Startup\XP25BrowserSuite.cmd"
echo XP25_VM_INSTALL_DONE > COM1
del /q C:\xp25\browser-suite.cmd
'''

VERIFY = r'''@echo off
echo XP25_VM_VERIFY_BEGIN > COM1
D:\ieremoval_probe.exe > C:\xp25\browser\ie-probe.log 2>&1
echo XP25_VM_IE_PROBE_EXIT=%ERRORLEVEL% > COM1
type C:\xp25\browser\ie-probe.log > COM1
start "" /wait "C:\Program Files\XP25Help\XP25Help.exe" --self-test > COM1
echo XP25_VM_HELP_SELF_TEST_EXIT=%ERRORLEVEL% > COM1
type C:\xp25-help-selftest.log > COM1
del /q C:\xp25-help-selftest.log
echo WScript.Echo("jscript ran") > C:\xp25\browser\engine-check.js
cscript //nologo //B C:\xp25\browser\engine-check.js
echo XP25_VM_JSCRIPT_RUN_EXIT=%ERRORLEVEL% > COM1
del /q C:\xp25\browser\engine-check.js
"C:\Program Files\XP25Browser\browserctl.exe" inventory > C:\xp25\browser\verify-inventory.txt
echo XP25_VM_INVENTORY_EXIT=%ERRORLEVEL% > COM1
del "%USERPROFILE%\Start Menu\Programs\Startup\XP25BrowserSuite.cmd"
echo XP25_VM_VERIFY_DONE > COM1
del /q C:\xp25\browser-suite.cmd
'''


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--prepared', type=Path, required=True, help='build/prepare_browser.py output (--internet gateway)')
    p.add_argument('--help-media', type=Path, required=True, help='build/prepare_native_help.py output')
    p.add_argument('--users-applet', type=Path, required=True, help='natively built xp25users.dll')
    p.add_argument('--ie-probe', type=Path, required=True, help='ieremoval_probe.exe from build/guest.py')
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    out = a.output.resolve()
    if not out.is_relative_to(ROOT / '.work'):
        p.error('private .work output required')
    prepared = json.loads((a.prepared / 'manifest.json').read_text())
    if prepared.get('internet') != 'gateway':
        p.error('the VM media needs Supermium prepared with --internet gateway')
    help_manifest = json.loads((a.help_media / 'manifest.json').read_text())
    out.mkdir(parents=True, exist_ok=False)
    media = out / 'media'
    shutil.copytree(a.prepared / 'media', media,
                    copy_function=lambda src, dst: subprocess.run(['cp', '--reflink=always', src, dst], check=True) and dst)
    for relative, digest in prepared['files'].items():
        if sha(media / relative) != digest:
            raise ValueError('prepared media changed: ' + relative)
    shutil.copytree(a.help_media / 'media', media / 'help')
    for name, digest in help_manifest['files'].items():
        if sha(media / 'help' / name) != digest:
            raise ValueError('help media changed: ' + name)
    shutil.copy2(a.users_applet, media / 'xp25users.cpl')
    shutil.copy2(a.ie_probe, media / 'ieremoval_probe.exe')
    removal = ie_removal.generate(media)
    for name, text in (('install-suite.cmd', INSTALL), ('verify-suite.cmd', VERIFY)):
        (out / name).write_bytes(text.replace('\n', '\r\n').encode('ascii'))
    iso = out / 'vm-browser.iso'
    command = ['genisoimage', '-quiet', '-J', '-joliet-long', '-r', '-V', 'XP25BROWSER', '-o', str(iso), str(media)]
    subprocess.run(command, check=True)
    manifest = {'prepared_manifest_sha256': sha(a.prepared / 'manifest.json'), 'pin': prepared['pin'],
                'internet': prepared['internet'], 'help_manifest_sha256': sha(a.help_media / 'manifest.json'),
                'patched_explorer': help_manifest['patched_explorer'], 'patched_explorer_sha256': help_manifest['patched_explorer_sha256'],
                'original_explorer_sha256': help_manifest['original_explorer_sha256'],
                'users_applet_sha256': sha(a.users_applet), 'ie_probe_sha256': sha(a.ie_probe), 'ie_removal': removal,
                'suites': {n: sha(out / n) for n in ('install-suite.cmd', 'verify-suite.cmd')},
                'files': {str(f.relative_to(media)): sha(f) for f in sorted(media.rglob('*')) if f.is_file()},
                'iso': str(iso), 'iso_sha256': sha(iso), 'commands': [command], 'redistribution_approved': False}
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'iso': str(iso), 'sha256': manifest['iso_sha256']}))


if __name__ == '__main__':
    main()
