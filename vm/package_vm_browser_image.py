#!/usr/bin/env python3
"""Flatten the Supermium/IE-removal runs of build/prepare_vm_browser.py into a standalone image.

Requires both runs to have shut down normally and been frozen, the verify run to
boot an overlay of the unchanged install run, every install and verify marker,
and then checks the disk offline: the Supermium files and the patched Explorer
are the prepared bytes, every removed file is gone, ieproxy.dll is kept. Then a
plain qemu-img convert (no compression: this becomes a working VM disk),
check and compare. Nothing is promoted beyond what was observed."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import xp_lab as lab

ROOT = Path(__file__).resolve().parents[1]
INSTALL = {'XP25_VM_BROWSER_INSTALL_EXIT': '0', 'XP25_VM_HELP_INSTALL_EXIT': '0', 'XP25_VM_IE_REMOVAL_EXIT': '0',
           'XP25_VM_REJECT_SCRIPT_URL': '87'}
VERIFY = {'XP25_VM_IE_PROBE_EXIT': '0', 'XP25_VM_HELP_SELF_TEST_EXIT': '0', 'XP25_VM_INVENTORY_EXIT': '0'}


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1 << 22), b''):
            h.update(block)
    return h.hexdigest()


def markers(run):
    return dict(re.findall(r'^(XP25_VM_[A-Z0-9_]+)=(-?\d+)\s*$', (run / 'serial.log').read_text(errors='replace').replace('\r', ''), re.M))


def frozen(run):
    checkpoint = json.loads((run / 'checkpoint.json').read_text())
    disk = run / 'disk.qcow2'
    if checkpoint['stage'] != 'normal_shutdown_frozen' or disk.stat().st_mode & 0o222 or sha(disk) != checkpoint['disk_sha256']:
        raise SystemExit(run.name + ' is not a normally stopped, unchanged frozen run')
    return disk, checkpoint['disk_sha256']


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--install-run', type=Path, required=True)
    p.add_argument('--verify-run', type=Path, required=True)
    p.add_argument('--media', type=Path, required=True, help='build/prepare_vm_browser.py output')
    p.add_argument('--name', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    install, verify, media, out = (x.resolve() for x in (a.install_run, a.verify_run, a.media, a.output))
    for path in (install, verify, media, out):
        if not path.is_relative_to(ROOT / '.work'):
            p.error('private .work paths required')
    install_disk, install_sha = frozen(install)
    verify_disk, verify_sha = frozen(verify)
    if json.loads((verify / 'inputs.json').read_text())['base_sha256'] != install_sha or \
            Path(json.loads((verify / 'inputs.json').read_text())['base']).resolve() != install_disk:
        raise SystemExit('the verify run does not boot the install run')
    found = {'install': markers(install), 'verify': markers(verify)}
    for phase, wanted in (('install', INSTALL), ('verify', VERIFY)):
        for key, value in wanted.items():
            if found[phase].get(key) != value:
                raise SystemExit('%s run: %s=%s, expected %s' % (phase, key, found[phase].get(key), value))
    if found['verify'].get('XP25_VM_JSCRIPT_RUN_EXIT') in (None, '0'):
        raise SystemExit('a JScript file still ran')
    manifest = json.loads((media / 'manifest.json').read_text())
    removal = manifest['ie_removal']
    out.mkdir(parents=True, exist_ok=False)
    os.chdir(out)
    installed, absent = [], []
    with lab.partition(verify_disk) as device:
        def read(guest):
            return lab.run(['ntfscat', device, guest])
        for relative, digest in manifest['files'].items():
            if relative.startswith('Supermium/'):
                guest = '/Program Files/' + relative
            elif relative in ('browserctl.exe', 'XP25Browser.exe', 'local.html'):
                guest = '/Program Files/XP25Browser/' + relative
            elif relative in ('help/XP25Help.exe', 'help/XP25Help.exe.manifest'):
                guest = '/Program Files/XP25Help/' + relative.split('/', 1)[1]
            elif relative == 'xp25users.cpl':
                guest = '/WINDOWS/system32/xp25users.cpl'
            else:
                continue
            data = read(guest)
            if hashlib.sha256(data).hexdigest() != digest:
                raise SystemExit('installed file differs: ' + guest)
            installed.append({'guest_path': guest, 'sha256': digest, 'bytes': len(data)})
        if hashlib.sha256(read('/WINDOWS/explorer.exe')).hexdigest() != manifest['patched_explorer_sha256']:
            raise SystemExit('Explorer is not the Help-patched build')
        removed = ['/WINDOWS/system32/' + n for n in removal['system32']] + \
                  ['/WINDOWS/system32/en-US/' + n for n in removal['system32_en_us']] + \
                  ['/WINDOWS/system32/dllcache/' + n for n in removal['dllcache']]
        for guest in removed:
            folder, name = guest.rsplit('/', 1)
            listing = subprocess.run(['ntfsls', device, '-p', folder], capture_output=True, text=True).stdout.split()
            if name.lower() in (entry.lower() for entry in listing):
                raise SystemExit('still present: ' + guest)
            absent.append(guest)
        ie_folder = [e for e in subprocess.run(['ntfsls', device, '-p', '/Program Files/Internet Explorer'], capture_output=True,
                                               text=True).stdout.split() if e not in ('.', '..')]
        if [e.lower() for e in ie_folder] != [n.lower() for n in removal['ie_folder_kept']]:
            raise SystemExit('the IE folder holds ' + str(ie_folder))
    commands = []

    def execute(cmd):
        commands.append(cmd)
        r = subprocess.run(cmd, capture_output=True, text=True)
        lab.record({'argv': cmd, 'returncode': r.returncode, 'stdout': r.stdout, 'stderr': r.stderr})
        if r.returncode:
            raise RuntimeError(r.stderr)
        return r.stdout
    image = out / a.name
    execute(['qemu-img', 'convert', '-f', 'qcow2', '-O', 'qcow2', '-o', 'compat=1.1,lazy_refcounts=off', str(verify_disk), str(image)])
    execute(['qemu-img', 'check', str(image)])
    execute(['qemu-img', 'compare', '-f', 'qcow2', '-F', 'qcow2', str(verify_disk), str(image)])
    info = json.loads(execute(['qemu-img', 'info', '--output=json', str(image)]))
    if info.get('backing-filename'):
        raise SystemExit('standalone image has a backing file')
    image.chmod(0o444)
    result = {'image': str(image), 'image_sha256': sha(image), 'bytes': image.stat().st_size, 'virtual_size': info['virtual-size'],
              'backing_file': None, 'install_run': str(install), 'install_disk_sha256': install_sha,
              'verify_run': str(verify), 'verify_disk_sha256': verify_sha, 'markers': found,
              'media_manifest_sha256': sha(media / 'manifest.json'), 'pin': manifest['pin'], 'internet': manifest['internet'],
              'patched_explorer_sha256': manifest['patched_explorer_sha256'], 'installed_files': installed,
              'removed_files_absent': absent, 'ie_folder': ie_folder, 'commands': commands,
              'limitations': ['Supermium has no renderer sandbox on NT 5.1; XP25Browser runs it with a SAFER Normal User token in a job.',
                              'The intermittent chrome.dll 0x842214 handle CHECK of Milestone 7 is not fixed.',
                              'Help and Support, HTML Help (.chm), the Search Companion, Outlook Express HTML mail and '
                              '.js/.vbs scripts no longer work: their engine is removed.',
                              'Private engineering image; redistribution rights not established.']}
    (out / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'image': str(image), 'sha256': result['image_sha256']}))


if __name__ == '__main__':
    main()
