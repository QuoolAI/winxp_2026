#!/usr/bin/env python3
"""Create the MerlinAI demonstration VM and enroll an XP25 VM with MerlinAI.

  enroll_vm.py create --dir DIR --image IMG --name XP25-MerlinAI-Demo [--mac 52:54:00:25:00:09] [--ip 10.25.0.27]
      a writable reflink copy of IMG, a DHCP reservation on XP25-Isolated, the
      xp25-merlin NIC filter (relay and deployment-agent ports only) and a
      libvirt domain with the XP25 hardware profile (1 vCPU, 1 GiB, IDE, RTL8139,
      VNC on 127.0.0.1, COM1 to DIR/serial.log). Nothing else changes.
  enroll_vm.py enroll --dir DIR --installation ID (--builder-key HEX | --builder-key-file FILE) --agent-config FILE
                      [--disk-dir DIR] [--builder-agent NAME --builder-agent-key-file FILE] [--keyboard]
      with the VM shut off: a new deployment key (DIR/deploy.key, 0600), the
      installation added to the deployment agent's configuration, and a one-time
      logon script staged into the guest that runs
      MerlinAI.exe /configure <relay> <agent> ID <builder key> <deploy key> and
      deletes itself. --disk-dir names where the VM's disks live when that is
      not DIR (the agent creates overlays only there); --builder-agent gives the
      installation its own builder credential in the agent. Keys cross into the
      guest only this way or by typing them
      into MerlinAI Settings; the staged file's clusters may persist in NTFS free
      space after deletion (documented limitation of offline enrollment).

      SECURITY: ntfscp gives the staged files no security descriptor, so until the
      first XP25 logon runs and deletes them, every account on the VM can read the
      keys. Use offline enrollment only for a VM no other account can log on to.
      --keyboard instead needs the VM running with an administrator's console
      window focused: it types MerlinAI.exe /configure ... there through libvirt
      (keys are not logged), clears the console and closes it. Nothing is written
      to the guest's disk except MerlinAI's protected Credentials key."""
import argparse
import json
import os
import re
from pathlib import Path
import secrets
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'vm'))
VIRSH = ['virsh', '-c', 'qemu:///system']

DOMAIN = """<domain type='kvm'>
  <name>{name}</name>
  <description>MerlinAI demonstration VM (Milestone 9): the XP25 M9 image with MerlinAI ({image_sha}) for the end-to-end self-repair demonstration. Network: XP25-Isolated, filter xp25-merlin (MerlinAI relay 8740 and deployment agent 8746 on 10.25.0.1 only). System disk managed by the MerlinAI deployment agent after enrollment. Created by components/merlin/host/enroll_vm.py.</description>
  <memory unit='KiB'>1048576</memory>
  <vcpu placement='static'>1</vcpu>
  <os><type arch='i686' machine='pc-i440fx-8.2'>hvm</type><boot dev='hd'/></os>
  <features><acpi/><apic/></features>
  <cpu mode='custom' match='exact' check='none'><model fallback='forbid'>qemu32</model></cpu>
  <clock offset='localtime'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>preserve</on_crash>
  <devices>
    <emulator>/usr/bin/qemu-system-i386</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' cache='writeback'/>
      <source file='{disk}'/>
      <target dev='hda' bus='ide'/>
    </disk>
    <controller type='ide' index='0'/>
    <controller type='usb' index='0' model='piix3-uhci'/>
    <interface type='network'>
      <mac address='{mac}'/>
      <source network='XP25-Isolated'/>
      <model type='rtl8139'/>
      <filterref filter='xp25-merlin'>
        <parameter name='GATEWAY_IP' value='10.25.0.1'/>
        <parameter name='RELAY_PORT' value='8740'/>
        <parameter name='DEPLOY_PORT' value='8746'/>
      </filterref>
    </interface>
    <serial type='file'><source path='{dir}/serial.log'/><target type='isa-serial' port='0'/></serial>
    <console type='file'><source path='{dir}/serial.log'/><target type='serial' port='0'/></console>
    <input type='tablet' bus='usb'/>
    <input type='mouse' bus='ps2'/>
    <input type='keyboard' bus='ps2'/>
    <graphics type='vnc' port='-1' autoport='yes' listen='127.0.0.1'><listen type='address' address='127.0.0.1'/></graphics>
    <audio id='1' type='none'/>
    <video><model type='vga' vram='16384' heads='1' primary='yes'/></video>
    <memballoon model='none'/>
  </devices>
</domain>
"""

ENROLL = r'''@echo off
rem MerlinAI enrollment (one time): endpoints and credentials for this installation, then remove this file.
"C:\Program Files\XP25\MerlinAI\MerlinAI.exe" /configure http://10.25.0.1:8740 http://10.25.0.1:8746 {installation} {builder_key} {deploy_key}
del "%USERPROFILE%\Start Menu\Programs\Startup\XP25MerlinEnroll.cmd"
del C:\xp25\merlin-enroll.cmd & goto :eof
'''


def run(cmd, check=True):
    return subprocess.run([str(c) for c in cmd], check=check, capture_output=True, text=True)


def create(args):
    d = args.dir.resolve()
    d.mkdir(parents=True, exist_ok=False)
    disk = d / (args.name + '.qcow2')
    run(['cp', '--reflink=always', args.image.resolve(), disk])
    disk.chmod(0o644)
    image_sha = json.loads((args.image.resolve().parent / 'manifest.json').read_text())['image_sha256']
    hosts = run(VIRSH + ['net-dumpxml', 'XP25-Isolated']).stdout
    if args.mac.lower() not in hosts.lower():
        run(VIRSH + ['net-update', 'XP25-Isolated', 'add', 'ip-dhcp-host',
                     "<host mac='%s' name='xp25-merlin-demo' ip='%s'/>" % (args.mac, args.ip), '--live', '--config'])
    if ' xp25-merlin ' not in run(VIRSH + ['nwfilter-list']).stdout + ' ':
        run(VIRSH + ['nwfilter-define', HERE / 'xp25-merlin.nwfilter.xml'])
    xml = DOMAIN.format(name=args.name, disk=disk, mac=args.mac, dir=d, image_sha=image_sha[:16])
    (d / 'domain.xml').write_text(xml)
    run(VIRSH + ['define', d / 'domain.xml'])
    record = {'name': args.name, 'disk': str(disk), 'image': str(args.image.resolve()), 'image_sha256': image_sha, 'mac': args.mac,
              'ip': args.ip}
    (d / 'vm.json').write_text(json.dumps(record, indent=1) + '\n')
    print(json.dumps(record))


TYPED = {' ': ['KEY_SPACE'], '\\': ['KEY_BACKSLASH'], '.': ['KEY_DOT'], '/': ['KEY_SLASH'], '-': ['KEY_MINUS'],
         ':': ['KEY_LEFTSHIFT', 'KEY_SEMICOLON'], '"': ['KEY_LEFTSHIFT', 'KEY_APOSTROPHE']}


def type_line(domain, text):
    """Type one line into the guest through libvirt; nothing is logged (the line can hold keys)."""
    for c in text + '\n':
        if c == '\n':
            keys = ['KEY_ENTER']
        elif c.isascii() and c.isupper():
            keys = ['KEY_LEFTSHIFT', 'KEY_' + c]
        elif c.isascii() and c.isalnum():
            keys = ['KEY_' + c.upper()]
        else:
            keys = TYPED[c]
        subprocess.run(VIRSH + ['send-key', domain, '--codeset', 'linux', '--holdtime', '60'] + keys, check=True, capture_output=True)
        time.sleep(0.12)


def enroll(args):
    import xp_lab as lab
    d = args.dir.resolve()
    vm = json.loads((d / 'vm.json').read_text())
    state = run(VIRSH + ['domstate', vm['name']]).stdout.strip()
    if args.keyboard and state != 'running':
        raise SystemExit('keyboard enrollment needs the VM running with an administrator console focused')
    if not args.keyboard and state != 'shut off':
        raise SystemExit('shut the VM down first')
    if args.builder_key_file:
        text = args.builder_key_file.read_text().strip()
        args.builder_key = json.loads(text)['builder_key'] if text.startswith('{') else text
    if not args.builder_key or not all(c in '0123456789abcdef' for c in args.builder_key) or len(args.builder_key) != 64:
        raise SystemExit('the builder key is 64 lowercase hex characters')
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', args.installation):
        raise SystemExit('bad installation id')
    deploy_key = secrets.token_hex(32)
    key_file = d / 'deploy.key'
    fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(deploy_key + '\n')
    cfg_path = args.agent_config.resolve()
    cfg = json.loads(cfg_path.read_text())
    entry = {'deploy_key_file': str(key_file), 'domain': vm['name'],
             'disk_dir': str(args.disk_dir.resolve() if args.disk_dir else d), 'client': vm['ip']}
    if args.builder_agent:
        entry.update(builder_agent=args.builder_agent, builder_key_file=str(args.builder_agent_key_file.resolve()))
    cfg.setdefault('installations', {})[args.installation] = entry
    cfg_path.write_text(json.dumps(cfg, indent=1) + '\n')
    if args.keyboard:
        type_line(vm['name'], '"C:\\Program Files\\XP25\\MerlinAI\\MerlinAI.exe" /configure %s %s %s %s %s'
                  % (args.relay, args.agent_url, args.installation, args.builder_key, deploy_key))
        time.sleep(5)
        type_line(vm['name'], 'cls')                   # the keys leave the screen
        time.sleep(1)
        type_line(vm['name'], 'exit')
        print(json.dumps({'installation': args.installation, 'deploy_key_file': str(key_file), 'agent_config': str(cfg_path),
                          'typed': 'MerlinAI.exe /configure (keys not logged)'}))
        return
    work = d / 'enroll'
    work.mkdir(exist_ok=True)
    script = work / 'merlin-enroll.cmd'
    fd = os.open(script, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(ENROLL.format(installation=args.installation, builder_key=args.builder_key, deploy_key=deploy_key).replace('\n', '\r\n'))
    startup = work / 'XP25MerlinEnroll.cmd'
    startup.write_bytes(b'@call C:\\xp25\\merlin-enroll.cmd\r\n')
    disk = Path(run(VIRSH + ['dumpxml', '--inactive', vm['name']]).stdout.split("<source file='")[1].split("'")[0])
    cwd = os.getcwd()
    os.chdir(work)
    try:
        with lab.partition(disk, True) as device:
            lab.run(['ntfscp', '-t', device, script, '/xp25/merlin-enroll.cmd'])
            lab.run(['ntfscp', '-t', device, startup, '/Documents and Settings/XP25/Start Menu/Programs/Startup/XP25MerlinEnroll.cmd'])
    finally:
        os.chdir(cwd)
    script.unlink()                                   # the keys stay only in deploy.key (host) and the guest
    print('warning: the staged enrollment script has no access control until the first XP25 logon deletes it; '
          'use this only for a VM no other account can log on to', file=sys.stderr)
    print(json.dumps({'installation': args.installation, 'deploy_key_file': str(key_file), 'agent_config': str(cfg_path),
                      'staged': ['/xp25/merlin-enroll.cmd', 'Startup/XP25MerlinEnroll.cmd']}))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('create')
    p.add_argument('--dir', type=Path, required=True)
    p.add_argument('--image', type=Path, required=True)
    p.add_argument('--name', default='XP25-MerlinAI-Demo')
    p.add_argument('--mac', default='52:54:00:25:00:09')
    p.add_argument('--ip', default='10.25.0.27')
    p = sub.add_parser('enroll')
    p.add_argument('--dir', type=Path, required=True)
    p.add_argument('--installation', required=True)
    p.add_argument('--builder-key')
    p.add_argument('--builder-key-file', type=Path, help='the JSON printed by builder_vm.py register, or the key alone')
    p.add_argument('--keyboard', action='store_true')
    p.add_argument('--relay', default='http://10.25.0.1:8740')
    p.add_argument('--agent-url', default='http://10.25.0.1:8746')
    p.add_argument('--agent-config', type=Path, required=True)
    p.add_argument('--disk-dir', type=Path)
    p.add_argument('--builder-agent')
    p.add_argument('--builder-agent-key-file', type=Path)
    args = parser.parse_args()
    return {'create': create, 'enroll': enroll}[args.action](args) or 0


if __name__ == '__main__':
    sys.exit(main())
