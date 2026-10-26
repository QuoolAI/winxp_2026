#!/usr/bin/env python3
"""Create and boot a unique browser-test overlay of a frozen engineering image.
All offline edits target the new overlay. Private QMP/serial paths, distinct MAC,
no VNC, and a fresh network namespace without an uplink.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import secrets
import sys
import time
import xp_lab as lab
ROOT=Path(__file__).resolve().parents[1]

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1<<22),b''):h.update(b)
    return h.hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base',type=Path,required=True);p.add_argument('--sha256',required=True)
    p.add_argument('--media',type=Path,required=True);p.add_argument('--name',required=True)
    p.add_argument('--mode',choices=['up','mp','tcg'],required=True)
    p.add_argument('--memory',type=int,default=1024)
    p.add_argument('--vga',choices=['std','cirrus','vmware'],default='std')
    p.add_argument('--run-root',type=Path,default=ROOT/'.work/browser-20261025/runs')
    p.add_argument('--root-suite',action='store_true',help='stage at volume root for an original SP3 control without C:\\xp25')
    p.add_argument('--gdb',action='store_true',help='private UNIX GDB socket for a diagnostic overlay only')
    p.add_argument('--suite',type=Path)
    p.add_argument('--gateway',type=Path)
    a=p.parse_args()
    if not a.name or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in a.name):p.error('simple unique name required')
    base=a.base.resolve();iso=a.media.resolve()
    suite_path=a.suite.resolve() if a.suite else None
    gateway=a.gateway.resolve() if a.gateway else None
    if '.work' not in base.parts or '.work' not in iso.parts or base.stat().st_mode&0o222:p.error('private frozen base and private media required')
    run_root=a.run_root.resolve()
    if not run_root.is_relative_to(ROOT/'.work') or not 256<=a.memory<=3072:p.error('private run root and 256..3072 MiB required')
    out=run_root/a.name;out.mkdir(parents=True,exist_ok=False)
    os.chdir(out)
    actual=sha(base)
    if actual!=a.sha256:raise ValueError('base hash mismatch')
    mac='52:54:07:'+':'.join(hashlib.sha256(a.name.encode()).hexdigest()[i:i+2] for i in (0,2,4))
    suite=r'''@echo off
mkdir C:\xp25\browser 2>nul
echo XP25_BROWSER_INSTALL_BEGIN > COM1
call D:\install.cmd > C:\xp25\browser\install.log 2>&1
echo XP25_BROWSER_INSTALL_EXIT=%ERRORLEVEL% > COM1
"C:\Program Files\XP25Browser\browserctl.exe" inventory > C:\xp25\browser\before.txt
start "" "C:\Program Files\Supermium\chrome.exe" --no-first-run --classic-omnibox --classic-omnibox-border --compact-ui --enable-features=SupermiumCustomTabs --enable-logging --log-file=C:\xp25\browser\chrome.log "file:///C:/Program%%20Files/XP25Browser/local.html"
echo XP25_BROWSER_LAUNCH_REQUESTED > COM1
del "%USERPROFILE%\Start Menu\Programs\Startup\XP25BrowserSuite.cmd"
'''
    suite_bytes=suite_path.read_bytes() if suite_path else suite.replace('\n','\r\n').encode()
    suite_bytes=suite_bytes.replace(b'__SLOW__',b'slow' if a.mode=='tcg' else b'')
    secret=secrets.token_hex(32) if b'__PROVIDER_SECRET__' in suite_bytes else None
    if secret:
        suite_bytes=suite_bytes.replace(b'__PROVIDER_SECRET__',secret.encode())
        (out/'gateway-clients.json').write_text(json.dumps({'xp25':{'secret_hex':secret}})+'\n')
    (out/'browser-suite.cmd').write_bytes(suite_bytes)
    target='/XP25BrowserDiagSuite.cmd' if a.root_suite else '/xp25/browser-suite.cmd'
    (out/'XP25BrowserSuite.cmd').write_bytes(('@call C:'+target.replace('/','\\')+'\r\n').encode())
    lab.run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',base,'disk.qcow2'])
    with lab.partition(out/'disk.qcow2',True) as device:
        for target,source in {target:out/'browser-suite.cmd','/Documents and Settings/XP25/Start Menu/Programs/Startup/XP25BrowserSuite.cmd':out/'XP25BrowserSuite.cmd'}.items():
            lab.run(['ntfscp','-t',device,source,target])
            if lab.run(['ntfscat',device,target])!=source.read_bytes():raise ValueError('staging mismatch')
    (out/'inputs.json').write_text(json.dumps({'base':str(base),'base_sha256':actual,'media':str(iso),'media_sha256':sha(iso),'mode':a.mode,'mac':mac,'memory_mib':a.memory,'vga':a.vga,'root_suite':a.root_suite,'suite_sha256':hashlib.sha256(suite_bytes).hexdigest()},indent=2)+'\n')
    command=['qemu-system-i386','-name',a.name,'-machine','pc-i440fx-8.2'+(',kernel-irqchip=on' if a.mode!='tcg' else ''),'-accel','tcg,thread=single' if a.mode=='tcg' else 'kvm','-cpu','qemu32','-m',str(a.memory),'-smp','2' if a.mode=='mp' else '1','-nodefaults','-nic','none','-vga','std','-display','none','-monitor','none','-qmp','unix:qmp.sock,server=on,wait=off','-serial','file:serial.log','-rtc','base=localtime','-drive','file=disk.qcow2,format=qcow2,if=ide,index=0','-drive','file='+str(iso)+',format=raw,readonly=on,if=ide,index=2,media=cdrom','-boot','order=c','-pidfile','qemu.pid','-no-reboot','-no-shutdown','-S']
    command[command.index('-vga')+1]=a.vga
    if a.gdb:command.extend(['-gdb','unix:gdb.sock,server=on,wait=off'])
    (out/'qemu-command.json').write_text(json.dumps(command,indent=2)+'\n')
    wrapper=['unshare','--user','--map-root-user','--net',sys.executable,str(ROOT/'vm/browser_network.py'),'qemu-command.json','--parent-netns',os.readlink('/proc/self/ns/net'),'--mac',mac,'--fixtures',str(ROOT/'components/browser')]
    if gateway:wrapper.extend(['--gateway',str(gateway)])
    if secret:wrapper.extend(['--provider-clients',str(out/'gateway-clients.json'),'--mock-key','sk-xp25-isolated-test-'+secrets.token_hex(8)])
    with (out/'namespace.log').open('w') as f:proc=subprocess.Popen(wrapper,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
    lab.record({'argv':wrapper,'pid':proc.pid})
    for _ in range(300):
        if proc.poll() is not None:raise RuntimeError((out/'namespace.log').read_text())
        if (out/'qmp.sock').exists():
            try:
                with lab.QMP() as q:q.call('cont')
                break
            except (ConnectionRefusedError,EOFError):pass
        time.sleep(.1)
    else:raise TimeoutError('QMP')
    lab.checkpoint(stage='browser_guest_booting',namespace_pid=proc.pid,base_sha256=actual)
    print(out)
if __name__=='__main__':main()
