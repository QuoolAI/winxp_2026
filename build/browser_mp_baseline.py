#!/usr/bin/env python3
"""Create an independent browser test input with the already verified native
MP kernel/HAL pair. The accepted clean AI image and MP run remain read-only.
This is a test candidate, not an accepted OS image or a kernel implementation
change. Only two guest files are written, with before/after bytes verified.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'vm'))
import xp_lab as lab
PAIRS={'xp25krnl.exe':'e571ae5ec54ef5ccfca71a0e9cd578d6020f0c2ff04692b4ef247a12607ce6b0',
       'xp25hal.dll':'69ca3e7109b94c3f1505d681ded1ebc04df448668a67069bc4e847f3116756e6'}

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1<<22),b''):h.update(b)
    return h.hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base',type=Path,required=True);p.add_argument('--base-sha256',required=True)
    p.add_argument('--mp-run',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();base=a.base.resolve();run=a.mp_run.resolve();out=a.output.resolve()
    if not out.is_relative_to(ROOT/'.work'):p.error('private .work output required')
    mp=run/'disk.qcow2';checkpoint=json.loads((run/'checkpoint.json').read_text())
    if base.stat().st_mode&0o222 or mp.stat().st_mode&0o222 or checkpoint.get('stage')!='normal_shutdown_frozen':p.error('frozen inputs required')
    if sha(base)!=a.base_sha256 or sha(mp)!=checkpoint['disk_sha256']:raise ValueError('input hash mismatch')
    out.mkdir(parents=True,exist_ok=False);os.chdir(out);files={}
    with lab.partition(mp,False) as device:
        for name,expected in PAIRS.items():
            data=lab.run(['ntfscat',device,'/WINDOWS/system32/'+name])
            if hashlib.sha256(data).hexdigest()!=expected:raise ValueError('unverified MP component '+name)
            (out/name).write_bytes(data)
    lab.run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',base,'disk.qcow2'])
    with lab.partition(out/'disk.qcow2',True) as device:
        for name,expected in PAIRS.items():
            target='/WINDOWS/system32/'+name;before=lab.run(['ntfscat',device,target])
            (out/('before-'+name)).write_bytes(before)
            lab.run(['ntfscp','-t',device,out/name,target])
            after=lab.run(['ntfscat',device,target])
            if after!=(out/name).read_bytes():raise ValueError('guest replacement mismatch')
            files[target]={'before_sha256':hashlib.sha256(before).hexdigest(),'after_sha256':expected}
    (out/'image-check.log').write_bytes(lab.run(['qemu-img','check','disk.qcow2']))
    (out/'disk.qcow2').chmod(0o444)
    result={'role':'unaccepted_MP_pair_browser_test_candidate','base':str(base),'base_sha256':a.base_sha256,'MP_run':str(run),'MP_disk_sha256':checkpoint['disk_sha256'],'guest_changes':files,'boot_configuration_changed':False,'image_sha256':sha(out/'disk.qcow2')}
    (out/'manifest.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()
