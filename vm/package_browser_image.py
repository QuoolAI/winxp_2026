#!/usr/bin/env python3
"""Verify a normally stopped installation and flatten a private experimental image.

This does not promote a failed or incomplete compatibility matrix to acceptance.
No package or guest content is uploaded or added to Git.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import xp_lab as lab

ROOT=Path(__file__).resolve().parents[1]

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1<<20),b''):h.update(block)
    return h.hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run',type=Path,required=True)
    p.add_argument('--prepared',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();run=a.run.resolve();prepared=a.prepared.resolve();out=a.output.resolve()
    for path in [run,prepared,out]:
        if not path.is_relative_to(ROOT/'.work'):p.error('private .work paths required')
    checkpoint=json.loads((run/'checkpoint.json').read_text());disk=run/'disk.qcow2'
    if checkpoint['stage']!='normal_shutdown_frozen' or disk.stat().st_mode&0o222:
        p.error('normally stopped, frozen installation required')
    if sha(disk)!=checkpoint['disk_sha256']:raise ValueError('frozen disk changed')
    if 'XP25_IMAGE_INSTALL_EXIT=0' not in (run/'serial.log').read_text():
        raise ValueError('no successful guest installation evidence')
    pin=json.loads((prepared/'manifest.json').read_text())
    out.mkdir(parents=True,exist_ok=False);os.chdir(out)
    rows=[]
    with lab.partition(disk) as device:
        for relative,digest in pin['files'].items():
            if relative.startswith('Supermium/'):
                guest='/Program Files/'+relative
            elif relative in ['browserctl.exe','rollback.cmd','local.html']:
                guest='/Program Files/XP25Browser/'+relative
            else:continue
            data=lab.run(['ntfscat',device,guest]);actual=hashlib.sha256(data).hexdigest()
            if actual!=digest:raise ValueError('installed file changed: '+guest)
            rows.append({'guest_path':guest,'sha256':actual,'bytes':len(data)})
        marker=lab.run(['ntfscat',device,'/Program Files/XP25Browser/installed.ok']).decode().strip()
        if marker!=pin['pin']['sha256']:raise ValueError('installation marker mismatch')
    commands=[]
    def execute(cmd):
        commands.append(cmd);r=subprocess.run(cmd,capture_output=True,text=True)
        lab.record({'argv':cmd,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
        if r.returncode:raise RuntimeError(r.stderr)
        return r.stdout
    image=out/'XP25-Browser-Experimental.qcow2'
    execute(['qemu-img','convert','-f','qcow2','-O','qcow2','-c','-o','compat=1.1,lazy_refcounts=off',str(disk),str(image)])
    execute(['qemu-img','check',str(image)])
    execute(['qemu-img','compare','-f','qcow2','-F','qcow2',str(disk),str(image)])
    info=json.loads(execute(['qemu-img','info','--output=json',str(image)]))
    if info.get('backing-filename'):raise ValueError('standalone image has backing file')
    image.chmod(0o444)
    result={'status':'experimental_unaccepted','acceptance_complete':False,
            'limitations':['Full KVM/TCG regression and restart persistence are not accepted.',
                           'Browser sandbox protection is not established; consult version-specific command/token evidence.',
                           'Shared IE libraries retained; Help and Support loads Trident.',
                           'Private engineering image; redistribution rights not established.'],
            'source_run':str(run),'source_disk_sha256':checkpoint['disk_sha256'],
            'prepared_manifest_sha256':sha(prepared/'manifest.json'),'pin':pin['pin'],
            'installed_files':rows,'commands':commands,'image_info':info,
            'image':str(image),'image_sha256':sha(image)}
    (out/'manifest.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'image':str(image),'sha256':result['image_sha256'],'status':result['status']}))

if __name__=='__main__':main()
