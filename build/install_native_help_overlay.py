#!/usr/bin/env python3
"""Stage a reviewed Help resource in a NEW, unaccepted, unbooted overlay."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from install_branding_overlay import verify_pair
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'vm'))
import xp_lab as lab
def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1<<20),b''):h.update(b)
    return h.hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['base','package','output']:p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--sha256',required=True);p.add_argument('--restore',action='store_true',help='restore the verified original resource in a NEW overlay only');a=p.parse_args();base=a.base.resolve();package=a.package.resolve();out=a.output.resolve()
    if any('.work' not in x.parts for x in [base,package,out]) or base.stat().st_mode&0o222:p.error('frozen private base and private outputs required')
    if sha(base)!=a.sha256:raise ValueError('base changed')
    m=json.loads((package/'manifest.json').read_text());old=Path(m['original_explorer']);new=Path(m['patched_explorer'])
    if sha(old)!=m['original_explorer_sha256'] or sha(new)!=m['patched_explorer_sha256']:raise ValueError('package changed')
    verify_pair(old,new,[[6,46,1033]]);out.mkdir(parents=True,exist_ok=False);os.chdir(out)
    lab.run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',str(base),'disk.qcow2'])
    with lab.partition(out/'disk.qcow2',True) as device:
        original=lab.run(['ntfscat',device,'/WINDOWS/explorer.exe'])
        expected=m['patched_explorer_sha256'] if a.restore else m['original_explorer_sha256']
        if hashlib.sha256(original).hexdigest()!=expected:raise ValueError('unexpected guest Explorer')
        if a.restore:
            backup=lab.run(['ntfscat',device,'/xp25-help-explorer-before.exe'])
            if hashlib.sha256(backup).hexdigest()!=m['original_explorer_sha256']:raise ValueError('invalid recovery copy')
        else:lab.run(['ntfscp','-t',device,str(old),'/xp25-help-explorer-before.exe'])
        replacement=old if a.restore else new
        lab.run(['ntfscp','-t',device,str(replacement),'/WINDOWS/explorer.exe'])
        if lab.run(['ntfscat',device,'/WINDOWS/explorer.exe'])!=replacement.read_bytes():raise ValueError('staging mismatch')
    (out/'disk.qcow2').chmod(0o444);result={'status':'unaccepted_unbooted_help_resource_overlay','restored':a.restore,'base':str(base),'base_sha256':a.sha256,'disk_sha256':sha(out/'disk.qcow2'),'package':str(package),'resource_only':True,'recovery_guest_path':'/xp25-help-explorer-before.exe'};(out/'manifest.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':main()
