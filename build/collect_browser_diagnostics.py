#!/usr/bin/env python3
"""Collect only diagnostic dumps/logs from a frozen private test guest.
Never extracts the browser Profile directory, cookies, history or passwords.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'vm'))
import xp_lab as lab

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    run=a.run.resolve();out=a.output.resolve();disk=run/'disk.qcow2'
    if not run.is_relative_to(ROOT/'.work') or not out.is_relative_to(ROOT/'.work') or disk.stat().st_mode&0o222:p.error('private frozen test image required')
    out.mkdir(parents=True,exist_ok=False);os.chdir(out);rows=[]
    with lab.partition(disk) as device:
        names=lab.run(['ntfsls','-p','/xp25/browserdiag',device]).decode().splitlines()
        for name in names:
            if Path(name).name!=name or not (name.endswith(('.dmp','.stack','.log')) or name=='after.txt'):continue
            data=lab.run(['ntfscat',device,'/xp25/browserdiag/'+name]);(out/name).write_bytes(data)
            rows.append({'name':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
    (out/'manifest.json').write_text(json.dumps({'run':str(run),'files':rows,'profile_extracted':False},indent=2)+'\n');print(json.dumps({'files':len(rows),'bytes':sum(r['bytes'] for r in rows)}))
if __name__=='__main__':main()
