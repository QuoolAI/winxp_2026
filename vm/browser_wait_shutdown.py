#!/usr/bin/env python3
"""Observe a fixture's actual guest-requested shutdown, then freeze its overlay."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import xp_lab as lab
ROOT=Path(__file__).resolve().parents[1]

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',type=Path,required=True);p.add_argument('--marker',required=True);p.add_argument('--timeout',type=int,default=900);a=p.parse_args();run=a.run.resolve()
    if not run.is_relative_to(ROOT/'.work'):p.error('private .work run required')
    deadline=time.time()+a.timeout
    while time.time()<deadline:
        if (run/'serial.log').exists() and a.marker in (run/'serial.log').read_text(errors='replace'):break
        time.sleep(.5)
    else:raise TimeoutError(a.marker)
    os.chdir(run)
    with lab.QMP() as q:
        q.s.settimeout(90);pending=list(q.events)
        while True:
            event=pending.pop(0) if pending else json.loads(q.f.readline());lab.record({'event':event})
            if event.get('event') in ['RESET','GUEST_PANICKED']:raise ValueError('unexpected reset/panic')
            if event.get('event')=='SHUTDOWN':
                if event.get('data')!={'guest':True,'reason':'guest-shutdown'}:raise ValueError('unexpected shutdown cause')
                (run/'guest-shutdown-event.json').write_text(json.dumps(event,indent=2)+'\n');break
    subprocess.run([sys.executable,str(ROOT/'vm/xp_lab.py'),str(run),'finish'],check=True)
    print(run)
if __name__=='__main__':main()
