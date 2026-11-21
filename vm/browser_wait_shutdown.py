#!/usr/bin/env python3
"""Observe a fixture's actual guest-requested shutdown, then freeze its overlay.

With --xp25-logon the image runs the XP25 Winlogon without automatic logon: at
each boot's logon dialog XP25 (blank password) is logged on, as vm/security_lab.py
does, so the Startup fixture can run. That mode watches the whole run on one QMP
connection, so the shutdown event cannot fall between the marker and the connection."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import xp_lab as lab
ROOT=Path(__file__).resolve().parents[1]

def winlogon_events(text):
    events=[]
    for line in text.splitlines():
        at=line.find('{"xp25_winlogon"')
        if at>=0:
            try:events.append(json.loads(line[at:])['xp25_winlogon'])
            except (ValueError,KeyError):pass
    return events

def shutdown_event(run,event):
    if event.get('event') in ['RESET','GUEST_PANICKED']:raise ValueError('unexpected reset/panic')
    if event.get('event')!='SHUTDOWN':return False
    if event.get('data')!={'guest':True,'reason':'guest-shutdown'}:raise ValueError('unexpected shutdown cause')
    (run/'guest-shutdown-event.json').write_text(json.dumps(event,indent=2)+'\n');return True

def log_on(run,q,deadline,scale):
    """Log XP25 on at the first boot's XP25 Winlogon dialog; return once the session is interactive."""
    attempts=0;sent_at=0.0;sent_results=-1
    while time.time()<deadline:
        time.sleep(2);q.call('query-status')
        for event in q.events:
            lab.record({'event':event})
            if event.get('event') in ('SHUTDOWN','RESET','GUEST_PANICKED'):raise ValueError('guest stopped before logon: '+json.dumps(event))
        q.events.clear()
        text=(run/'serial.log').read_text(errors='replace') if (run/'serial.log').exists() else ''
        events=winlogon_events(text)
        if events.count('session_interactive')>=1:lab.record({'session_interactive_boot':1});return
        results=events.count('gina_logged_out_result')
        if events.count('core_ready')>=1 and (sent_results<0 or (results==sent_results and time.time()-sent_at>40*scale)):
            if sent_results<0:time.sleep(8*scale)
            for name in ('ctrl-a','backspace','ret'):lab.key(q,name);time.sleep(0.3)
            attempts+=1;sent_at,sent_results=time.time(),results;lab.record({'logon_keys_sent':attempts,'boot':1})
            if attempts>8:raise ValueError('logon keys not accepted')
    raise TimeoutError('logon')

def logon_until(run,q,marker,deadline,scale,ui_shutdown=False):
    """Log on at each boot's XP25 Winlogon dialog until the marker appears; then watch for the shutdown.
    With ui_shutdown, a guest still running 60 s after the marker is turned off through
    Start > Turn Off Computer > Turn Off (shutdown.exe has no InitShutdown server under the XP25 Winlogon)."""
    logons=attempts=0;sent_at=0.0;sent_results=-1;marked_at=None;ui_tries=0
    while time.time()<deadline:
        time.sleep(2);q.call('query-status')
        text=(run/'serial.log').read_text(errors='replace') if (run/'serial.log').exists() else ''
        while q.events:
            event=q.events.pop(0);lab.record({'event':event})
            if shutdown_event(run,event):
                if marker not in text:raise ValueError('guest shut down before '+marker)
                return
        if marker in text:
            marked_at=marked_at or time.time()
            if ui_shutdown and time.time()-marked_at>(60+90*ui_tries)*scale:
                if ui_tries>=6:raise ValueError('Turn Off Computer keys not accepted')
                for name,pause in (('esc',1),('ctrl-esc',2),('u',3),('u',1)):lab.key(q,name);time.sleep(pause*scale)
                ui_tries+=1;lab.record({'ui_shutdown_keys_sent':ui_tries})
            continue
        # One logon per boot: core_ready, then the MSGINA dialog. Keys are repeated only
        # while MSGINA has not reported a result for the previous attempt (lost keys).
        events=winlogon_events(text)
        ready,interactive,results=events.count('core_ready'),events.count('session_interactive'),events.count('gina_logged_out_result')
        if interactive>=ready and ready>logons:
            logons,attempts,sent_at,sent_results=ready,0,0.0,-1;lab.record({'session_interactive_boot':ready})
        elif ready>logons and (sent_results<0 or (results==sent_results and time.time()-sent_at>40*scale)):
            if sent_results<0:time.sleep(8*scale)
            for name in ('ctrl-a','backspace','ret'):lab.key(q,name);time.sleep(0.3)
            attempts+=1;sent_at,sent_results=time.time(),results;lab.record({'logon_keys_sent':attempts,'boot':ready})
            if attempts>8:raise ValueError('logon keys not accepted')
    raise TimeoutError(marker)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',type=Path,required=True);p.add_argument('--marker',required=True);p.add_argument('--timeout',type=int,default=900)
    p.add_argument('--xp25-logon',action='store_true',help='log on XP25 (blank password) at the XP25 Winlogon dialog of each boot')
    p.add_argument('--ui-shutdown',action='store_true',help='with --xp25-logon: turn the guest off from the Start menu if it is still running 60 s after the marker')
    a=p.parse_args();run=a.run.resolve()
    if not run.is_relative_to(ROOT/'.work'):p.error('private .work run required')
    if a.xp25_logon:
        os.chdir(run)
        tcg=json.loads(Path('inputs.json').read_text()).get('mode')=='tcg'
        with lab.QMP() as q:logon_until(run,q,a.marker,time.time()+a.timeout*(3 if tcg else 1),6 if tcg else 1,a.ui_shutdown)
        subprocess.run([sys.executable,str(ROOT/'vm/xp_lab.py'),str(run),'finish'],check=True)
        print(run);return
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
            if shutdown_event(run,event):break
    subprocess.run([sys.executable,str(ROOT/'vm/xp_lab.py'),str(run),'finish'],check=True)
    print(run)
if __name__=='__main__':main()
