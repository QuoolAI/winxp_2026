#!/usr/bin/env python3
"""Run independent browser KVM/TCG regressions with bounded, private fixtures.
No registered domain is accessed. Every mode has a new overlay, MAC and network
namespace. Evidence is retained on failures and no failure is promoted to a pass.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request
import xp_lab as lab
ROOT=Path(__file__).resolve().parents[1]

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1<<22),b''):h.update(b)
    return h.hexdigest()

def serial(run):return (run/'serial.log').read_text(errors='replace').replace('\r','') if (run/'serial.log').exists() else ''

def serial_markers(text):
    return dict(re.findall(r'^([A-Z0-9_]+)=(-?\d+)\s*$',text,re.M))

def status(run,stage,**fields):
    row={'stage':stage,'time':time.time(),**fields}
    (run/'matrix-progress.json').write_text(json.dumps(row,indent=2)+'\n')
    print(run.name+': '+stage,flush=True)

def wait_until(run,predicate,label,timeout=900):
    deadline=time.time()+timeout
    while time.time()<deadline:
        if predicate():return
        time.sleep(1)
    raise TimeoutError(label)

def client(run,namespace,phase,extra,cdp_timeout=45):
    out=run/phase
    attempt=1
    while out.exists():
        attempt+=1;out=run/(phase+'-'+str(attempt))
    # The bridge can accept before Chromium's loopback listener is ready.
    probe=['nsenter','--target',str(namespace),'--user','--net','--preserve-credentials',sys.executable,'-c',
           'import urllib.request,json; op=urllib.request.build_opener(urllib.request.ProxyHandler({})); r=json.load(op.open("http://10.25.0.10:9223/json/version",timeout=3)); assert r.get("webSocketDebuggerUrl")']
    deadline=time.time()+240
    while True:
        ready=subprocess.run(probe,capture_output=True)
        if ready.returncode==0:break
        if time.time()>deadline:raise TimeoutError('Chromium DevTools readiness')
        time.sleep(2)
    command=['nsenter','--target',str(namespace),'--user','--net','--preserve-credentials',sys.executable,str(ROOT/'vm/browser_cdp.py'),'--output',str(out),'--close-browser',*extra]
    env=dict(os.environ,XP25_CDP_TIMEOUT=str(cdp_timeout))
    with (run/(out.name+'.log')).open('w') as log:
        process=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT,env=env)
        deadline=time.time()+480
        captured=False
        while process.poll() is None:
            if not captured and (out/'ready-for-screenshot.json').exists():
                subprocess.run([sys.executable,str(ROOT/'vm/xp_lab.py'),str(run),'screen','supermium-local'],capture_output=True,check=True)
                captured=True
            if time.time()>deadline:
                process.terminate();process.wait(timeout=10);raise TimeoutError(phase)
            time.sleep(.5)
    result=json.loads((out/'result.json').read_text())
    if process.returncode or not result.get('passed'):raise ValueError(phase+' failed: '+str(result.get('error',result.get('checks'))))
    return result,str(out/'result.json')

def execute(a,mode):
    name=a.prefix+'-'+mode;run=a.run_root/name
    command=[sys.executable,str(ROOT/'vm/browser_lab.py'),'--base',str(a.base),'--sha256',a.sha256,'--media',str(a.media/'browser-tests.iso'),'--suite',str(a.media/'suite.cmd'),'--name',name,'--mode',mode,'--gateway',str(a.gateway),'--run-root',str(a.run_root),'--memory',str(a.memory)]
    if not a.resume:
        with (a.output/(mode+'-launch.log')).open('w') as f:subprocess.run(command,stdout=f,stderr=subprocess.STDOUT,check=True)
    else:
        inputs=json.loads((run/'inputs.json').read_text())
        if inputs['base_sha256']!=a.sha256 or inputs['mode']!=mode or inputs['media_sha256']!=sha(a.media/'browser-tests.iso'):
            raise ValueError('resume input contract mismatch')
    report={'mode':mode,'run':str(run),'launch_command':command,'passed':False}
    try:
        status(run,'waiting_for_browser')
        wait_until(run,lambda:'XP25_BROWSER_CDP_STARTING' in serial(run),'browser startup',1200)
        namespace=json.loads((run/'checkpoint.json').read_text())['namespace_pid']
        time.sleep(4)
        status(run,'browser_tests')
        previous=[]
        if a.resume and 'XP25_BROWSER_PERSISTENCE_STARTING' in serial(run):
            for f in run.glob('cdp-browser*/result.json'):
                result=json.loads(f.read_text())
                if result.get('passed'):previous.append((f.stat().st_mtime,f,result))
        if previous:
            _,f,report['browser']=max(previous,key=lambda row:row[0]);browser_evidence=str(f)
        else:
            report['browser'],browser_evidence=client(run,namespace,'cdp-browser',['--https','--policy'],cdp_timeout=240 if mode=='tcg' else 45)
        wait_until(run,lambda:'XP25_BROWSER_PERSISTENCE_STARTING' in serial(run),'browser relaunch',120)
        time.sleep(4)
        status(run,'profile_and_settings_persistence')
        report['persistence'],persistence_evidence=client(run,namespace,'cdp-persistence',['--persistence'],cdp_timeout=240 if mode=='tcg' else 45)
        status(run,'windows_and_ai_regressions')
        wait_until(run,lambda:'XP25_BROWSER_SUITE_DONE' in serial(run),'regression suite',1800 if mode=='tcg' else 900)
        os.chdir(run)
        # The batch script gives this listener five seconds before shutdown.exe.
        with lab.QMP() as q:
            q.s.settimeout(90)
            pending=list(q.events)
            while True:
                event=pending.pop(0) if pending else json.loads(q.f.readline())
                lab.record({'event':event})
                if event.get('event') in ('RESET','GUEST_PANICKED'):raise ValueError('unexpected guest reset/panic')
                if event.get('event')=='SHUTDOWN':
                    if event.get('data')!={'guest':True,'reason':'guest-shutdown'}:raise ValueError('unexpected shutdown cause')
                    (run/'guest-shutdown-event.json').write_text(json.dumps(event,indent=2)+'\n');break
        # Avoid process-wide cwd changes in threaded jobs: use CLI finalization.
        subprocess.run([sys.executable,str(ROOT/'vm/xp_lab.py'),str(run),'finish'],capture_output=True,check=True)
        text=serial(run)
        markers=serial_markers(text)
        expected=['XP25_BROWSER_INSTALL_EXIT','XP25_BROWSER_SHELL_EXIT','XP25_BROWSER_PROCESS_EXIT','XP25_BROWSER_REOPEN_EXIT','XP25_BROWSER_AI_EXIT','XP25_BROWSER_PROVIDER_EXIT','MSI_BUILD_EXIT','MSI_INSTALL_EXIT','MSI_INSTALLED_STATE_EXIT','MSI_UNINSTALL_EXIT','MSI_UNINSTALLED_STATE_EXIT']
        checks={key:markers.get(key)=='0' for key in expected}
        checks['rejected_shortcut_scheme']=markers.get('XP25_SHELLEXECUTE_REJECTED_SCHEME')=='87'
        for kind in ['HTTP','HTTPS','HTML','HTM','URL']:checks['ShellExecute_'+kind]=markers.get('XP25_SHELLEXECUTE_'+kind)=='0'
        receipts=[json.loads(row)['result'] for row in (run/'browser-js-results.jsonl').read_text().splitlines()]
        for kind,source in [('HTTP','http://xp25.test:8080/local.html?case=shell-http'),
                            ('HTML','file:///C:/Program%20Files/XP25Browser/local.html'),
                            ('HTM','file:///D:/fixture.htm'),
                            ('URL','http://xp25.test:8080/local.html?case=shell-url')]:
            checks['rendered_ShellExecute_'+kind]=any(r.get('source')==source and r.get('checks') and all(r['checks'].values()) for r in receipts)
        checks['guest_shutdown']=(run/'guest-shutdown-event.json').exists()
        cases=[]
        for row in text.splitlines():
            try:
                case=json.loads(row)
                if isinstance(case,dict):cases.append(case)
            except (ValueError,TypeError):pass
        checks['all_serial_case_results_pass']=not any(c.get('status')=='fail' for c in cases) and 'BROWSER_CASE FAIL' not in text
        checks['all_recorded_probe_exits_zero']=all(value=='0' for key,value in markers.items() if key.endswith('_EXIT') and key!='XP25_SHELLEXECUTE_REJECTED_SCHEME')
        report['unverified_probe_cases']=[c for c in cases if c.get('status')=='not_tested']
        # Preserve explicit gaps even when the implemented regression probes pass.
        checks['full_regression_coverage']=not report['unverified_probe_cases']
        checks['ai_62_cases']=bool(re.search(r'AI_PROBE_COMPLETE passes=55 failures=0',text)) and bool(re.search(r'AI_PROBE_COMPLETE passes=7 failures=0',text))
        report['checks']=checks;report['passed']=all(checks.values())
        report['evidence_sha256']={str(f.relative_to(run)):sha(f) for f in [run/'serial.log',run/'guest-shutdown-event.json',Path(browser_evidence),Path(persistence_evidence),run/'checkpoint.json']}
        status(run,'passed' if report['passed'] else 'regression_failures',checks=checks)
    except Exception as e:
        report['error']={'type':type(e).__name__,'message':str(e)}
        status(run,'failed',error=report['error'])
    destination=run/'browser-results.json'
    if destination.exists():
        n=1
        while (run/('browser-results-previous-'+str(n)+'.json')).exists():n+=1
        destination.rename(run/('browser-results-previous-'+str(n)+'.json'))
    destination.write_text(json.dumps(report,indent=2)+'\n')
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base',type=Path,required=True);p.add_argument('--sha256',required=True)
    p.add_argument('--media',type=Path,required=True);p.add_argument('--gateway',type=Path,required=True)
    p.add_argument('--prefix',required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--mode',choices=['up','mp','tcg'],action='append')
    p.add_argument('--resume',action='store_true')
    p.add_argument('--run-root',type=Path,default=ROOT/'.work/browser-20261025/runs')
    p.add_argument('--memory',type=int,default=1024)
    a=p.parse_args();a.base=a.base.resolve();a.run_root=a.run_root.resolve();a.media=a.media.resolve();a.gateway=a.gateway.resolve();a.output=a.output.resolve()
    if not a.output.is_relative_to(ROOT/'.work'):p.error('private .work output required')
    a.output.mkdir(parents=True,exist_ok=False)
    # Processes keep cwd isolated even while QMP observers operate concurrently.
    modes=a.mode or ['up','mp','tcg']
    results=[]
    for mode in modes:
        # Each child owns its cwd. This coordinator can safely launch all modes.
        command=[sys.executable,__file__,'--base',str(a.base),'--sha256',a.sha256,'--media',str(a.media),'--gateway',str(a.gateway),'--prefix',a.prefix,'--output',str(a.output/mode),'--run-root',str(a.run_root),'--memory',str(a.memory),'--worker',mode]
        if a.resume:command.append('--resume')
        with (a.output/(mode+'.log')).open('w') as f:
            process=subprocess.Popen(command,stdout=f,stderr=subprocess.STDOUT)
        results.append((mode,process))
    while any(proc.poll() is None for _,proc in results):time.sleep(2)
    report={'modes':{mode:json.loads((a.output/mode/'result.json').read_text()) for mode,_ in results}}
    report['passed']=all(row.get('passed') for row in report['modes'].values())
    (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':report['passed'],'modes':{m:r.get('passed') for m,r in report['modes'].items()}}))
    if not report['passed']:raise SystemExit(2)

# Worker parsing is kept separate so ordinary callers cannot accidentally reuse
# another run's cwd while observing QMP.
if __name__=='__main__':
    if '--worker' in sys.argv:
        index=sys.argv.index('--worker');mode=sys.argv[index+1];del sys.argv[index:index+2]
        parser=argparse.ArgumentParser()
        for arg in ['base','media','gateway','output','run_root']:parser.add_argument('--'+arg.replace('_','-'),type=Path,required=True)
        parser.add_argument('--memory',type=int,required=True)
        parser.add_argument('--sha256',required=True);parser.add_argument('--prefix',required=True)
        parser.add_argument('--resume',action='store_true')
        args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=False)
        result=execute(args,mode);(args.output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        raise SystemExit(0 if result['passed'] else 2)
    main()
