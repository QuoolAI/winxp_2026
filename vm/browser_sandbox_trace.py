#!/usr/bin/env python3
"""Identify the fixture's executing renderer PID/TID using its own trace marker.
Run inside the isolated test namespace; no real user profile or browsing data.
The browser is left open for a separate native token/access-boundary probe.
"""
import argparse
import json
from pathlib import Path
import time
from browser_cdp import CDP,get

MARKER='XP25_SANDBOX_EXECUTION_PROOF'
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve()
    if '.work' not in out.parts:p.error('private test output required')
    out.mkdir(parents=True,exist_ok=False);transcript=[];result={};browser=None;page=None
    try:
        version=get('/json/version');browser=CDP(version['webSocketDebuggerUrl'],transcript)
        target=next(v for v in get('/json/list') if v.get('type')=='page' and v.get('url','').startswith('http://xp25.test:8080/local.html'))
        page=CDP(target['webSocketDebuggerUrl'],transcript)
        state=page.evaluate('({title:document.title,url:location.href})');result['page_state']=state
        if state.get('result',{}).get('value',{}).get('title')!='XP25 JavaScript PASS':raise RuntimeError('fixture JavaScript has not passed')
        browser.call('Tracing.start',{'categories':'devtools.timeline','transferMode':'ReportEvents'})
        result['marker_evaluation']=page.evaluate('console.timeStamp("'+MARKER+'"); "fixture-marker-issued"')
        browser.call('Tracing.end');deadline=time.time()+30
        while time.time()<deadline:
            browser.call('Browser.getVersion')
            if any(e.get('method')=='Tracing.tracingComplete' for e in browser.events):break
            time.sleep(.2)
        matches=[]
        for event in browser.events:
            if event.get('method')=='Tracing.dataCollected':
                for row in event['params']['value']:
                    if row.get('name')=='TimeStamp' and MARKER in json.dumps(row.get('args',{})):matches.append(row)
        result['marker_events']=matches
        result['executing_renderer_ids']=sorted({(e['pid'],e['tid']) for e in matches})
        result['identified']=bool(matches)
        if not matches:raise RuntimeError('no executing-renderer trace marker observed')
    except Exception as e:result['error']={'type':type(e).__name__,'message':str(e)};result['identified']=False
    finally:
        if page:page.close()
        if browser:browser.close()
        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');(out/'transcript.json').write_text(json.dumps(transcript,indent=2)+'\n');print(json.dumps(result,indent=2))
    if not result.get('identified'):raise SystemExit(2)
if __name__=='__main__':main()
