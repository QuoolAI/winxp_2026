#!/usr/bin/env python3
"""Exercise an empty XP25 browser test profile through the isolated fixture bridge.
No certificate/sandbox bypass is permitted. Does not read any user's history,
cookies, passwords or sessions. Run inside the browser's network namespace.
"""
import argparse
import json
import os
from pathlib import Path
import time
import threading
CDP_TIMEOUT=float(os.environ.get('XP25_CDP_TIMEOUT','45'))
import urllib.request
import websocket

HOST='http://10.25.0.10:9223'
TRACE_OUTPUT=None
class Completed(Exception):
    pass

def get(path):
    op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    return json.load(op.open(HOST+path,timeout=10))

class CDP:
    def __init__(self,url,transcript):
        self.ws=websocket.create_connection(url,timeout=CDP_TIMEOUT,suppress_origin=True,http_no_proxy=['*'])
        self.n=0;self.events=[];self.transcript=transcript
        self.stopped=threading.Event()
        def keepalive():
            while not self.stopped.wait(10):
                try:self.ws.ping()
                except (OSError,websocket.WebSocketException):return
        threading.Thread(target=keepalive,daemon=True).start()
    def call(self,method,params=None):
        self.n+=1;message={'id':self.n,'method':method,'params':params or {}}
        self.ws.send(json.dumps(message));self.transcript.append({'request':message,'time':time.time()})
        if TRACE_OUTPUT:
            (TRACE_OUTPUT/'current-request.json').write_text(json.dumps({'method':method,'parameters':params or {},'time':time.time()},indent=2)+'\n')
        deadline=time.time()+CDP_TIMEOUT
        while True:
            remaining=deadline-time.time()
            if remaining<=0:raise TimeoutError(method)
            self.ws.settimeout(remaining)
            opcode,frame=self.ws.recv_data_frame(control_frame=True)
            if opcode in (websocket.ABNF.OPCODE_PING,websocket.ABNF.OPCODE_PONG):continue
            if opcode==websocket.ABNF.OPCODE_CLOSE:raise websocket.WebSocketConnectionClosedException('CDP peer closed')
            r=json.loads(frame.data)
            if r.get('id')==self.n:
                self.transcript.append({'response':r,'time':time.time()})
                if 'error' in r:raise RuntimeError(r['error'])
                return r.get('result',{})
            self.events.append(r)
    def evaluate(self,expression):return self.call('Runtime.evaluate',{'expression':expression,'returnByValue':True,'awaitPromise':True})
    def close(self):
        self.stopped.set();self.ws.close()

def page(browser,context,transcript):
    target=browser.call('Target.createTarget',dict({'url':'about:blank'},**({'browserContextId':context} if context else {})))['targetId']
    return target,CDP('ws://10.25.0.10:9223/devtools/page/'+target,transcript)

def loaded(p,timeout=CDP_TIMEOUT,expected=None):
    deadline=time.time()+timeout
    while time.time()<deadline:
        r=p.evaluate('({ready:document.readyState,title:document.title,url:location.href})')
        v=r.get('result',{}).get('value',{})
        if v.get('ready')=='complete' and (expected is None or v.get('url')==expected):return v
        time.sleep(.5)
    raise TimeoutError('page load')

def main():
    global TRACE_OUTPUT
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--https',action='store_true')
    p.add_argument('--eval');p.add_argument('--navigate');p.add_argument('--close-browser',action='store_true')
    p.add_argument('--persistence',action='store_true')
    p.add_argument('--policy',action='store_true',help='require the image URL policy to block non-approved hosts')
    a=p.parse_args();out=a.output.resolve()
    if '.work' not in out.parts:p.error('private .work evidence required')
    os.environ['NO_PROXY']='*';os.environ['no_proxy']='*'
    out.mkdir(parents=True,exist_ok=False);TRACE_OUTPUT=out;transcript=[];result={'checks':{},'limitations':[]}
    browser=None
    try:
        version=get('/json/version');result['version']=version
        browser=CDP(version['webSocketDebuggerUrl'],transcript)
        result['processes']=browser.call('SystemInfo.getProcessInfo')
        if a.persistence:
            target,pg=page(browser,None,transcript)
            pg.call('Page.navigate',{'url':'http://xp25.test:8080/local.html'})
            loaded(pg,expected='http://xp25.test:8080/local.html')
            stored=pg.evaluate('localStorage.getItem("xp25-cdp-persistence")')
            result['profile_storage']=stored
            result['checks']['profile_persists']=stored.get('result',{}).get('value')=='xp25-browser-fixture-v1'
            pg.call('Page.navigate',{'url':'chrome://settings/appearance'})
            loaded(pg,expected='chrome://settings/appearance')
            pref=pg.evaluate('new Promise(resolve=>chrome.settingsPrivate.getPref("webkit.webprefs.default_font_size",p=>resolve(p.value)))')
            result['font_preference']=pref
            result['checks']['appearance_setting_persists']=pref.get('result',{}).get('value')==17
            pg.close()
            raise Completed()
        if a.eval or a.navigate:
            pages=get('/json/list');pg=CDP(next(v['webSocketDebuggerUrl'] for v in pages if v['type']=='page'),transcript)
            if a.navigate:result['navigation']=pg.call('Page.navigate',{'url':a.navigate});result['page']=loaded(pg)
            if a.eval:result['evaluation']=pg.evaluate(a.eval)
            pg.close();result['checks']['diagnostic_completed']=True;raise Completed()
        context=None
        target,pg=page(browser,context,transcript);pg.call('Page.enable');pg.call('Network.enable')
        result['local_http_navigation']=pg.call('Page.navigate',{'url':'http://xp25.test:8080/local.html'})
        result['local_http_page']=loaded(pg,expected='http://xp25.test:8080/local.html')
        r=pg.evaluate('({title:document.title,checks:[...document.querySelectorAll("#results li")].map(x=>x.textContent),storage:localStorage.getItem("xp25-fixture")})')
        result['javascript']=r
        result['checks']['modern_javascript']=r.get('result',{}).get('value',{}).get('title')=='XP25 JavaScript PASS'
        pg.call('Page.bringToFront')
        (out/'ready-for-screenshot.json').write_text(json.dumps(result['local_http_page'])+'\n')
        time.sleep(4)
        pg.call('Page.navigate',{'url':'file:///C:/Program%20Files/XP25Browser/local.html'})
        result['local_file_page']=loaded(pg,expected='file:///C:/Program%20Files/XP25Browser/local.html');result['checks']['local_html']=result['local_file_page']['title']=='XP25 JavaScript PASS'
        second,other=page(browser,context,transcript);other.call('Page.navigate',{'url':'http://xp25.test:8080/local.html?tab=2'});result['second_tab']=loaded(other,expected='http://xp25.test:8080/local.html?tab=2')
        result['checks']['multiple_tabs']=result['second_tab']['title']=='XP25 JavaScript PASS'
        if a.https:
            result['https']={}
            for name,url,valid in [('valid','https://example.com/',True),('expired','https://expired.badssl.com/',False),('hostname','https://wrong.host.badssl.com/',False),('untrusted','https://self-signed.badssl.com/',False)]:
                pg.events=[];nav=pg.call('Page.navigate',{'url':url});state=loaded(pg,expected=url if valid else None)
                details=[e['params']['response'].get('securityDetails') for e in pg.events if e.get('method')=='Network.responseReceived' and e['params'].get('type')=='Document']
                failed=[e['params'] for e in pg.events if e.get('method')=='Network.loadingFailed']
                result['https'][name]={'navigation':nav,'page':state,'security_details':details,'loading_failed':failed}
                if valid:ok=not nav.get('errorText') and state.get('url')==url and any(d and d.get('protocol') in ['TLS 1.2','TLS 1.3'] for d in details)
                else:ok=bool(nav.get('errorText','').startswith('net::ERR_CERT_') or any(e.get('errorText','').startswith('net::ERR_CERT_') for e in failed))
                result['checks']['https_'+name]=ok
        if a.policy:
            result['policy']={}
            # Not on URLAllowlist: Chromium must refuse before any network request.
            for name,url in [('lab_subdomain','http://blocked.xp25.test:8080/local.html?case=policy-blocked'),('public_site','https://www.wikipedia.org/')]:
                nav=pg.call('Page.navigate',{'url':url});result['policy'][name]=nav
                result['checks']['policy_blocks_'+name]=nav.get('errorText')=='net::ERR_BLOCKED_BY_ADMINISTRATOR'
        browser.call('Browser.setDownloadBehavior',{'behavior':'allow','downloadPath':r'C:\xp25\browser\downloads','eventsEnabled':True})
        result['download_navigation']=pg.call('Page.navigate',{'url':'http://xp25.test:8080/download.txt'})
        # File writes can outlive the navigation response, especially under TCG.
        # Drain the browser event stream until completion or a bounded deadline.
        deadline=time.time()+45
        while time.time()<deadline:
            browser.call('Browser.getVersion')
            if any(e.get('method')=='Browser.downloadProgress' and e['params'].get('state')=='completed' for e in browser.events):break
            time.sleep(.5)
        result['download_events']=[e for e in browser.events if e.get('method','').startswith('Browser.download')]
        result['checks']['download_completed']=any(e.get('method')=='Browser.downloadProgress' and e['params'].get('state')=='completed' for e in result['download_events'])
        pg.call('Page.navigate',{'url':'http://xp25.test:8080/local.html'})
        loaded(pg,expected='http://xp25.test:8080/local.html')
        pg.evaluate('localStorage.setItem("xp25-cdp-persistence","xp25-browser-fixture-v1")')
        pg.call('Page.navigate',{'url':'chrome://settings/appearance'})
        loaded(pg,expected='chrome://settings/appearance')
        result['set_font_preference']=pg.evaluate('new Promise(resolve=>chrome.settingsPrivate.setPref("webkit.webprefs.default_font_size",17,"",ok=>resolve(ok)))')
        result['checks']['appearance_setting_changed']=result['set_font_preference'].get('result',{}).get('value') is True
        result['processes_after']=browser.call('SystemInfo.getProcessInfo')
        pg.close();other.close()
    except Completed:
        pass
    except Exception as e:
        result['error']={'type':type(e).__name__,'message':str(e)}
    finally:
        if browser:
            if a.close_browser:
                try:browser.call('Browser.close')
                except (OSError,RuntimeError,websocket.WebSocketException):pass
            browser.close()
        result['passed']=bool(result['checks']) and all(result['checks'].values()) and 'error' not in result
        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        (out/'transcript.json').write_text(json.dumps(transcript,indent=2)+'\n')
        print(json.dumps(result,indent=2))
    if not result['passed']:raise SystemExit(2)
if __name__=='__main__':main()
