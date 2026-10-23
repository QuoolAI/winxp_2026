#!/usr/bin/env python3
"""Private XP image/QMP helpers. Callers select a fresh .work/ directory.

All commands and QMP exchanges are journaled; a running image must never be
opened for offline modification. The CLI serializes UI operations with a lock.
"""
import argparse, contextlib, datetime, fcntl, hashlib, json, os, socket, struct, subprocess, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
def record(obj):
    obj['utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with Path('journal.jsonl').open('a') as f: f.write(json.dumps(obj) + '\n')

def checkpoint(**data):
    p=Path('checkpoint.json'); old=json.loads(p.read_text()) if p.exists() else {}
    old.update(data); old['utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    Path('checkpoint.tmp').write_text(json.dumps(old,indent=2)+'\n'); os.replace('checkpoint.tmp',p)

def run(cmd):
    r=subprocess.run(list(map(str,cmd)),capture_output=True)
    record({'argv':list(map(str,cmd)),'rc':r.returncode,'stderr':r.stderr.decode(errors='replace')})
    if r.returncode: raise RuntimeError(r.stderr.decode(errors='replace'))
    return r.stdout

class QMP:
    def __enter__(self):
        self.s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); self.s.settimeout(10)
        self.s.connect('qmp.sock'); self.f=self.s.makefile('rwb'); self.f.readline(); self.n=0
        self.call('qmp_capabilities'); return self
    def call(self,command,args=None):
        self.n+=1; msg={'execute':command,'id':self.n}
        if args is not None: msg['arguments']=args
        self.f.write(json.dumps(msg).encode()+b'\n'); self.f.flush()
        while True:
            line=self.f.readline()
            if not line: raise EOFError(command)
            response=json.loads(line)
            if response.get('id')==self.n: break
            record({'event':response})
        record({'qmp':msg,'response':response})
        if 'error' in response: raise RuntimeError(response['error'])
        return response.get('return')
    def hmp(self,text): return self.call('human-monitor-command',{'command-line':text})
    def __exit__(self,*args): self.f.close(); self.s.close()

@contextlib.contextmanager
def partition(disk,writable=False):
    run(['qemu-img','dd','-f','qcow2','bs=512','count=1','if='+str(disk),'of=mbr.bin'])
    entry=Path('mbr.bin').read_bytes()[446:462]; start,size=struct.unpack('<II',entry[8:16])
    assert entry[4]==7 and start and size
    export=Path.cwd()/'partition.raw'; export.touch()
    source={'driver':'qcow2','node-name':'source','read-only':not writable,'file':{'driver':'file','filename':str(disk),'read-only':not writable}}
    part={'driver':'raw','node-name':'partition','read-only':not writable,'offset':start*512,'size':size*512,'file':'source'}
    cmd=['qemu-storage-daemon','--blockdev',json.dumps(source),'--blockdev',json.dumps(part),'--export',f'type=fuse,id=ntfs,node-name=partition,mountpoint={export},writable={"on" if writable else "off"},allow-other=off']
    with Path('storage.log').open('a') as log:
        proc=subprocess.Popen(cmd,stdout=log,stderr=subprocess.STDOUT); record({'argv':cmd,'pid':proc.pid})
        try:
            for _ in range(100):
                if proc.poll() is not None: raise RuntimeError(Path('storage.log').read_text())
                if export.stat().st_size: break
                time.sleep(.05)
            else: raise TimeoutError('FUSE export')
            yield export
        finally:
            run(['fusermount','-u',export]); proc.terminate(); proc.wait(timeout=10)

def screen(q,name):
    from PIL import Image
    q.call('screendump',{'filename':str(Path.cwd()/(name+'.ppm'))})
    Image.open(name+'.ppm').save(name+'.png')
    return str(Path.cwd()/(name+'.png'))

def key(q,k):
    q.hmp('sendkey '+k);time.sleep(.12)

def type_text(q,value):
    basic={' ':'spc','\\':'backslash','.':'dot','/':'slash','-':'minus','=':'equal'}
    shifted={':':'semicolon','"':'apostrophe','_':'minus','&':'7','>':'dot','%':'5'}
    for c in value:
        if c.isupper():k='shift-'+c.lower()
        elif c in shifted:k='shift-'+shifted[c]
        elif c in basic:k=basic[c]
        elif c.isascii() and c.isalnum():k=c
        else:raise ValueError(c)
        key(q,k)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory',type=Path)
    p.add_argument('action',choices=['qmp','hmp','screen','run','key','type','restart','finish'])
    p.add_argument('value',nargs='?')
    a=p.parse_args();directory=a.directory.resolve()
    if not directory.is_relative_to(ROOT/'.work'):p.error('private .work/ directory required')
    os.chdir(directory)
    with Path('operation.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with QMP() as q:
            if a.action=='hmp':print(q.hmp(a.value))
            elif a.action=='qmp':print(q.call(a.value))
            elif a.action=='screen':print(screen(q,a.value or 'screen'))
            elif a.action=='key':key(q,a.value)
            elif a.action=='type':type_text(q,a.value)
            elif a.action=='run':
                key(q,'shift');key(q,'meta_l-r');time.sleep(1);key(q,'ctrl-a');type_text(q,a.value);key(q,'ret')
            elif a.action=='restart':
                q.call('set-action',{'reboot':'reset','shutdown':'pause'})
                key(q,'shift');key(q,'meta_l-r');time.sleep(1);key(q,'ctrl-a')
                type_text(q,'shutdown.exe -r -t 0');key(q,'ret')
                q.s.settimeout(60)
                while True:
                    event=json.loads(q.f.readline())
                    record({'event':event})
                    if event.get('event')=='RESET':
                        if not event.get('data',{}).get('guest'):raise RuntimeError('reset was not guest requested')
                        Path('guest-restart.json').write_text(json.dumps(event,indent=2)+'\n')
                        break
            elif a.action=='finish':
                state=q.call('query-status')
                if state['status']!='shutdown':raise RuntimeError('guest must shut down normally first')
                screen(q,'normal-shutdown')
                Path('normal-shutdown.json').write_text(json.dumps({'trigger':'guest shutdown.exe -s -t 0','qemu_status':state,'quit_after_shutdown':True},indent=2)+'\n')
                q.call('quit')
        if a.action=='finish':
            for _ in range(100):
                result=subprocess.run(['qemu-img','check','disk.qcow2'],capture_output=True)
                if result.returncode==0:break
                time.sleep(.1)
            Path('image-check.log').write_bytes(result.stdout+result.stderr)
            if result.returncode:raise RuntimeError('image check failed')
            Path('disk.qcow2').chmod(0o444)
            checkpoint(stage='normal_shutdown_frozen',disk_sha256=hashlib.sha256(Path('disk.qcow2').read_bytes()).hexdigest())

if __name__=='__main__':main()
