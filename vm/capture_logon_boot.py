#!/usr/bin/env python3
"""Read-only NT 5.1 x86 boot trace: LSASS object opens and first hard error.

Kernel offsets are from matching maps and supplied ks386.inc. No service result
or exception is changed. Leaves the disposable guest paused for inspection.
"""
import argparse,json,re,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('directory',type=Path);p.add_argument('--kernel',type=Path,required=True);a=p.parse_args();d=a.directory.resolve()
 if not d.is_relative_to(ROOT/'.work'):p.error('private experiment required')
 mapping=a.kernel.with_suffix('.map').read_text();symbols={}
 for name,count in [('NtCreateProcessEx',36),('NtOpenEvent',12),('NtConnectPort',32),('NtOpenKey',12),('NtRaiseHardError',24)]:
  m=re.search('_'+name+'@'+str(count)+r'\s+([0-9a-fA-F]{8})',mapping)
  if not m:raise ValueError('matching map symbol missing: '+name)
  symbols[name]=int(m[1],16)-0x400000+0x80a02000
 (d/'boot-trace-config.json').write_text(json.dumps(symbols,indent=2)+'\n')
 code=r'''import gdb,struct,json
m=gdb.selected_inferior();opens=[]
def read(p,n):return bytes(m.read_memory(p,n))
def u32(p):return struct.unpack('<I',read(p,4))[0]
def uni(p):
 n,_,buf=struct.unpack('<HHI',read(p,8));return read(buf,min(n,2048)).decode('utf-16-le',errors='replace') if n else ''
def modules(process):
 ldr=u32(u32(process+0x1b0)+12);head=ldr+12;node=u32(head);result=[]
 for _ in range(300):
  if node==head:break
  base=u32(node+24);pe=base+u32(base+60)
  result.append({'base':base,'name':uni(node+44),'path':uni(node+36),'size':u32(node+32),'checksum':u32(pe+88),'timestamp':u32(pe+8)})
  node=u32(node)
 return result
class Trace(gdb.Breakpoint):
 def __init__(self,name,address):
  self.name=name;super().__init__('*'+hex(address),type=gdb.BP_HARDWARE_BREAKPOINT,internal=True)
 def stop(self):
  try:
   thread=u32(0xffdff124);process=u32(thread+0x44)
   name=read(process+0x174,16).split(bytes([0]))[0].decode(errors='replace')
   if self.name=='NtCreateProcessEx':
    if name=='winlogon.exe':
     self.enabled=False
     for bp in object_breaks:bp.enabled=True
    return False
   if name!='lsass.exe':return False
   sp=int(gdb.parse_and_eval('$esp'))&0xffffffff;args=list(struct.unpack('<6I',read(sp+4,24)))
   if self.name!='NtRaiseHardError':
    if self.name=='NtConnectPort':objname=args[1];root=0
    else:attr=args[2];objname=u32(attr+8);root=u32(attr+4)
    opens.append({'api':self.name,'name':uni(objname) if objname else '', 'root':root})
    if len(opens)>1000:opens.pop(0)
    return False
   trap=u32(thread+0x134);ebp=u32(trap+96);usp=u32(trap+116);frames=[]
   for _ in range(50):
    if not 0<ebp<0x80000000:break
    try:nxt,ret=struct.unpack('<II',read(ebp,8));values=struct.unpack('<6I',read(ebp+8,24))
    except gdb.MemoryError:break
    frames.append({'ebp':ebp,'return':ret,'args':values})
    if not ebp<nxt<ebp+0x100000:break
    ebp=nxt
   result={'process':name,'eprocess':process,'hard_error_arguments':args,'user_eip':u32(trap+104),'user_esp':usp,'frames':frames,'modules':modules(process),'object_opens':opens}
   open('lsa-hard-error.json','w').write(json.dumps(result,indent=2)+chr(10))
   open('lsa-user-stack.bin','wb').write(read(usp,min(16384,0x10000-(usp&0xffff))))
   print(json.dumps({'status':hex(args[0]),'frames':frames,'recent_opens':opens[-15:]}),flush=True);return True
  except Exception as e:print('trace error: '+str(e),flush=True);return False
object_breaks=[]
for name,address in json.load(open('boot-trace-config.json')).items():
 bp=Trace(name,address)
 if name not in ('NtCreateProcessEx','NtRaiseHardError'):
  bp.enabled=False;object_breaks.append(bp)
'''
 compile(code,'boot-trace.py','exec');(d/'boot-trace.py').write_text(code)
 (d/'boot-trace.gdb').write_text('set pagination off\nset architecture i386\ntarget remote gdb.sock\nsource boot-trace.py\ncontinue\nmonitor stop\ndisconnect\n')
 with (d/'boot-trace.log').open('w') as log:subprocess.run(['gdb','-q','-nx','-batch','-x','boot-trace.gdb'],cwd=d,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=180)
 if not (d/'lsa-hard-error.json').is_file():raise RuntimeError('no LSASS hard error captured')
 print(d/'lsa-hard-error.json')
if __name__=='__main__':main()
