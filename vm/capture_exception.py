#!/usr/bin/env python3
"""Capture the first access violation in one NT 5.1 x86 guest process.

Uses the matching original kernel map and NT 5.1 structure layout. Read-only
inspection; leaves the private guest paused. Do not use on a reference/user VM.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory', type=Path)
    p.add_argument('--kernel', type=Path, required=True)
    p.add_argument('--process', choices=['explorer.exe', 'winlogon.exe'], required=True)
    p.add_argument('--chance', choices=['first', 'second'], default='first')
    a = p.parse_args()
    directory = a.directory.resolve()
    if not directory.is_relative_to(ROOT / '.work'):
        p.error('private guest directory required')
    mapping = a.kernel.with_suffix('.map').read_text()
    match = re.search(r'_KiDispatchException@20\s+([0-9a-fA-F]{8})', mapping)
    if not match:
        p.error('matching KiDispatchException map symbol required')
    address = int(match[1], 16) - 0x400000 + 0x80a02000
    config = {'process': a.process, 'breakpoint': address, 'kernel': str(a.kernel.resolve()), 'chance': a.chance}
    (directory / 'exception-config.json').write_text(json.dumps(config, indent=2) + '\n')
    code = r'''import gdb,struct,json
config=json.load(open('exception-config.json'))
def read(p,n):return bytes(gdb.selected_inferior().read_memory(p,n))
def u32(p):return struct.unpack('<I',read(p,4))[0]
def uni(p):
 n,_,buf=struct.unpack('<HHI',read(p,8))
 return read(buf,min(n,2048)).decode('utf-16-le',errors='replace') if n else ''
def modules(process):
 peb=u32(process+0x1b0);ldr=u32(peb+12);head=ldr+12;node=u32(head);result=[]
 for _ in range(300):
  if node==head:break
  base=u32(node+24);pe=base+u32(base+60)
  result.append({'base':base,'size':u32(node+32),'name':uni(node+44),'path':uni(node+36),
   'pe_checksum':u32(pe+24+64),'timestamp':u32(pe+8),'entry_point':u32(node+28)})
  node=u32(node)
 return result
class Capture(gdb.Breakpoint):
 def stop(self):
  try:
   esp=int(gdb.parse_and_eval('$esp'))&0xffffffff;record=u32(esp+4)
   if u32(record)!=0xc0000005:return False
   if config['chance']=='second' and u32(esp+20)!=0:return False
   thread=u32(0xffdff124);process=u32(thread+0x44)
   name=read(process+0x174,16).split(bytes([0]))[0].decode(errors='replace')
   if name!=config['process']:return False
   trap=u32(esp+12);values=struct.unpack('<40I',read(trap,160))
   indices={'edx':15,'ecx':16,'eax':17,'edi':21,'esi':22,'ebx':23,'ebp':24,'eip':26,'cs':27,'eflags':28,'esp':29}
   registers={n:values[i] for n,i in indices.items()};frames=[];ebp=registers['ebp']
   for _ in range(64):
    if not 0<ebp<0x80000000:break
    try:following,ret=struct.unpack('<II',read(ebp,8));args=struct.unpack('<6I',read(ebp+8,24))
    except gdb.MemoryError:break
    frames.append({'ebp':ebp,'return':ret,'args':args})
    if not ebp<following<ebp+0x100000:break
    ebp=following
   result={'process':name,'eprocess':process,'code':u32(record),'exception_address':u32(record+12),
     'operation':u32(record+20),'fault_address':u32(record+24),'first_chance':u32(esp+20),
     'registers':registers,'frames':frames,'modules':modules(process)}
   stack=registers['esp'];length=min(16384,0x10000-(stack&0xffff))
   open('exception-stack.bin','wb').write(read(stack,length))
   open('exception-record.bin','wb').write(read(record,80));open('exception-trap.bin','wb').write(read(trap,160))
   ip=registers['eip'];open('exception-instructions.bin','wb').write(read(ip-32,192))
   result['instruction_bytes_address']=ip-32;result['stack_bytes_address']=stack
   open('first-exception.json','w').write(json.dumps(result,indent=2)+chr(10))
   print(json.dumps(result),flush=True);return True
  except Exception as e:
   print('capture error: '+str(e),flush=True)
   return False
Capture('*'+hex(config['breakpoint']),type=gdb.BP_HARDWARE_BREAKPOINT,internal=True)
'''
    # Keep the generated GDB program independent from host imports and filesystem state.
    compile(code, 'capture-first.py', 'exec')
    (directory / 'capture-first.py').write_text(code)
    (directory / 'capture-first.gdb').write_text('set pagination off\nset architecture i386\n'
        'target remote gdb.sock\nsource capture-first.py\ncontinue\nmonitor stop\ndisconnect\n')
    with (directory / 'capture-first.log').open('w') as log:
        subprocess.run(['gdb', '-q', '-nx', '-batch', '-x', 'capture-first.gdb'], cwd=directory,
                       stdout=log, stderr=subprocess.STDOUT, check=True, timeout=600)
    if not (directory / 'first-exception.json').exists():
        raise RuntimeError('no valid exception captured; inspect capture-first.log')


if __name__ == '__main__':
    main()
