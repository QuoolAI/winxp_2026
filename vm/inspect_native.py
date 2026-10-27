#!/usr/bin/env python3
"""Capture live NT 5.1 x86 module/process evidence using the matching kernel map.

Run with no other debugger attached. The guest is left paused after inspection;
resume it with QMP after reviewing the evidence.
"""
import argparse
import json
from pathlib import Path
import re
import struct
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--kernel', type=Path, required=True)
    args = parser.parse_args()
    kernel = args.kernel.resolve()
    data = kernel.read_bytes()
    pe = struct.unpack_from('<I', data, 60)[0]
    expected = struct.unpack_from('<I', data, pe+24+64)[0]
    mapping = kernel.with_suffix('.map').read_text()
    symbols = {}
    for name in ('PsLoadedModuleList', 'PsActiveProcessHead'):
        match = re.search(r'_' + name + r'\s+([0-9a-fA-F]{8})', mapping)
        if not match:
            raise ValueError('missing matching symbol: ' + name)
        symbols[name] = int(match[1], 16)-0x400000+0x80a02000
    code = '''import gdb,struct,json
m=gdb.selected_inferior()
def read(p,n):return bytes(m.read_memory(p,n))
def u32(p):return struct.unpack('<I',read(p,4))[0]
def uni(p):
 n,_,buf=struct.unpack('<HHI',read(p,8));return read(buf,n).decode('utf-16-le',errors='replace') if n else ''
modules=[];head=MODULE_HEAD;node=u32(head)
for i in range(300):
 if node==head:break
 modules.append({'base':hex(u32(node+0x18)),'size':u32(node+0x20),'name':uni(node+0x2c),'path':uni(node+0x24)});node=u32(node)
kernel=next(x for x in modules if 'xp25krnl' in x['path'].lower());base=int(kernel['base'],16);checksum=u32(base+u32(base+60)+24+64)
processes=[];head=PROCESS_HEAD;node=u32(head)
for i in range(200):
 if node==head:break
 p=node-0x88;processes.append({'pid':u32(p+0x84),'name':read(p+0x174,16).split(b'\\0')[0].decode(errors='replace')});node=u32(node)
r={'loaded_kernel':kernel,'loaded_kernel_checksum':hex(checksum),'expected_compiled_checksum':hex(EXPECTED),'checksum_matches':checksum==EXPECTED,'processes':processes,'modules':modules}
open('native-stack-verification.json','w').write(json.dumps(r,indent=2)+'\\n');print(json.dumps(r,indent=2))
'''.replace('MODULE_HEAD', str(symbols['PsLoadedModuleList'])).replace(
        'PROCESS_HEAD', str(symbols['PsActiveProcessHead'])).replace('EXPECTED', str(expected))
    directory = args.directory.resolve()
    script = 'set pagination off\nset architecture i386\ntarget remote gdb.sock\npython\n' + code + 'end\nmonitor stop\ndisconnect\n'
    (directory / 'inspect-current.gdb').write_text(script)
    with (directory / 'inspect-current.log').open('w') as log:
        subprocess.run(['gdb', '-q', '-nx', '-batch', '-x', 'inspect-current.gdb'],
                       cwd=directory, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=30)
    result = json.loads((directory / 'native-stack-verification.json').read_text())
    if not result['checksum_matches']:
        raise ValueError('loaded kernel checksum mismatch')
    print(json.dumps({'kernel': result['loaded_kernel'], 'checksum_matches': True}))


if __name__ == '__main__':
    main()
