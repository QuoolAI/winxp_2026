#!/usr/bin/env python3
"""Read x86 test-profile minidumps without executing guest code or uploading data.
Frame-pointer chains and bounded stack candidates are labelled separately;
matching symbols, not nearest symbol guesses, identify captured instruction RVAs.
"""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct
import uuid

class Dump:
    def __init__(self,path):
        self.file=path.open('rb')
        try:self.data=mmap.mmap(self.file.fileno(),0,access=mmap.ACCESS_READ)
        finally:self.file.close()
        try:self.parse()
        except Exception:
            self.data.close()
            raise
    def parse(self):
        if self.data[:4]!=b'MDMP':raise ValueError('not a minidump')
        count,directory=struct.unpack_from('<II',self.data,8);self.streams={}
        for i in range(count):
            kind,size,rva=struct.unpack_from('<III',self.data,directory+12*i)
            if rva+size>len(self.data):raise ValueError('invalid stream bounds')
            self.streams[kind]=(rva,size)
        self.ranges=[]
        if 9 in self.streams:
            at,_=self.streams[9];count,offset=struct.unpack_from('<QQ',self.data,at)
            for i in range(count):
                start,size=struct.unpack_from('<QQ',self.data,at+16+16*i);self.ranges.append((start,size,offset));offset+=size
        elif 5 in self.streams:
            at,_=self.streams[5];count=self.u32(at)
            for i in range(count):
                start,size,offset=struct.unpack_from('<QII',self.data,at+4+16*i);self.ranges.append((start,size,offset))
        self.modules=[]
        if 4 in self.streams:
            at,_=self.streams[4]
            for i in range(self.u32(at)):
                row=at+4+108*i;base,size,checksum,timestamp,name=struct.unpack_from('<QIIII',self.data,row)
                module={'base':base,'size':size,'checksum':checksum,'timestamp':timestamp,'path':self.string(name)}
                cvsize,cvrva=struct.unpack_from('<II',self.data,row+76)
                if cvsize>=24 and self.data[cvrva:cvrva+4]==b'RSDS':
                    module['pdb']={'guid':str(uuid.UUID(bytes_le=self.data[cvrva+4:cvrva+20])).upper(),'age':self.u32(cvrva+20),'path':self.data[cvrva+24:cvrva+cvsize].split(b'\0')[0].decode(errors='replace')}
                self.modules.append(module)
        self.threads=[]
        if 3 in self.streams:
            at,size=self.streams[3];count=self.u32(at)
            if 4+48*count>size:raise ValueError('invalid thread-list bounds')
            for i in range(count):
                row=at+4+48*i;start,length,offset=struct.unpack_from('<QII',self.data,row+24)
                if offset+length>len(self.data):raise ValueError('invalid thread stack bounds')
                self.ranges.append((start,length,offset))
                context_size,context=struct.unpack_from('<II',self.data,row+40)
                self.threads.append({'tid':self.u32(row),'context_size':context_size,'context_rva':context})
    def u32(self,offset):return struct.unpack_from('<I',self.data,offset)[0]
    def string(self,rva):return self.data[rva+4:rva+4+self.u32(rva)].decode('utf-16le',errors='replace')
    def memory(self,address,size):
        for start,length,offset in self.ranges:
            if start<=address and address+size<=start+length:return self.data[offset+address-start:offset+address-start+size]
        raise ValueError('address not captured: '+hex(address))
    def locate(self,address):
        for m in self.modules:
            if m['base']<=address<m['base']+m['size']:return {'address':hex(address),'module':m['path'],'rva':hex(address-m['base'])}
        return {'address':hex(address),'module':None}
    def context_report(self,size,rva):
        if size<204 or rva+size>len(self.data):raise ValueError('x86 context unavailable')
        result={}
        registers={name:self.u32(rva+offset) for name,offset in {'edi':156,'esi':160,'ebx':164,'edx':168,'ecx':172,'eax':176,'ebp':180,'eip':184,'eflags':192,'esp':196}.items()};result['registers']=registers
        frame=registers['ebp'];frames=[]
        for _ in range(64):
            try:words=struct.unpack('<10I',self.memory(frame,40))
            except ValueError:break
            args=[]
            for word in words[2:]:
                item={'value':hex(word)}
                try:
                    data=self.memory(word,64);text=data.decode('utf-16le',errors='replace').split('\0')[0]
                    if text and all(c.isprintable() and c!='\ufffd' for c in text):item['possible_utf16']=text
                except ValueError:pass
                args.append(item)
            frames.append({'ebp':hex(frame),'return':self.locate(words[1]),'arguments':args})
            if not frame<words[0]<frame+0x100000:break
            frame=words[0]
        result['frame_pointer_chain']=frames
        candidates=[]
        for offset in range(0,4096,4):
            try:value=struct.unpack('<I',self.memory(registers['esp']+offset,4))[0]
            except ValueError:break
            where=self.locate(value)
            if where['module']:candidates.append({'stack_offset':offset,**where})
        result['unverified_stack_candidates']=candidates
        return result
    def report(self):
        result={'streams':sorted(self.streams),'modules':self.modules,'memory_ranges':len(self.ranges)}
        result['threads']=[{'tid':t['tid'],**self.context_report(t['context_size'],t['context_rva'])} for t in self.threads]
        if 6 in self.streams:
            at,_=self.streams[6];tid=self.u32(at);code,flags=struct.unpack_from('<II',self.data,at+8);address=struct.unpack_from('<Q',self.data,at+24)[0]
            result['exception']={'tid':tid,'code':hex(code),'flags':flags,**self.locate(address)}
            result.update(self.context_report(*struct.unpack_from('<II',self.data,at+160)))
        result['limitations']=['Frame pointers can be absent or stale.','Stack candidates are addresses, not proven call frames.','An exception dump alone does not establish whether it was handled.']
        return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('dump',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if '.work' not in a.dump.resolve().parts or '.work' not in a.output.resolve().parts:p.error('private .work files required')
    d=Dump(a.dump);result=d.report();result['dump']=str(a.dump.resolve());h=hashlib.sha256()
    with a.dump.open('rb') as f:
        for block in iter(lambda:f.read(1<<20),b''):h.update(block)
    result['sha256']=h.hexdigest();a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'exception':result.get('exception'),'exception_frames':len(result.get('frame_pointer_chain',[])),'threads':len(result['threads'])}))
if __name__=='__main__':main()
