#!/usr/bin/env python3
"""Build static PE, source-reference and observed runtime IE dependency graphs.
Private source excerpts and binary inventories stay in .work. Absence of an edge
is never removal evidence; COM, LoadLibrary, delay imports and legacy consumers
require runtime/interface tests.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from inspect_component import PE

TARGETS={'mshtml.dll','shdocvw.dll','browseui.dll','urlmon.dll','wininet.dll','jscript.dll','vbscript.dll','ieframe.dll'}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--modules',type=Path,required=True);p.add_argument('--source',type=Path,required=True)
    p.add_argument('--runtime',type=Path,action='append',default=[]);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();out=a.output.resolve()
    if '.work' not in out.parts:p.error('private .work output required')
    out.mkdir(parents=True,exist_ok=False)
    nodes={};edges=[];fail=[]
    for f in sorted(a.modules.rglob('*')):
        if f.suffix.lower() not in {'.exe','.dll','.cpl','.ocx','.scr'}:continue
        name=str(f.relative_to(a.modules)).lower()
        try:
            pe=PE(f);nodes[name]={'sha256':hashlib.sha256(pe.data).hexdigest()}
            for delayed in (False,True):
                for module,symbols in pe.imports(delayed).items():edges.append({'from':name,'to':module,'kind':'delay_import' if delayed else 'import','symbols':symbols})
        except Exception as e:fail.append({'path':name,'error':str(e)})
    source_edges=[]
    pattern=r'(?i)mshtml|shdocvw|browseui|urlmon|wininet|jscript|vbscript|ieframe|CLSID_WebBrowser|IWebBrowser2|IHTMLDocument|IActiveDesktop'
    cmd=['rg','-n','--no-heading','-i',pattern,str(a.source),'-g','*.c','-g','*.cpp','-g','*.h','-g','*.inc','-g','sources*','-g','*.idl']
    r=subprocess.run(cmd,capture_output=True,text=True,errors='replace')
    if r.returncode not in (0,1):raise RuntimeError(r.stderr)
    for row in r.stdout.splitlines():
        path,n,text=row.split(':',2)
        source_edges.append({'path':str(Path(path).relative_to(a.source)),'line':int(n),'references':sorted(set(x.lower() for x in re.findall(pattern,text))),'text':text[:500]})
    runtime=[]
    for f in a.runtime:
        pid_names={}
        for row in f.read_text(errors='replace').splitlines():
            m=re.match(r'PROCESS pid=(\d+) parent=(\d+) name=(\S+) threads=(\d+)',row)
            if m:pid_names[m[1]]=m[3].lower()
            m=re.match(r'MODULE pid=(\d+) name=(\S+)',row)
            if m:runtime.append({'process':pid_names.get(m[1],'unknown'),'pid':int(m[1]),'module':m[2].lower(),'evidence':str(f)})
    consumers={t:{'static':[e for e in edges if e['to']==t],'runtime':[e for e in runtime if e['module']==t],'status':'retained_compatibility_component','removal_verified':False} for t in sorted(TARGETS)}
    result={'nodes':nodes,'edges':edges,'consumers':consumers,'parse_failures':fail,'runtime':runtime,'source_references':source_edges,'commands':[cmd],'limitations':['Imports describe link contracts, not exercised features.','Source reference matches include comments, headers and dead code.','Runtime modules prove loading, not that an interface is essential or safe.','Third-party applications outside this image are not exhaustively inventoried.','No IE engine DLL is removed by this audit.']}
    (out/'inventory.json').write_text(json.dumps(result,indent=2)+'\n')
    dot=['digraph IE {','rankdir=LR;']
    for e in edges:
        if e['to'] in TARGETS:dot.append(json.dumps(e['from'])+' -> '+json.dumps(e['to'])+' [label='+json.dumps(e['kind'])+'];')
    for e in runtime:
        if e['module'] in TARGETS:dot.append(json.dumps(e['process'])+' -> '+json.dumps(e['module'])+' [color=blue,label="loaded"];')
    dot.append('}');(out/'dependencies.dot').write_text('\n'.join(dot)+'\n')
    print(json.dumps({'PE_nodes':len(nodes),'PE_edges':len(edges),'source_matches':len(source_edges),'parse_failures':len(fail),'consumers':{t:len(c['static']) for t,c in consumers.items()}}))
if __name__=='__main__':main()
