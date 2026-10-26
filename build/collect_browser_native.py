#!/usr/bin/env python3
"""Extract a stopped native build, verify its staged sources and XP import contracts."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
from browser_tools import ROOT,TARGETS
from inspect_component import PE

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['run','media','modules','output']:p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();out=a.output.resolve()
    if not out.is_relative_to(ROOT/'.work'):p.error('private .work output required')
    run=a.run.resolve();manifest=json.loads((a.media/'manifest.json').read_text())
    serial=(run/'serial.log').read_text()
    if 'XP25_BROWSER_NATIVE_RC=0' not in serial or 'XP25_BROWSER_NATIVE_WRAPPER=0' not in serial:
        raise ValueError('native build did not succeed')
    sources={k:v for k,v in manifest['files'].items() if k.startswith('browser/')}
    files=['/nt/xp25/'+s for s in sources]
    files+=['/nt/xp25/browser/'+n+'/obj/i386/'+n+'.exe' for n in TARGETS]
    files+=['/xpout/browser-01/native.log']
    out.mkdir(parents=True,exist_ok=False);extracted=out/'extracted'
    command=[sys.executable,str(ROOT/'vm/read_guest.py'),str(run/'disk.qcow2'),str(extracted),*files]
    subprocess.run(command,check=True)
    for relative,digest in sources.items():
        if sha(extracted/'nt/xp25'/relative)!=digest:raise ValueError('staged source mismatch: '+relative)
    cache={}
    def resolve(module,symbol,seen=()):
        if (module,symbol) in seen:raise ValueError('forwarder loop')
        if module not in cache:cache[module]=PE(a.modules/module).exports()
        if symbol not in cache[module]:raise ValueError('missing import '+module+'!'+symbol)
        forwarded=cache[module][symbol]
        if forwarded:
            target,name=forwarded.rsplit('.',1);resolve(target.lower()+'.dll',name,(*seen,(module,symbol)))
    report={'run':str(run),'source_manifest_sha256':sha(a.media/'manifest.json'),
            'source_files_verified':len(sources),'command':command,'native_build_exit':0,'tools':{}}
    for name,(_,_,libs) in TARGETS.items():
        exe=out/(name+'.exe');shutil.copy2(extracted/'nt/xp25/browser'/name/'obj/i386'/(name+'.exe'),exe)
        pe=PE(exe)
        for module,symbols in pe.imports().items():
            if module not in {lib+'.dll' for lib in libs}:raise ValueError('unexpected runtime '+module)
            for symbol in symbols:resolve(module,symbol)
        row=pe.inspect();row['guest_imports_resolved']=True
        report['tools'][name]=row
        (out/(name+'-pe.json')).write_text(json.dumps(row,indent=2)+'\n')
    (out/'collect.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'native_build_exit':0,'sources_verified':len(sources),'tools':{n:r['sha256'] for n,r in report['tools'].items()}},indent=2))

if __name__=='__main__':main()
