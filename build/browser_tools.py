#!/usr/bin/env python3
"""Build native NT 5.1 browser integration and test tools; validate guest imports.
Cross-compilation is recorded separately from the original NT-toolchain build.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from inspect_component import PE
ROOT=Path(__file__).resolve().parents[1]
TARGETS={'browserctl':('components/browser/browserctl.c','BrowserMain',['kernel32','user32','shell32','shlwapi','ole32','uuid','advapi32','psapi','msvcrt']),
         'browser_shell':('tests/guest/browser_shell.c','ShellProbeMain',['kernel32','user32','advapi32','shell32','shlwapi','ole32','uuid','msvcrt']),
         'browser_bridge':('tests/guest/browser_bridge.c','BridgeMain',['kernel32','ws2_32','msvcrt']),
         'browser_wait':('tests/guest/browser_wait.c','WaitMain',['kernel32']),
         'browser_commandline':('tests/guest/browser_commandline.c','FixtureMain',['kernel32','user32','advapi32','shell32','psapi','msvcrt']),
         'browser_crash':('tests/guest/browser_crash.c','CrashMain',['kernel32','advapi32','user32'])}

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--toolchain',type=Path,required=True);p.add_argument('--modules',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    out=a.output.resolve()
    if not out.is_relative_to(ROOT/'.work'):p.error('fresh private .work output required')
    out.mkdir(parents=True,exist_ok=False);cc=a.toolchain.resolve()/'i686-w64-mingw32-gcc-posix'
    report={'compiler':str(cc),'compiler_sha256':sha(cc),'compiler_version':subprocess.check_output([cc,'--version'],text=True).splitlines()[0],'tools':{}}
    cache={}
    def exports(module):
        if module not in cache:cache[module]=PE(a.modules/module).exports()
        return cache[module]
    def resolve(module,symbol,seen=()):
        pair=(module,symbol)
        if pair in seen:raise ValueError('forwarder loop')
        available=exports(module)
        if symbol not in available:raise ValueError('unavailable guest symbol '+module+'!'+symbol)
        forwarded=available[symbol]
        if forwarded:
            target,name=forwarded.rsplit('.',1);resolve(target.lower()+('.dll' if not target.lower().endswith('.dll') else ''),name,(*seen,pair))
    try:
        for name,(source,entry,libs) in TARGETS.items():
            src=ROOT/source;exe=out/(name+'.exe');cmd=[str(cc),'-Os','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-nostdlib','-Wl,--entry,_'+entry+'@0','-Wl,--subsystem,console:5.1','-Wl,--major-os-version,5,--minor-os-version,1','-Wl,--no-insert-timestamp',str(src),'-o',str(exe),*['-l'+lib for lib in libs],'-lgcc']
            row={'source':source,'source_sha256':sha(src),'command':cmd};report['tools'][name]=row
            r=subprocess.run(cmd,capture_output=True);(out/(name+'.log')).write_bytes(r.stdout+r.stderr);row['compiler_exit']=r.returncode
            if r.returncode:raise ValueError('compilation failed: '+name)
            pe=PE(exe);row['pe']=pe.inspect()
            if (pe.u16(pe.opt+40),pe.u16(pe.opt+42),pe.u16(pe.opt+48),pe.u16(pe.opt+50))!=(5,1,5,1):raise ValueError('not an NT 5.1 PE')
            for module,symbols in pe.imports().items():
                if module not in {lib+'.dll' for lib in libs}:raise ValueError('unapproved runtime: '+module)
                for symbol in symbols:resolve(module,symbol)
            row['guest_imports_resolved']=True
        report['passed']=True
    except Exception as e:
        report['passed']=False;report['error']=str(e);raise
    finally:(out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':True,'binaries':{n:r['pe']['sha256'] for n,r in report['tools'].items()}},indent=2))
if __name__=='__main__':main()
