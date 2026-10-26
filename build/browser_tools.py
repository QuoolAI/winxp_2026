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
WINDOWED={'XP25Help','XP25Browser'}
TARGETS={'browserctl':('components/browser/browserctl.c','BrowserMain',['kernel32','user32','shell32','shlwapi','ole32','uuid','advapi32','psapi','msvcrt']),
         'XP25Browser':('components/browser/browserctl.c','LauncherMain',['kernel32','user32','shell32','shlwapi','ole32','uuid','advapi32','psapi','msvcrt']),
         'browser_shell':('tests/guest/browser_shell.c','ShellProbeMain',['kernel32','user32','advapi32','shell32','shlwapi','ole32','uuid','msvcrt']),
         'browser_bridge':('tests/guest/browser_bridge.c','BridgeMain',['kernel32','ws2_32','msvcrt']),
         'browser_wait':('tests/guest/browser_wait.c','WaitMain',['kernel32']),
         'browser_commandline':('tests/guest/browser_commandline.c','FixtureMain',['kernel32','user32','advapi32','shell32','psapi','msvcrt']),
         'browser_crash':('tests/guest/browser_crash.c','CrashMain',['kernel32','advapi32','user32']),
         'browser_debug':('tests/guest/browser_debug.c','DebugMain',['kernel32','user32','advapi32','shell32','psapi','dbghelp','msvcrt']),
         'browser_sandbox':('tests/guest/browser_sandbox.c','SandboxMain',['kernel32','user32','advapi32','psapi','msvcrt']),
         'XP25Help':('components/help/native_help.c','HelpMain',['kernel32','user32','gdi32','shell32','msvcrt']),
         'browser_iocancel':('tests/guest/browser_iocancel.c','IoCancelMain',['kernel32','user32','msvcrt']),
         'browser_watch':('tests/guest/browser_watch.c','WatchMain',['kernel32','user32','shell32','msvcrt']),
         'browser_launch':('tests/guest/browser_launch.c','LaunchMain',['kernel32','user32','advapi32','msvcrt'])}
# Browser-scoped DLLs: (source, entry, stdcall argument bytes, definition, libraries).
DLLS={'pwrp_k32':('components/browser/xp25_pwrp.c','Xp25PwrpEntry',12,'components/browser/pwrp_k32.def',['kernel32'])}
# The NT 5.1 librarian accepts module.name forwarders only when an import
# library on its command line supplies them (cf. sfc_fwd, wsock32).
SYSTEM_IMPORT_LIBS={'user32'}

def forwarder_modules(definition):
    """Forwarded-to module -> names, from a generated proxy .def."""
    modules={}
    for name,(_,forwarder) in definition_exports(definition).items():
        if forwarder:
            module,target=forwarder.split('.',1);modules.setdefault(module,[]).append(target)
    return modules

def definition_exports(path):
    """Name -> (ordinal, forwarder or None) from a generated proxy .def."""
    rows={}
    for text in Path(path).read_text().splitlines():
        if not text.startswith('    '):continue
        name,rest=text.strip().split('=',1);target,ordinal=rest.split(' @')
        rows[name]=(int(ordinal),target if '.' in target else None)
    return rows

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def check_exports(pe,expected):
    """Require the exact names, ordinals and forwarders of the definition."""
    actual=pe.exports();by_ordinal={k:v for k,v in actual.items() if k.startswith('#')}
    names={k for k in actual if not k.startswith('#')}
    if names!=set(expected):raise ValueError('proxy export names differ from the definition')
    for name,(ordinal,forwarder) in expected.items():
        if '#'+str(ordinal) not in by_ordinal or actual[name]!=by_ordinal['#'+str(ordinal)]:raise ValueError('ordinal mismatch: '+name)
        if actual[name]!=forwarder:raise ValueError('forwarder mismatch: '+name)

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
            src=ROOT/source;exe=out/(name+'.exe');cmd=[str(cc),'-Os','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-nostdlib','-Wl,--entry,_'+entry+'@0','-Wl,--subsystem,'+('windows' if name in WINDOWED else 'console')+':5.1','-Wl,--major-os-version,5,--minor-os-version,1','-Wl,--no-insert-timestamp',str(src),'-o',str(exe),*['-l'+lib for lib in libs],'-lgcc']
            row={'source':source,'source_sha256':sha(src),'command':cmd};report['tools'][name]=row
            r=subprocess.run(cmd,capture_output=True);(out/(name+'.log')).write_bytes(r.stdout+r.stderr);row['compiler_exit']=r.returncode
            if r.returncode:raise ValueError('compilation failed: '+name)
            pe=PE(exe);row['pe']=pe.inspect()
            if (pe.u16(pe.opt+40),pe.u16(pe.opt+42),pe.u16(pe.opt+48),pe.u16(pe.opt+50))!=(5,1,5,1):raise ValueError('not an NT 5.1 PE')
            for module,symbols in pe.imports().items():
                if module not in {lib+'.dll' for lib in libs}:raise ValueError('unapproved runtime: '+module)
                for symbol in symbols:resolve(module,symbol)
            row['guest_imports_resolved']=True
        for name,(source,entry,stack,definition,libs) in DLLS.items():
            src=ROOT/source;dll=out/(name+'.dll')
            cmd=[str(cc),'-Os','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-nostdlib','-shared','-Wl,--entry,_%s@%d'%(entry,stack),'-Wl,--enable-stdcall-fixup','-Wl,--subsystem,windows:5.1','-Wl,--major-os-version,5,--minor-os-version,1','-Wl,--no-insert-timestamp',str(src),str(ROOT/definition),'-o',str(dll),*['-l'+lib for lib in libs],'-lgcc']
            row={'source':source,'source_sha256':sha(src),'definition':definition,'definition_sha256':sha(ROOT/definition),'command':cmd};report['tools'][name]=row
            r=subprocess.run(cmd,capture_output=True);(out/(name+'.log')).write_bytes(r.stdout+r.stderr);row['compiler_exit']=r.returncode
            if r.returncode:raise ValueError('compilation failed: '+name)
            pe=PE(dll);row['pe']=pe.inspect()
            if (pe.u16(pe.opt+40),pe.u16(pe.opt+42),pe.u16(pe.opt+48),pe.u16(pe.opt+50))!=(5,1,5,1):raise ValueError('not an NT 5.1 PE')
            if not pe.u16(pe.pe+22)&0x2000:raise ValueError('not a DLL')
            for module,symbols in pe.imports().items():
                if module not in {lib+'.dll' for lib in libs}:raise ValueError('unapproved runtime: '+module)
                for symbol in symbols:resolve(module,symbol)
            check_exports(pe,definition_exports(ROOT/definition))
            row['guest_imports_resolved']=row['exports_match_definition']=True
        report['passed']=True
    except Exception as e:
        report['passed']=False;report['error']=str(e);raise
    finally:(out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':True,'binaries':{n:r['pe']['sha256'] for n,r in report['tools'].items()}},indent=2))
if __name__=='__main__':main()
