#!/usr/bin/env python3
"""Stage original NT build-toolchain inputs for the XP25 browser utilities."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from browser_tools import TARGETS,DLLS,ROOT,WINDOWED,SYSTEM_IMPORT_LIBS,forwarder_modules

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve()
    if not out.is_relative_to(ROOT/'.work'):p.error('private .work output required')
    out.mkdir(parents=True,exist_ok=False);media=out/'media';tree=media/'browser';tree.mkdir(parents=True)
    for name,(source,entry,libs) in TARGETS.items():
        d=tree/name;d.mkdir();f=ROOT/source;shutil.copy2(f,d/f.name)
        text='TARGETNAME='+name+'\nTARGETPATH=obj\nTARGETTYPE=PROGRAM\nUMTYPE='+('windows' if name in WINDOWED else 'console')+'\nUMENTRYABS='+entry+'\nUSE_MSVCRT=1\nMSC_WARNING_LEVEL=/W4 /WX /wd4201\nSOURCES='+f.name+'\nTARGETLIBS='+' '.join('$(SDK_LIB_PATH)\\'+lib+'.lib' for lib in libs if lib!='msvcrt')+'\n'
        (d/'sources').write_bytes(text.replace('\n','\r\n').encode());(d/'makefile').write_bytes(b'!INCLUDE $(NTMAKEENV)\\makefile.def\r\n')
    import_libs=[]
    for name,(source,entry,_,definition,libs) in DLLS.items():
        d=tree/name;d.mkdir();f=ROOT/source;shutil.copy2(f,d/f.name);shutil.copy2(ROOT/definition,d/Path(definition).name)
        forwards=[]
        for module,names in sorted(forwarder_modules(ROOT/definition).items()):
            if module in SYSTEM_IMPORT_LIBS:forwards.append('$(SDK_LIB_PATH)\\'+module+'.lib');continue
            # Import library for a non-system forward target, built by build.cmd.
            (d/(module+'.def')).write_bytes(('LIBRARY '+module+'\r\nEXPORTS\r\n'+''.join('    '+n+'\r\n' for n in names)).encode('ascii'))
            import_libs.append(name+'\\'+module);forwards.append(module+'.lib')
        text='TARGETNAME='+name+'\nTARGETPATH=obj\nTARGETTYPE=DYNLINK\nDLLDEF='+Path(definition).name+'\nDLLENTRY='+entry+'\nUMTYPE=windows\nUSE_NOLIBS=1\nMSC_WARNING_LEVEL=/W4 /WX /wd4201\nSOURCES='+f.name+'\nTARGETLIBS='+' '.join('$(SDK_LIB_PATH)\\'+lib+'.lib' for lib in libs)+'\nLINKLIBS='+' '.join(forwards)+'\n'
        (d/'sources').write_bytes(text.replace('\n','\r\n').encode());(d/'makefile').write_bytes(b'!INCLUDE $(NTMAKEENV)\\makefile.def\r\n')
    (tree/'dirs').write_bytes(('DIRS='+' '.join([*TARGETS,*DLLS])+'\r\n').encode())
    cmd=r'''@echo off
setlocal
if exist C:\nt\xp25\browser exit /b 2
mkdir C:\xpout\browser-01
mkdir C:\xpout\browser-01\temp
xcopy /e /i /y D:\browser C:\nt\xp25\browser > C:\xpout\browser-01\copy.log
if errorlevel 1 exit /b 1
call C:\nt\tools\razzle.cmd offline no_urt no_title temp C:\xpout\browser-01\temp binaries_dir C:\xpout\browser-01\binaries > C:\xpout\browser-01\environment.log 2>&1
if not defined NTMAKEENV exit /b 1
pushd C:\nt\xp25\browser
__IMPORT_LIBS__C:\nt\tools\x86\build.exe -cZ > C:\xpout\browser-01\native.log 2>&1
set RESULT=%ERRORLEVEL%
findstr /l /c:"BUILD: nmake.exe failed" C:\xpout\browser-01\native.log >nul
if not errorlevel 1 set RESULT=1
for %%F in (build*.err) do if exist %%F if %%~zF GTR 0 set RESULT=1
echo XP25_BROWSER_NATIVE_RC=%RESULT% > COM1
type C:\xpout\browser-01\native.log > COM1
popd
exit /b %RESULT%
'''
    suite=r'''@echo off
echo XP25_BROWSER_NATIVE_BEGIN > COM1
call D:\build.cmd
echo XP25_BROWSER_NATIVE_WRAPPER=%ERRORLEVEL% > COM1
del "%USERPROFILE%\Start Menu\Programs\Startup\XP25BrowserSuite.cmd"
echo XP25_BROWSER_NATIVE_DONE > COM1
shutdown.exe -s -t 10
'''
    cmd=cmd.replace('__IMPORT_LIBS__',''.join('lib.exe -nologo -machine:i386 -def:'+m+'.def -out:'+m+'.lib > C:\\xpout\\browser-01\\implib.log 2>&1\nif errorlevel 1 exit /b 1\n' for m in import_libs))
    for path,text in [(media/'build.cmd',cmd),(out/'suite.cmd',suite)]:path.write_bytes(text.replace('\n','\r\n').encode())
    command=['genisoimage','-quiet','-J','-r','-o',str(out/'native.iso'),str(media)];subprocess.run(command,check=True)
    (out/'manifest.json').write_text(json.dumps({'commands':[command],'files':{str(f.relative_to(media)):hashlib.sha256(f.read_bytes()).hexdigest() for f in media.rglob('*') if f.is_file()}},indent=2)+'\n');print(out/'native.iso')
if __name__=='__main__':main()
