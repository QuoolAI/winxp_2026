#!/usr/bin/env python3
"""Add native diagnostics to verified private browser media; never a ship image."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def containment_suite():
    """Launch through the windowed launcher and through a shell association, then
    test the live browser tokens against administrator-only objects."""
    rows=[r'@echo off',r'mkdir C:\xp25 2>nul',r'mkdir C:\xp25\browserdiag 2>nul',
          r'call D:\install.cmd > C:\xp25\browserdiag\install.log 2>&1',r'echo XP25_DIAGNOSTIC_INSTALL_EXIT=%ERRORLEVEL% > COM1',r'if errorlevel 1 goto done',
          r'D:\browser_shell.exe > COM1',r'echo XP25_CONTAIN_SHELL_EXIT=%ERRORLEVEL% > COM1']
    for tag,launch in [('LAUNCHER',r'"%ProgramFiles%\XP25Browser\XP25Browser.exe" open-url "http://xp25.test:8080/local.html?case=containment-launcher"'),
                       ('ASSOCIATION',r'D:\browserctl.exe shell "http://xp25.test:8080/local.html?case=containment-association"')]:
        rows+=[launch+' > COM1','echo XP25_CONTAIN_'+tag+'_LAUNCH=%ERRORLEVEL% > COM1']+[r'D:\wait.exe']*6
        rows+=[r'D:\browser_sandbox.exe > COM1','echo XP25_CONTAIN_'+tag+'_PROBE=%ERRORLEVEL% > COM1',
               'D:\\browserctl.exe inventory > C:\\xp25\\browserdiag\\'+tag.lower()+'-inventory.log',r'D:\browserctl.exe close > COM1']+[r'D:\wait.exe']*3
    rows+=[':done',r'del "%USERPROFILE%\Start Menu\Programs\Startup\XP25BrowserSuite.cmd"','echo XP25_DIAGNOSTIC_DONE > COM1',r'D:\wait.exe','shutdown.exe -s -t 5']
    return '\n'.join(rows)+'\n'

def watch_ab_suite(cycles,hold):
    """Alternate Supermium's original wrapper and the XP25 proxy in equal blocks,
    under the debugger and unmonitored, verifying the installed layout each time."""
    if not 1<=cycles<=40 or not 10<=hold<=300:raise ValueError('cycles 1..40 and hold 10..300 required')
    rows=[r'@echo off',r'mkdir C:\xp25 2>nul',r'mkdir C:\xp25\browserdiag 2>nul',
          r'call D:\install.cmd > C:\xp25\browserdiag\install.log 2>&1',r'echo XP25_DIAGNOSTIC_INSTALL_EXIT=%ERRORLEVEL% > COM1',r'if errorlevel 1 goto done',
          r'set P=%ProgramFiles%\Supermium',r'mkdir C:\xp25\watchdir',
          r'copy /y "%P%\pwrp_k32.dll" C:\xp25\watchdir\pwrp_k32_sm.dll >nul',r'copy /y D:\xp25compat\pwrp_k32.dll C:\xp25\watchdir\pwrp_k32.dll >nul',
          r'D:\browser_iocancel.exe > COM1',r'echo XP25_DIAGNOSTIC_IOCANCEL_EXIT=%ERRORLEVEL% > COM1',
          r'D:\browser_watch.exe C:\xp25\watchdir > COM1',r'echo XP25_DIAGNOSTIC_WATCH_EXIT=%ERRORLEVEL% > COM1']
    for mode,prefix in [('debug','d'),('plain','p')]:
        for block in (1,2):
            for layout in ('orig','prox'):
                tag=prefix+layout+str(block)
                rows+=['call :'+layout,'echo XP25_AB_LAYOUT_'+tag.upper()+'=%ERRORLEVEL% > COM1',
                       r'D:\browser_debug.exe %s %d %d %s > COM1'%(mode,cycles,hold,tag),'echo XP25_AB_'+tag.upper()+'_EXIT=%ERRORLEVEL% > COM1']
    rows+=['call :orig',r'D:\browserctl.exe inventory > C:\xp25\browserdiag\after.txt',':done',
           r'del "%USERPROFILE%\Start Menu\Programs\Startup\XP25BrowserSuite.cmd"','echo XP25_DIAGNOSTIC_DONE > COM1',
           r'D:\wait.exe',r'D:\wait.exe','shutdown.exe -s -t 5','goto :eof',
           ':orig',r'copy /y C:\xp25\watchdir\pwrp_k32_sm.dll "%P%\pwrp_k32.dll" >nul',r'if exist "%P%\pwrp_k32_sm.dll" del /q "%P%\pwrp_k32_sm.dll"',
           r'if exist "%P%\pwrp_k32_sm.dll" exit /b 2',r'fc /b C:\xp25\watchdir\pwrp_k32_sm.dll "%P%\pwrp_k32.dll" >nul',r'exit /b %ERRORLEVEL%',
           ':prox',r'copy /y C:\xp25\watchdir\pwrp_k32_sm.dll "%P%\pwrp_k32_sm.dll" >nul',r'copy /y D:\xp25compat\pwrp_k32.dll "%P%\pwrp_k32.dll" >nul',
           r'fc /b C:\xp25\watchdir\pwrp_k32_sm.dll "%P%\pwrp_k32_sm.dll" >nul',r'if errorlevel 1 exit /b 3',r'fc /b D:\xp25compat\pwrp_k32.dll "%P%\pwrp_k32.dll" >nul',r'exit /b %ERRORLEVEL%']
    return '\n'.join(rows)+'\n'

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['prepared','native','output']:p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--mode',choices=['debug','plain','watch-ab','containment'],required=True)
    p.add_argument('--cycles',type=int,default=5,help='watch-ab: cycles per block')
    p.add_argument('--hold',type=int,default=45,help='watch-ab: seconds before close; Chromium reclaims idle pool workers after 30')
    a=p.parse_args();out=a.output.resolve()
    if any(not path.resolve().is_relative_to(ROOT/'.work') for path in [a.prepared,a.native,out]):p.error('private .work inputs/output required')
    manifest=json.loads((a.prepared/'manifest.json').read_text())
    for name,digest in manifest['files'].items():
        if sha(a.prepared/'media'/name)!=digest:raise ValueError('prepared file changed: '+name)
    out.mkdir(parents=True,exist_ok=False);media=out/'media'
    shutil.copytree(a.prepared/'media',media,copy_function=lambda src,dst:subprocess.run(['cp','--reflink=always',src,dst],check=True) and dst)
    for name in ['browser_debug','browser_sandbox','browser_iocancel','browserctl']+(['browser_watch'] if a.mode=='watch-ab' else [])+(['browser_shell'] if a.mode=='containment' else []):
        shutil.copy2(a.native/(name+'.exe'),media/(name+'.exe'))
    if a.mode=='watch-ab':
        (media/'xp25compat').mkdir();shutil.copy2(a.native/'pwrp_k32.dll',media/'xp25compat/pwrp_k32.dll')
    shutil.copy2(a.native/'browser_wait.exe',media/'wait.exe')
    suite=r'''@echo off
mkdir C:\xp25 2>nul
mkdir C:\xp25\browserdiag 2>nul
call D:\install.cmd > C:\xp25\browserdiag\install.log 2>&1
echo XP25_DIAGNOSTIC_INSTALL_EXIT=%ERRORLEVEL% > COM1
if errorlevel 1 goto done
D:\browser_iocancel.exe > COM1
echo XP25_DIAGNOSTIC_IOCANCEL_EXIT=%ERRORLEVEL% > COM1
D:\browser_debug.exe __MODE__ > COM1
set BROWSER_RESULT=%ERRORLEVEL%
echo XP25_DIAGNOSTIC_BROWSER_EXIT=%BROWSER_RESULT% > COM1
if "%BROWSER_RESULT%"=="0" goto inventory
D:\browser_debug.exe snapshot > COM1
echo XP25_DIAGNOSTIC_SNAPSHOT_EXIT=%ERRORLEVEL% > COM1
:inventory
D:\browserctl.exe inventory > C:\xp25\browserdiag\after.txt
D:\browserctl.exe close
:done
del "%USERPROFILE%\Start Menu\Programs\Startup\XP25BrowserSuite.cmd"
echo XP25_DIAGNOSTIC_DONE > COM1
D:\wait.exe
D:\wait.exe
shutdown.exe -s -t 5
'''.replace('__MODE__','plain' if a.mode=='plain' else '')
    if a.mode=='watch-ab':suite=watch_ab_suite(a.cycles,a.hold)
    if a.mode=='containment':suite=containment_suite()
    (out/'suite.cmd').write_bytes(suite.replace('\n','\r\n').encode())
    command=['genisoimage','-quiet','-J','-joliet-long','-r','-o',str(out/'diagnostic.iso'),str(media)]
    subprocess.run(command,check=True)
    (out/'manifest.json').write_text(json.dumps({'status':'private_diagnostics_only','pin':manifest['pin'],'mode':a.mode,'prepared_manifest_sha256':sha(a.prepared/'manifest.json'),'native_collection_sha256':sha(a.native/'collect.json'),'files':{str(f.relative_to(media)):sha(f) for f in media.rglob('*') if f.is_file()},'suite_sha256':sha(out/'suite.cmd'),'iso_sha256':sha(out/'diagnostic.iso'),'commands':[command]},indent=2)+'\n')
    print(out/'diagnostic.iso')
if __name__=='__main__':main()
