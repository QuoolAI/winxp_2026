#!/usr/bin/env python3
"""Prepare an experimental native Help app and one reversible Explorer resource.
Only the Start-menu Help command changes. Legacy Help executable/COM/CHM/HLP
handlers and the original helpctr App Paths registration remain untouched.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from pe_resources import Resources,strings
from prepare_branding import string_replace
from install_branding_overlay import verify_pair

ROOT=Path(__file__).resolve().parents[1]
EXPLORER_SHA='487830836b1543a2e8fd2600b0bb08fb9145d8bf303afbf9817d0151e4f8af1e'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['explorer','exe','browserctl','output']:p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();out=a.output.resolve()
    if any(not path.resolve().is_relative_to(ROOT/'.work') for path in [a.explorer,a.exe,a.browserctl,out]):p.error('private .work inputs/outputs required')
    if sha(a.explorer)!=EXPLORER_SHA:raise ValueError('unrecognized accepted native Explorer')
    out.mkdir(parents=True,exist_ok=False);media=out/'media';media.mkdir()
    r=Resources(a.explorer);key=(6,732//16+1,1033);before=strings(r.entries[key]['data'])
    string_replace(r,732,'helpctr.exe>-FromStartHelp','XP25Help.exe')
    generated=out/'explorer-native-help.exe';edited=r.write(generated);verify_pair(a.explorer,generated,[list(key)])
    after=strings(Resources(generated).entries[key]['data'])
    if any(x!=y for i,(x,y) in enumerate(zip(before,after)) if i!=732%16):raise ValueError('another string changed')
    shutil.copy2(a.exe,media/'XP25Help.exe');shutil.copy2(a.browserctl,media/'rollbackctl.exe');shutil.copy2(ROOT/'components/help/XP25Help.exe.manifest',media/'XP25Help.exe.manifest')
    scopes=[('HKLM',r'Software\Microsoft\Windows\CurrentVersion\App Paths\XP25Help.exe'),('HKCU',r'Software\Microsoft\Windows\CurrentVersion\App Paths\XP25Help.exe')]
    reg=['Windows Registry Editor Version 5.00',''];install=['@echo off','setlocal','set H=%ProgramFiles%\\XP25Help','if exist "%H%\\installed.ok" exit /b 0','if exist "%H%\\XP25Help.exe" exit /b 80','mkdir "%H%" 2>nul','copy /y "%~dp0rollbackctl.exe" "%H%\\rollbackctl.exe" >nul','if errorlevel 1 exit /b 1'];rollback=['@echo off','setlocal','set H=%ProgramFiles%\\XP25Help','set FAILED=0']
    for i,(short,path) in enumerate(scopes,3000):
        install+=['"%H%\\rollbackctl.exe" key-save '+short+' "'+path+'" '+str(i),'if errorlevel 1 exit /b 1']
        rollback+=['"%H%\\rollbackctl.exe" key-restore '+short+' "'+path+'" '+str(i),'if errorlevel 1 set FAILED=1']
        long='HKEY_LOCAL_MACHINE' if short=='HKLM' else 'HKEY_CURRENT_USER'
        app_path=r'C:\Program Files\XP25Help\XP25Help.exe'
        reg+=['['+long+'\\'+path+']','@="'+app_path.replace('\\','\\\\')+'"','']
    (media/'native-help.reg').write_bytes(('\r\n'.join(reg)+'\r\n').encode('utf-16'))
    install+=['copy /y "%~dp0XP25Help.exe" "%H%\\XP25Help.exe" >nul','if errorlevel 1 goto fail','copy /y "%~dp0XP25Help.exe.manifest" "%H%\\XP25Help.exe.manifest" >nul','if errorlevel 1 goto fail','copy /y "%~dp0rollback.cmd" "%H%\\rollback.cmd" >nul','if errorlevel 1 goto fail','reg import "%~dp0native-help.reg"','if errorlevel 1 goto fail','echo '+sha(a.exe)+' > "%H%\\installed.ok"','exit /b 0',':fail','call "%~dp0rollback.cmd"','exit /b 1']
    rollback+=['if "%FAILED%"=="1" exit /b 1','del /q "%H%\\installed.ok" 2>nul','echo Explorer resource recovery: restore C:\\xp25-help-explorer-before.exe offline in a NEW overlay.','exit /b 0']
    for name,lines in [('install.cmd',install),('rollback.cmd',rollback)]: (media/name).write_bytes(('\r\n'.join(lines)+'\r\n').encode())
    suite=r'''@echo off
call D:\install.cmd > C:\xp25-help-install.log 2>&1
echo XP25_HELP_INSTALL_EXIT=%ERRORLEVEL% > COM1
start "" /wait "C:\Program Files\XP25Help\XP25Help.exe" --self-test > COM1
echo XP25_HELP_SELF_TEST_EXIT=%ERRORLEVEL% > COM1
type C:\xp25-help-selftest.log > COM1
start "" "C:\Program Files\XP25Help\XP25Help.exe"
del "%USERPROFILE%\Start Menu\Programs\Startup\XP25BrowserSuite.cmd"
echo XP25_HELP_READY > COM1
''';(out/'suite.cmd').write_bytes(suite.replace('\n','\r\n').encode())
    command=['genisoimage','-quiet','-J','-r','-o',str(out/'help.iso'),str(media)];subprocess.run(command,check=True)
    (out/'manifest.json').write_text(json.dumps({'status':'unaccepted_native_help_candidate','original_explorer':str(a.explorer.resolve()),'original_explorer_sha256':EXPLORER_SHA,'patched_explorer':str(generated),'patched_explorer_sha256':sha(generated),'resource_change':{'id':732,'before':before[732%16],'after':after[732%16]},'resource_verification':edited,'legacy_handlers_changed':False,'files':{f.name:sha(f) for f in media.iterdir()},'commands':[command]},indent=2)+'\n');print(out/'help.iso')
if __name__=='__main__':main()
