#!/usr/bin/env python3
"""Add pinned, already built XP25 test fixtures to verified browser media."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prepared',type=Path,required=True);p.add_argument('--bridge',type=Path,required=True)
    p.add_argument('--shell-probe',type=Path,required=True);p.add_argument('--ai-probe',type=Path,required=True)
    p.add_argument('--wait-probe',type=Path,required=True,help='test-only five-second native Sleep fixture')
    p.add_argument('--regression',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();out=a.output.resolve()
    if '.work' not in out.parts:p.error('private .work output required')
    out.mkdir(parents=True,exist_ok=False);media=out/'media'
    shutil.copytree(a.prepared/'media',media,copy_function=lambda src,dst:subprocess.run(['cp','--reflink=always',src,dst],check=True) and dst)
    manifest=json.loads((a.prepared/'manifest.json').read_text())
    for relative,digest in manifest['files'].items():
        if sha(media/relative)!=digest:raise ValueError('prepared media changed')
    for path,name in [(a.bridge,'bridge.exe'),(a.shell_probe,'browser_shell.exe'),(a.ai_probe,'ai_probe.exe'),(a.wait_probe,'wait.exe')]:shutil.copy2(path,media/name)
    for path in a.regression.iterdir():
        if path.is_file():shutil.copy2(path,media/path.name)
        else:shutil.copytree(path,media/path.name)
    (media/'fixture.htm').write_bytes((media/'local.html').read_bytes())
    (media/'fixture.url').write_bytes(b'[InternetShortcut]\r\nURL=http://xp25.test:8080/local.html?case=shell-url\r\n')
    (media/'rejected.url').write_bytes(b'[InternetShortcut]\r\nURL=javascript:alert(1)\r\n')
    sample='@echo off\r\nD:\\wait.exe\r\nD:\\wait.exe\r\nD:\\browserctl.exe inventory > C:\\xp25\\browser\\during.txt\r\n'
    (media/'sample.cmd').write_bytes(sample.encode())
    suite=r'''@echo off
mkdir C:\xp25\browser 2>nul
echo XP25_BROWSER_INSTALL_BEGIN > COM1
call D:\install.cmd > C:\xp25\browser\install.log 2>&1
echo XP25_BROWSER_INSTALL_EXIT=%ERRORLEVEL% > COM1
if errorlevel 1 goto regress
D:\browser_shell.exe > COM1
echo XP25_BROWSER_SHELL_EXIT=%ERRORLEVEL% > COM1
D:\browserctl.exe inventory > C:\xp25\browser\before.txt
rem Test-only system proxy: the packaged image retains its original settings.
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /d "10.25.0.1:3128" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyOverride /d "xp25.test;localhost;127.0.0.1;10.25.0.1" /f >nul
D:\browserctl.exe shell "http://xp25.test:8080/local.html?case=shell-http" > COM1
echo XP25_SHELLEXECUTE_HTTP=%ERRORLEVEL% > COM1
ping -n 16 127.0.0.1 >nul
D:\browserctl.exe shell "C:\Program Files\XP25Browser\local.html" > COM1
echo XP25_SHELLEXECUTE_HTML=%ERRORLEVEL% > COM1
D:\browserctl.exe shell "D:\fixture.htm" > COM1
echo XP25_SHELLEXECUTE_HTM=%ERRORLEVEL% > COM1
D:\browserctl.exe shell "D:\fixture.url" > COM1
echo XP25_SHELLEXECUTE_URL=%ERRORLEVEL% > COM1
D:\browserctl.exe open-shortcut "D:\rejected.url" > COM1
echo XP25_SHELLEXECUTE_REJECTED_SCHEME=%ERRORLEVEL% > COM1
D:\browserctl.exe shell "https://example.com/" > COM1
echo XP25_SHELLEXECUTE_HTTPS=%ERRORLEVEL% > COM1
ping -n 16 127.0.0.1 >nul
D:\browserctl.exe inventory > C:\xp25\browser\normal-profile.txt
D:\browserctl.exe close
ping -n 12 127.0.0.1 >nul
start "" /b cmd.exe /c D:\sample.cmd
start "" /b D:\bridge.exe
echo XP25_BROWSER_CDP_STARTING > COM1
start "" /wait "C:\Program Files\Supermium\chrome.exe" --no-first-run --disable-gpu --user-data-dir=C:\xp25\browser\TestProfile --remote-debugging-port=9222 --proxy-server=http://10.25.0.1:3128 --proxy-bypass-list="xp25.test;localhost;127.0.0.1;10.25.0.1" --classic-omnibox --classic-omnibox-border --compact-ui --enable-features=SupermiumCustomTabs,ForceXpTheme --enable-logging --log-file=C:\xp25\browser\test-chrome.log http://xp25.test:8080/local.html
echo XP25_BROWSER_PROCESS_EXIT=%ERRORLEVEL% > COM1
D:\browserctl.exe inventory > C:\xp25\browser\after.txt
echo XP25_BROWSER_PERSISTENCE_STARTING > COM1
start "" /wait "C:\Program Files\Supermium\chrome.exe" --no-first-run --disable-gpu --user-data-dir=C:\xp25\browser\TestProfile --remote-debugging-port=9222 --proxy-server=http://10.25.0.1:3128 --proxy-bypass-list="xp25.test;localhost;127.0.0.1;10.25.0.1" --classic-omnibox --classic-omnibox-border --compact-ui --enable-features=SupermiumCustomTabs,ForceXpTheme http://xp25.test:8080/local.html
echo XP25_BROWSER_REOPEN_EXIT=%ERRORLEVEL% > COM1
:regress
call D:\compat-regress.cmd
echo XP25_BROWSER_REGRESSION_DONE > COM1
mkdir C:\xp25\ai 2>nul
copy /y D:\ai_probe.exe C:\xp25\ai\ai_probe.exe >nul
C:\xp25\ai\ai_probe.exe suite __SLOW__
echo XP25_BROWSER_AI_EXIT=%ERRORLEVEL% > COM1
C:\xp25\ai\ai_probe.exe provider __PROVIDER_SECRET__ __SLOW__
echo XP25_BROWSER_PROVIDER_EXIT=%ERRORLEVEL% > COM1
echo XP25_BROWSER_SUITE_DONE > COM1
del "%USERPROFILE%\Start Menu\Programs\Startup\XP25BrowserSuite.cmd"
ping -n 6 127.0.0.1 >nul
shutdown.exe -s -t 0
'''
    # Guest scheduling delays must not depend on the networking stack under test.
    for count,repeats in [(16,3),(12,2),(6,1)]:
        suite=suite.replace('ping -n '+str(count)+' 127.0.0.1 >nul','\n'.join([r'D:\wait.exe']*repeats))
    (out/'suite.cmd').write_bytes(suite.replace('\n','\r\n').encode())
    cmd=['genisoimage','-quiet','-J','-joliet-long','-r','-o',str(out/'browser-tests.iso'),str(media)]
    subprocess.run(cmd,check=True)
    (out/'manifest.json').write_text(json.dumps({'commands':[cmd],'pin':manifest['pin'],'files':{str(f.relative_to(media)):sha(f) for f in sorted(media.rglob('*')) if f.is_file()},'suite_sha256':sha(out/'suite.cmd'),'iso_sha256':sha(out/'browser-tests.iso'),'test_bridge_scope':'Only fixture gateway to loopback CDP; no test bridge in production package.'},indent=2)+'\n')
    print(out/'browser-tests.iso')
if __name__=='__main__':main()
