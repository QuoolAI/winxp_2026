#!/usr/bin/env python3
"""Add pinned, already built XP25 test fixtures to verified browser media."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def render_suite():
    """Deterministically render the guest regression suite as CRLF bytes.

    This is supplied to vm/browser_lab.py via --suite; the ISO only carries the
    fixtures and probes, never the suite, so the suite can be regenerated and
    diffed independently of the (large, pinned) media image."""
    suite=r'''@echo off
mkdir C:\xp25\browser 2>nul
echo XP25_BROWSER_INSTALL_BEGIN > COM1
call D:\install.cmd > C:\xp25\browser\install.log 2>&1
echo XP25_BROWSER_INSTALL_EXIT=%ERRORLEVEL% > COM1
if errorlevel 1 goto regress
D:\browser_shell.exe > COM1
echo XP25_BROWSER_SHELL_EXIT=%ERRORLEVEL% > COM1
D:\browserctl.exe inventory > C:\xp25\browser\before.txt
rem Test-only approved hosts for the HTTPS cases (exact names the gateway tunnels).
rem The packaged image's policy permits only local files, internal pages and xp25.test.
reg add "HKLM\SOFTWARE\Policies\Supermium\URLAllowlist" /v 101 /d ".example.com" /f >nul
reg add "HKLM\SOFTWARE\Policies\Supermium\URLAllowlist" /v 102 /d ".www.example.com" /f >nul
reg add "HKLM\SOFTWARE\Policies\Supermium\URLAllowlist" /v 103 /d ".expired.badssl.com" /f >nul
reg add "HKLM\SOFTWARE\Policies\Supermium\URLAllowlist" /v 104 /d ".wrong.host.badssl.com" /f >nul
reg add "HKLM\SOFTWARE\Policies\Supermium\URLAllowlist" /v 105 /d ".self-signed.badssl.com" /f >nul
rem Test-only system proxy (unchanged from Phase 1): WinINET per-user settings that
rem route generic WinINET clients at the in-namespace proxy, the internal test host
rem and loopback bypassed. The packaged image retains its original settings.
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /d "10.25.0.1:3128" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyOverride /d "xp25.test;localhost;127.0.0.1;10.25.0.1" /f >nul
rem Phase-2 correction: pin the SAME routing as a managed Supermium policy so EVERY
rem browser launch path honours it (shell association as well as the explicit command
rem line). The per-user WinINET ProxyOverride alone did not reliably bypass the internal
rem test host for shell-launched browser instances, so http://xp25.test was sent to the
rem CONNECT-only gateway as a plain request and refused. This is a guest routing setting
rem only: host isolation is enforced by the namespace (no uplink) and the gateway
rem allowlist, which a guest proxy setting cannot weaken. The bypass list is the
rem in-namespace test host and loopback only; every real-Internet destination still
rem traverses the gateway.
reg add "HKLM\SOFTWARE\Policies\Supermium" /v ProxyMode /d "fixed_servers" /f >nul
reg add "HKLM\SOFTWARE\Policies\Supermium" /v ProxyServer /d "10.25.0.1:3128" /f >nul
reg add "HKLM\SOFTWARE\Policies\Supermium" /v ProxyBypassList /d "xp25.test;localhost;127.0.0.1;10.25.0.1" /f >nul
rem Test-only: the fixture server is plain HTTP, and an image prepared with --internet gateway forces
rem HTTPS-only mode; relax it so the fixtures load. Real destinations still traverse the gateway.
reg add "HKLM\SOFTWARE\Policies\Supermium" /v HttpsOnlyMode /d "allowed" /f >nul
rem Test-only: the XP25 Winlogon starts the user's screen saver after 10 idle minutes and the
rem DevTools cases give no input, so the test session's screen saver is switched off.
reg add "HKCU\Control Panel\Desktop" /v ScreenSaveActive /d 0 /f >nul
rundll32.exe user32.dll,UpdatePerUserSystemParameters
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
rem Test-only, for hardened images: the DevTools profile and downloads are in C:\xp25\browser,
rem which inherits an administrators-only ACL there, and the browser runs with the SAFER Normal
rem User token (Administrators deny-only), so the logged-on user gets this folder; the test
rem bridge's port is opened to the lab host only, since those images run Windows Firewall.
cacls C:\xp25\browser /E /G "%USERNAME%":F >nul
echo XP25_BROWSER_TEST_FOLDER_GRANT_EXIT=%ERRORLEVEL% > COM1
netsh firewall add portopening protocol=TCP port=9223 name=XP25TestBridge mode=ENABLE scope=CUSTOM addresses=10.25.0.1 >nul
echo XP25_BROWSER_TEST_BRIDGE_PORT_EXIT=%ERRORLEVEL% > COM1
start "" /b D:\bridge.exe
echo XP25_BROWSER_CDP_STARTING > COM1
D:\browser_launch.exe --no-first-run --disable-gpu --user-data-dir=C:\xp25\browser\TestProfile --remote-debugging-port=9222 --proxy-server=http://10.25.0.1:3128 --proxy-bypass-list="xp25.test;localhost;127.0.0.1;10.25.0.1" --classic-omnibox --classic-omnibox-border --compact-ui --enable-features=SupermiumCustomTabs,ForceXpTheme --enable-logging --log-file=C:\xp25\browser\test-chrome.log http://xp25.test:8080/local.html
echo XP25_BROWSER_PROCESS_EXIT=%ERRORLEVEL% > COM1
D:\browserctl.exe inventory > C:\xp25\browser\after.txt
echo XP25_BROWSER_PERSISTENCE_STARTING > COM1
D:\browser_launch.exe --no-first-run --disable-gpu --user-data-dir=C:\xp25\browser\TestProfile --remote-debugging-port=9222 --proxy-server=http://10.25.0.1:3128 --proxy-bypass-list="xp25.test;localhost;127.0.0.1;10.25.0.1" --classic-omnibox --classic-omnibox-border --compact-ui --enable-features=SupermiumCustomTabs,ForceXpTheme http://xp25.test:8080/local.html
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
    return suite.replace('\n','\r\n').encode()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prepared',type=Path,required=True);p.add_argument('--bridge',type=Path,required=True)
    p.add_argument('--shell-probe',type=Path,required=True);p.add_argument('--ai-probe',type=Path,required=True)
    p.add_argument('--wait-probe',type=Path,required=True,help='test-only five-second native Sleep fixture')
    p.add_argument('--launch-probe',type=Path,required=True,help='test-only SAFER Normal User browser launcher')
    p.add_argument('--regression',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();out=a.output.resolve()
    if '.work' not in out.parts:p.error('private .work output required')
    out.mkdir(parents=True,exist_ok=False);media=out/'media'
    shutil.copytree(a.prepared/'media',media,copy_function=lambda src,dst:subprocess.run(['cp','--reflink=always',src,dst],check=True) and dst)
    manifest=json.loads((a.prepared/'manifest.json').read_text())
    for relative,digest in manifest['files'].items():
        if sha(media/relative)!=digest:raise ValueError('prepared media changed')
    for path,name in [(a.bridge,'bridge.exe'),(a.shell_probe,'browser_shell.exe'),(a.ai_probe,'ai_probe.exe'),(a.wait_probe,'wait.exe'),(a.launch_probe,'browser_launch.exe')]:shutil.copy2(path,media/name)
    for path in a.regression.iterdir():
        if path.is_file():shutil.copy2(path,media/path.name)
        else:shutil.copytree(path,media/path.name)
    (media/'fixture.htm').write_bytes((media/'local.html').read_bytes())
    (media/'fixture.url').write_bytes(b'[InternetShortcut]\r\nURL=http://xp25.test:8080/local.html?case=shell-url\r\n')
    (media/'rejected.url').write_bytes(b'[InternetShortcut]\r\nURL=javascript:alert(1)\r\n')
    sample='@echo off\r\nD:\\wait.exe\r\nD:\\wait.exe\r\nD:\\browserctl.exe inventory > C:\\xp25\\browser\\during.txt\r\n'
    (media/'sample.cmd').write_bytes(sample.encode())
    (out/'suite.cmd').write_bytes(render_suite())
    cmd=['genisoimage','-quiet','-J','-joliet-long','-r','-o',str(out/'browser-tests.iso'),str(media)]
    subprocess.run(cmd,check=True)
    (out/'manifest.json').write_text(json.dumps({'commands':[cmd],'pin':manifest['pin'],'files':{str(f.relative_to(media)):sha(f) for f in sorted(media.rglob('*')) if f.is_file()},'suite_sha256':sha(out/'suite.cmd'),'iso_sha256':sha(out/'browser-tests.iso'),'test_bridge_scope':'Only fixture gateway to loopback CDP; no test bridge in production package.'},indent=2)+'\n')
    print(out/'browser-tests.iso')
if __name__=='__main__':main()
