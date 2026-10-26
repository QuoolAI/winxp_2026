"""Generate the NT 5.1 shell registration and reversible guest installer."""
import json
from pathlib import Path

CLASSIC='--no-first-run --classic-omnibox --classic-omnibox-border --compact-ui --enable-features=SupermiumCustomTabs,ForceXpTheme'
LAUNCHER=r'"C:\Program Files\XP25Browser\XP25Browser.exe"'
# Supermium cannot sandbox renderers on NT 5.1, so the experimental image keeps
# unrestricted Internet browsing disabled. Only local files, internal pages and
# the private lab host load; an administrator adds approved hosts explicitly.
URL_BLOCKLIST=['*']
URL_ALLOWLIST=['file://*','chrome://*','chrome-extension://*','devtools://*','about:blank','.xp25.test']

def installation_suite():
    """Install-only Startup fixture for a fresh browser_lab overlay."""
    return r'''@echo off
call D:\install.cmd > C:\xp25-browser-install.log 2>&1
echo XP25_IMAGE_INSTALL_EXIT=%ERRORLEVEL% > COM1
if errorlevel 1 goto done
D:\browserctl.exe open-url "javascript:alert(1)" > COM1
echo XP25_IMAGE_REJECT_SCRIPT=%ERRORLEVEL% > COM1
D:\browserctl.exe open-url "https://example.com/" unexpected > COM1
echo XP25_IMAGE_REJECT_EXTRA_ARG=%ERRORLEVEL% > COM1
D:\browserctl.exe open-document "D:\registration-scope.json" > COM1
echo XP25_IMAGE_REJECT_NON_HTML=%ERRORLEVEL% > COM1
D:\browserctl.exe inventory > COM1
:done
del "%USERPROFILE%\Start Menu\Programs\Startup\XP25BrowserSuite.cmd"
echo XP25_IMAGE_INSTALL_DONE > COM1
shutdown.exe -s -t 10
'''.replace('\n','\r\n').encode('ascii')

def generate(out,pin,software_rendering=False):
    lines=['Windows Registry Editor Version 5.00',''];snapshots=[]
    # The native adapter validates one target and builds only fixed browser
    # arguments. It avoids XP's --single-argument quote bug and flag injection.
    adapter='"C:\\Program Files\\XP25Browser\\browserctl.exe" '
    exe=adapter+'open-document "%1"'
    def val(v):return '"'+v.replace('\\','\\\\').replace('"','\\"')+'"'
    def key(k,values):
        lines.append('['+k+']')
        for n,v in values.items():lines.append(('@' if n is None else val(n))+'='+('dword:%08x'%v if isinstance(v,int) else val(v)))
        lines.append('')
    def snap(root,path):snapshots.append((root,path))
    for short,long in [('HKLM','HKEY_LOCAL_MACHINE'),('HKCU','HKEY_CURRENT_USER')]:
        classes=long+r'\Software\Classes'
        for name in ['http','https','.htm','.html','.url','XP25.HTML','XP25.URL','htmlfile','htmfile']:
            snap(short,'Software\\Classes\\'+name)
        for protocol in ['http','https']:
            base=classes+'\\'+protocol
            key(base,{None:'URL:'+protocol+' Protocol','URL Protocol':''})
            key(base+r'\shell',{None:'open'});key(base+r'\shell\open\command',{None:adapter+'open-url "%1"'})
            lines.extend(['[-'+base+r'\shell\open\ddeexec]',''])
        for ext in ['.htm','.html']:key(classes+'\\'+ext,{None:'XP25.HTML'})
        key(classes+r'\XP25.HTML',{None:'Supermium HTML Document'})
        key(classes+r'\XP25.HTML\DefaultIcon',{None:r'C:\Program Files\Supermium\chrome.exe,0'})
        key(classes+r'\XP25.HTML\shell\open\command',{None:exe})
        for legacy in ['htmlfile','htmfile']:
            for verb in ['open','opennew','opennewwindow']:
                key(classes+'\\'+legacy+'\\shell\\'+verb+'\\command',{None:exe})
                lines.extend(['[-'+classes+'\\'+legacy+'\\shell\\'+verb+'\\ddeexec]',''])
        key(classes+r'\.url',{None:'XP25.URL'})
        key(classes+r'\XP25.URL',{None:'Internet Shortcut'})
        key(classes+r'\XP25.URL\DefaultIcon',{None:r'C:\Program Files\Supermium\chrome.exe,0'})
        key(classes+r'\XP25.URL\shell\open\command',{None:r'"C:\Program Files\XP25Browser\browserctl.exe" open-shortcut "%1"'})
        snap(short,r'Software\Clients\StartMenuInternet')
        key(long+r'\Software\Clients\StartMenuInternet',{None:'Supermium'})
    lines.extend(['[-HKEY_LOCAL_MACHINE\\SOFTWARE\\Clients\\StartMenuInternet\\IEXPLORE.EXE]',''])
    key(r'HKEY_LOCAL_MACHINE\SOFTWARE\Clients\StartMenuInternet\Supermium',{None:'Supermium'})
    key(r'HKEY_LOCAL_MACHINE\SOFTWARE\Clients\StartMenuInternet\Supermium\DefaultIcon',{None:r'C:\Program Files\Supermium\chrome.exe,0'})
    key(r'HKEY_LOCAL_MACHINE\SOFTWARE\Clients\StartMenuInternet\Supermium\shell\open\command',{None:LAUNCHER})
    snap('HKLM',r'Software\Policies\Supermium')
    lines.extend([r'[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Supermium]',''])
    key(r'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Supermium\URLBlocklist',{str(i+1):v for i,v in enumerate(URL_BLOCKLIST)})
    key(r'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Supermium\URLAllowlist',{str(i+1):v for i,v in enumerate(URL_ALLOWLIST)})
    policy=r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    snap('HKCU',policy);key('HKEY_CURRENT_USER\\'+policy,{'NoInternetIcon':1,'NoActiveDesktop':1})
    for view in ['NewStartPanel','ClassicStartMenu']:
        path='Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\'+view
        snap('HKCU',path);key('HKEY_CURRENT_USER\\'+path,{'{871C5380-42A0-1069-A2EA-08002B30309D}':1})
    snap('HKLM',r'Software\XP25\Browser')
    key(r'HKEY_LOCAL_MACHINE\SOFTWARE\XP25\Browser',{'Name':'Supermium','Version':pin['version'],'Release':pin['tag'],'PackageSHA256':pin['sha256'],'Path':r'C:\Program Files\Supermium\chrome.exe','SoftwareRendering':int(software_rendering),'UpdateMode':'Read-only host check; verified package and explicit approval required',
        'RendererSandbox':'Not available: Supermium disables renderer sandboxing before Windows 10','Containment':'SAFER Normal User token for XP25 entry points',
        'InternetPolicy':'Blocked except local files, internal pages and approved hosts','WatchCompatibility':'XP25 pwrp_k32 proxy (thread-agnostic directory watches)'})
    (out/'associations.reg').write_bytes(('\r\n'.join(lines)+'\r\n').encode('utf-16'))
    cmd=['@echo off','setlocal','set B=%ProgramFiles%\\XP25Browser','set P=%ProgramFiles%\\Supermium',
         'if exist "%B%\\installed.ok" exit /b 0','if exist "%P%\\chrome.exe" exit /b 80',
         'mkdir "%B%" 2>nul','copy /y "%~dp0browserctl.exe" "%B%\\browserctl.exe" >nul','if errorlevel 1 exit /b 1',
         'copy /y "%~dp0rollback.cmd" "%B%\\rollback.cmd" >nul','if errorlevel 1 exit /b 1',
         'copy /y "%~dp0XP25Browser.exe" "%B%\\XP25Browser.exe" >nul','if errorlevel 1 exit /b 1']
    rollback=['@echo off','setlocal','set B=%ProgramFiles%\\XP25Browser','set FAILED=0']
    for i,(root,path) in enumerate(snapshots):
        cmd.extend(['"%B%\\browserctl.exe" key-save '+root+' "'+path+'" '+str(i),'if errorlevel 1 exit /b 1'])
        rollback.extend(['"%B%\\browserctl.exe" key-restore '+root+' "'+path+'" '+str(i),'if errorlevel 1 set FAILED=1'])
    own_links=[r'%USERPROFILE%\Desktop\Supermium.lnk',r'%USERPROFILE%\Start Menu\Programs\Supermium.lnk',r'%APPDATA%\Microsoft\Internet Explorer\Quick Launch\Supermium.lnk']
    cmd.append('mkdir "%B%\\rollback-links" 2>nul')
    for i,l in enumerate(own_links):
        cmd.extend(['if not exist "'+l+'" goto ownabsent'+str(i),'copy /y "'+l+'" "%B%\\rollback-links\\super'+str(i)+'.lnk" >nul','if errorlevel 1 goto fail','goto ownsaved'+str(i),':ownabsent'+str(i),'echo absent > "%B%\\rollback-links\\super'+str(i)+'.absent"',':ownsaved'+str(i)])
        rollback.extend(['if exist "%B%\\rollback-links\\super'+str(i)+'.absent" del /q "'+l+'" 2>nul','if exist "%B%\\rollback-links\\super'+str(i)+'.lnk" copy /y "%B%\\rollback-links\\super'+str(i)+'.lnk" "'+l+'" >nul'])
    cmd.extend(['xcopy /e /i /h /y "%~dp0Supermium" "%P%" >nul','if errorlevel 1 goto fail',
                'reg import "%~dp0associations.reg"','if errorlevel 1 goto fail','"%B%\\browserctl.exe" shortcuts','if errorlevel 1 goto fail'])
    links=[r'%USERPROFILE%\Desktop\Internet Explorer.lnk',r'%USERPROFILE%\Start Menu\Internet Explorer.lnk',r'%USERPROFILE%\Start Menu\Programs\Internet Explorer.lnk',r'%APPDATA%\Microsoft\Internet Explorer\Quick Launch\Launch Internet Explorer Browser.lnk',r'%ALLUSERSPROFILE%\Desktop\Internet Explorer.lnk',r'%ALLUSERSPROFILE%\Start Menu\Programs\Internet Explorer.lnk']
    links.extend([r'%APPDATA%\Microsoft\Internet Explorer\Quick Launch\Internet Explorer.lnk',r'%USERPROFILE%\Start Menu\Programs\Accessories\System Tools\Internet Explorer (No Add-ons).lnk',r'%ALLUSERSPROFILE%\Start Menu\Programs\Accessories\System Tools\Internet Explorer (No Add-ons).lnk'])
    cmd.append('mkdir "%B%\\rollback-links" 2>nul')
    for i,l in enumerate(links):
        cmd.extend(['if not exist "'+l+'" goto link'+str(i),'copy /y "'+l+'" "%B%\\rollback-links\\'+str(i)+'.lnk" >nul','if errorlevel 1 goto fail','del /q "'+l+'"',':link'+str(i)])
        rollback.append('if exist "%B%\\rollback-links\\'+str(i)+'.lnk" copy /y "%B%\\rollback-links\\'+str(i)+'.lnk" "'+l+'" >nul')
    cmd.extend(['copy /y "%~dp0local.html" "%B%\\local.html" >nul','echo '+pin['sha256']+' > "%B%\\installed.ok"','exit /b 0',':fail','call "%B%\\rollback.cmd"','exit /b 1'])
    rollback.extend(['if "%FAILED%"=="1" exit /b 1','del /q "%B%\\installed.ok" 2>nul','"%B%\\browserctl.exe" refresh','exit /b 0'])
    for n,rows in [('install.cmd',cmd),('rollback.cmd',rollback)]: (out/n).write_bytes(('\r\n'.join(rows)+'\r\n').encode('ascii'))
    (out/'registration-scope.json').write_text(json.dumps(snapshots,indent=2)+'\n')
