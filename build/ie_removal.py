"""Remove Internet Explorer 8 from an XP25 image that already has Supermium installed.

Deleted: the IE browser, its HTML engine (MSHTML), the JScript and VBScript engines,
mshta.exe, Internet Options and IE's per-user setup programs, with their language
files and the Windows File Protection copies in dllcache. Their COM classes and type
libraries are unregistered and the files are queued for deletion by the Session
Manager at the next boot, before WFP starts (browserctl delete-at-boot), with
AllowProtectedRenames set, without which it skips WFP-protected files.

Kept, because Windows itself needs them: WinINet, URLMon, Shdocvw, BrowseUI,
IEFrame and IERtUtil (Explorer imports or loads them), and ieproxy.dll, which
marshals 270 COM interfaces including Explorer's own. See KEPT.

Replaced: the User Accounts panel (nusrmgr.cpl runs on mshta) by xp25users.cpl,
which opens the classic netplwiz dialog; Start-menu Help by XP25Help (see
build/prepare_native_help.py); the Search Companion (HTML) by Explorer's classic
search. Nothing of this is reversible inside the guest: the previous disk is the
rollback."""
import json
from pathlib import Path

SYSTEM32 = ['mshtml.dll', 'mshtmled.dll', 'mshtmler.dll', 'mshtml.tlb', 'iepeers.dll', 'jscript.dll', 'vbscript.dll',
            'jsproxy.dll', 'mshta.exe', 'mshta.exe.mui', 'inetcpl.cpl', 'ie4uinit.exe', 'ie4uinit.exe.mui', 'ieudinit.exe',
            'BrowserChoice.exe']
LANGUAGE = ['mshtml.dll.mui', 'mshtmler.dll.mui', 'iepeers.dll.mui', 'jscript.dll.mui', 'vbscript.dll.mui',
            'mshta.exe.mui', 'inetcpl.cpl.mui', 'ie4uinit.exe.mui', 'ieudinit.exe.mui']
DLLCACHE = ['mshtml.dll', 'mshtmled.dll', 'mshtmler.dll', 'mshtml.tlb', 'iepeers.dll', 'jscript.dll', 'vbscript.dll',
            'jsproxy.dll', 'mshta.exe', 'inetcpl.cpl', 'ie4uinit.exe', 'iexplore.exe']
# Everything in %ProgramFiles%\Internet Explorer goes except these.
IE_FOLDER_KEEP = ['ieproxy.dll']
# Servers whose COM classes and type libraries are removed before the files go.
UNREGISTER = ['%S%\\' + n for n in ('mshtml.dll', 'mshtmled.dll', 'mshtml.tlb', 'iepeers.dll', 'jscript.dll', 'vbscript.dll',
                                     'jsproxy.dll', 'mshta.exe', 'inetcpl.cpl')] + ['%IE%\\iexplore.exe']
# IE's per-user setup: version update, icons, branding. Without them a new user gets no IE links.
ACTIVE_SETUP = ['{12d0ed0d-0ee0-4f90-8827-78cefb8f4988}', '{26923b43-4d38-484f-9b9e-de460746276c}',
                '{60B49E34-C7CC-11D0-8953-00A0C90347FF}']
KEPT = {
    'wininet.dll': 'Win32 Internet API; 91 system consumers (services, shell, update clients)',
    'urlmon.dll': 'URL monikers, downloads and zones; 70 consumers including the shell',
    'shdocvw.dll': 'imported by Explorer',
    'browseui.dll': 'imported by Explorer; folder-window navigation',
    'ieframe.dll': 'loaded by Explorer (IE8 moved shell browser code here)',
    'iertutil.dll': 'runtime support for the four above',
    'ieproxy.dll': 'proxy/stub for 270 COM interfaces, among them Explorer\'s (taskbar bands, travel log, notifications)',
    'nusrmgr.cpl': 'kept on disk only for its icon; hidden from the Control Panel',
    'hh.exe, hhctrl.ocx': 'HTML Help; cannot show .chm pages without MSHTML',
    'dxtrans.dll, dxtmsft.dll, pngfilt.dll, imgutil.dll': 'image and transition filters also used outside IE',
    'webcheck.dll, msfeeds.dll, occache.dll, iedkcs32.dll, ieakeng.dll, ieaksie.dll': 'IE support libraries that load '
        'nothing removed by themselves; webcheck starts with Explorer, iedkcs32 is a Group Policy extension',
}
PROFILES = ['Administrator', 'Default User']
IE_LINKS = [r'Desktop\Internet Explorer.lnk', r'Start Menu\Internet Explorer.lnk', r'Start Menu\Programs\Internet Explorer.lnk',
            r'Application Data\Microsoft\Internet Explorer\Quick Launch\Launch Internet Explorer Browser.lnk',
            r'Application Data\Microsoft\Internet Explorer\Quick Launch\Internet Explorer.lnk',
            r'Start Menu\Programs\Accessories\System Tools\Internet Explorer (No Add-ons).lnk']
INTERNET_ICON = '{871C5380-42A0-1069-A2EA-08002B30309D}'


def user_reg(root):
    """Per-user settings under a registry root (HKEY_CURRENT_USER or a loaded hive)."""
    lines = ['[' + root + r'\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState]',
             '"Use Search Asst"="no"', '',
             '[' + root + r'\Software\Clients\StartMenuInternet]', '@="XP25Browser.exe"', '',
             '[' + root + r'\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer]',
             '"NoInternetIcon"=dword:00000001', '"NoActiveDesktop"=dword:00000001', '']
    for view in ('NewStartPanel', 'ClassicStartMenu'):
        lines += ['[' + root + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\' + view + ']',
                  '"' + INTERNET_ICON + '"=dword:00000001', '']
    return lines


def machine_reg():
    lines = [r'[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\IEXPLORE.EXE]', '',
             r'[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Applications\iexplore.exe]', '']
    for c in ACTIVE_SETUP:
        lines += ['[-HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\' + c + ']', '']
    # File types and protocols whose only verbs run the removed programs.
    for key in (r'htafile\shell', r'mhtmlfile\shell', r'ftp\shell', r'htmlfile\shell\print', r'htmlfile\shell\printto',
                r'htmfile\shell\print', r'htmfile\shell\printto'):
        lines += [r'[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes' + '\\' + key + ']', '']
    lines += [r"[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\don't load]",
              '"nusrmgr.cpl"="no"', '"inetcpl.cpl"="no"', '',
              r'[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\Extended Properties\{305CA226-D286-468e-B848-2B2E8E697B74} 2]',
              r'"%SystemRoot%\\system32\\xp25users.cpl"=dword:00000009', '',
              r'[HKEY_LOCAL_MACHINE\SOFTWARE\XP25\Browser]',
              '"InternetExplorer"="Removed: IE8, MSHTML, JScript, VBScript, mshta and Internet Options. '
              'Kept for Windows: WinINet, URLMon, Shdocvw, BrowseUI, IEFrame, IERtUtil, ieproxy.dll"', '']
    return lines


def removal_cmd():
    q = lambda s: '"' + s + '"'
    rows = ['@echo off', 'setlocal', r'set B=%ProgramFiles%\XP25Browser', r'set S=%SystemRoot%\system32',
            r'set IE=%ProgramFiles%\Internet Explorer', r'set D=%SystemDrive%\Documents and Settings',
            r'if not exist "%B%\installed.ok" exit /b 81', r'if exist "%B%\ie-removed.ok" exit /b 0',
            r'copy /y "%~dp0xp25users.cpl" "%S%\xp25users.cpl" >nul', 'if errorlevel 1 exit /b 1',
            'echo XP25_IE_STEP=unregister']
    rows += ['"%B%\\browserctl.exe" unregister-file ' + q(path) + ' || exit /b 2' for path in UNREGISTER]
    rows += ['echo XP25_IE_STEP=registry', r'reg import "%~dp0remove-ie.reg"', 'if errorlevel 1 exit /b 3',
             r'reg import "%~dp0remove-ie-user.reg"', 'if errorlevel 1 exit /b 3']
    # Other profiles: their own registry hive and links; Supermium links copied from this user's.
    for i, profile in enumerate(PROFILES):
        p = r'%D%' + '\\' + profile
        rows += ['if not exist "' + p + r'\NTUSER.DAT" goto noprofile' + str(i),
                 r'reg load HKU\XP25IE "' + p + r'\NTUSER.DAT"', 'if errorlevel 1 exit /b 4',
                 r'reg import "%~dp0remove-ie-hive.reg"', 'set R=%ERRORLEVEL%', r'reg unload HKU\XP25IE',
                 'if not "%R%"=="0" exit /b 4']
        rows += ['del /q "' + p + '\\' + link + '" 2>nul' for link in IE_LINKS]
        rows += ['mkdir "' + p + r'\Start Menu\Programs" 2>nul',
                 r'copy /y "%USERPROFILE%\Start Menu\Programs\Supermium.lnk" "' + p + r'\Start Menu\Programs\Supermium.lnk" >nul',
                 'mkdir "' + p + r'\Application Data\Microsoft\Internet Explorer\Quick Launch" 2>nul',
                 r'copy /y "%USERPROFILE%\Start Menu\Programs\Supermium.lnk" "' + p + r'\Application Data\Microsoft\Internet Explorer\Quick Launch\Supermium.lnk" >nul',
                 ':noprofile' + str(i)]
    # The Session Manager skips Windows File Protection's files unless this is set; hotfix
    # installers set it for the same reason. It applies to the operations of the next boot.
    rows += ['echo XP25_IE_STEP=schedule',
             r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v AllowProtectedRenames /t REG_DWORD /d 1 /f',
             'if errorlevel 1 exit /b 5']
    # Parentheses keep each || with its own command inside if and for.
    for folder, names in (('%S%', SYSTEM32), ('%S%\\en-US', LANGUAGE), ('%S%\\dllcache', DLLCACHE)):
        rows += ['if exist "' + folder + '\\' + n + '" ("%B%\\browserctl.exe" delete-at-boot "' + folder + '\\' + n + '" || exit /b 5)' for n in names]
    keep = ' '.join('if /i not "%%~nxF"=="' + n + '"' for n in IE_FOLDER_KEEP)
    rows += ['for %%F in ("%IE%\\*") do ' + keep + ' ("%B%\\browserctl.exe" delete-at-boot "%%~F" || exit /b 5)',
             r'for /d %%F in ("%IE%\*") do ("%B%\browserctl.exe" delete-at-boot "%%~F" || exit /b 5)',
             r'echo removal scheduled > "%B%\ie-removed.ok"', 'exit /b 0']
    return rows


def generate(out):
    """remove-ie.cmd (run as an administrator after install.cmd), its three .reg files and ie-removal.json."""
    out = Path(out)
    (out / 'remove-ie.cmd').write_bytes(('\r\n'.join(removal_cmd()) + '\r\n').encode('ascii'))
    for name, lines in [('remove-ie.reg', machine_reg()), ('remove-ie-user.reg', user_reg('HKEY_CURRENT_USER')),
                        ('remove-ie-hive.reg', user_reg(r'HKEY_USERS\XP25IE'))]:
        (out / name).write_bytes(('\r\n'.join(['Windows Registry Editor Version 5.00', ''] + lines) + '\r\n').encode('utf-16'))
    record = {'system32': SYSTEM32, 'system32_en_us': LANGUAGE, 'dllcache': DLLCACHE, 'ie_folder_kept': IE_FOLDER_KEEP,
              'unregistered_servers': UNREGISTER, 'active_setup_removed': ACTIVE_SETUP, 'kept': KEPT, 'profiles': PROFILES}
    (out / 'ie-removal.json').write_text(json.dumps(record, indent=2) + '\n')
    return record
