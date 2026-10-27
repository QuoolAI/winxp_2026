#!/usr/bin/env python3
"""Prepare one SP3 shell ABI correction in a disposable native build copy."""
import argparse,hashlib,json,shutil,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OLD=b"    SECURITY_ATTRIBUTES *psa = CreateAllAccessSecurityAttributes(NULL, NULL, NULL);"
NEW=b"""    // XP25: SP3 SHLWAPI uses ordinal 563, stdcall with no arguments.
    // Ordinal 356 is a different six-argument function in the installed DLL.
    // Use the same descriptor provider as the installed SP3 Explorer.
    typedef SECURITY_ATTRIBUTES* (WINAPI *PFNSP3SECURITYATTRIBUTES)(void);
    HMODULE hShlwapi = GetModuleHandle(TEXT("shlwapi.dll"));
    PFNSP3SECURITYATTRIBUTES pfnSA = hShlwapi ?
        (PFNSP3SECURITYATTRIBUTES)GetProcAddress(hShlwapi, MAKEINTRESOURCEA(563)) : NULL;
    if (!pfnSA)
        return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
    SECURITY_ATTRIBUTES *psa = pfnSA();
    if (!psa)
        return E_OUTOFMEMORY;"""
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve()
 if not out.is_relative_to(ROOT/'.work'):p.error('private output required')
 source=ROOT/'Source/XPSP1/NT/shell/explorer/initcab.cpp';data=source.read_bytes()
 if data.count(OLD)!=1:raise ValueError('unreviewed source anchor')
 patched=data.replace(OLD,NEW.replace(b"\n",b"\r\n") if b"\r\n" in data else NEW)
 out.mkdir(parents=True,exist_ok=False);media=out/'media';media.mkdir()
 (media/'initcab-original.cpp').write_bytes(data);(media/'initcab-xp25.cpp').write_bytes(patched)
 shutil.copy2(ROOT/'build/native-shell-build.cmd',media/'native-shell-build.cmd')
 wrapper=r'''@echo off
if "%~1"=="" exit /b 2
fc /b C:\nt\shell\explorer\initcab.cpp D:\initcab-original.cpp > COM1
if errorlevel 1 exit /b 3
copy /b D:\initcab-xp25.cpp C:\nt\shell\explorer\initcab.cpp > COM1
if errorlevel 1 exit /b 4
call D:\native-shell-build.cmd %1
set XP25_BUILD_RESULT=%ERRORLEVEL%
C:\nt\tools\x86\cvdump.exe -p C:\nt\shell\explorer\winnt\obj\i386\explorer.pdb > C:\xpout\explorer-publics.txt
C:\nt\tools\x86\cvdump.exe -p C:\nt\ds\security\gina\userenv\main\obj\i386\userenv.pdb > C:\xpout\userenv-publics.txt
if exist D:\userenv-sp3.pdb C:\nt\tools\x86\cvdump.exe -p D:\userenv-sp3.pdb > C:\xpout\userenv-sp3-publics.txt
echo XP25_SHELL_COMPAT_BUILD_EXIT=%XP25_BUILD_RESULT% > COM1
exit /b %XP25_BUILD_RESULT%
'''
 (media/'build.cmd').write_bytes(wrapper.replace('\n','\r\n').encode('ascii'))
 symbols=ROOT/'.work/native-shell-userenv-20261024/symbols/userenv-sp3.pdb'
 if symbols.is_file():shutil.copy2(symbols,media/'userenv-sp3.pdb')
 command=['xorriso','-as','mkisofs','-quiet','-iso-level','3','-J','-R','-V','XP25SHELL','-o',str(out/'native-shell.iso'),str(media)]
 subprocess.run(command,check=True)
 sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
 (out/'manifest.json').write_text(json.dumps({'source':str(source),'original_sha256':sha(source),'patched_sha256':sha(media/'initcab-xp25.cpp'),'patch_scope':'One SCM event-security provider call; no DLL or security policy replacement.','files':{f.name:sha(f) for f in media.iterdir()},'command':command},indent=2)+'\n')
 print(out/'native-shell.iso')
if __name__=='__main__':main()
