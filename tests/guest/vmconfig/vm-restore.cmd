@echo off
rem Puts back the OEM text, Help and Support's OEM copy and the computer name
rem saved by vm-before.cmd on 2026-10-25. Run from this folder as an
rem administrator, then restart Windows. sysdm.cpl is restored offline; see
rem docs/xp25-vm-configuration.md.
setlocal
set /p OLD=<"%~dp0computername.before.txt"
copy /y /b "%~dp0OEMINFO.INI.before" %SystemRoot%\system32\OEMINFO.INI
reg import "%~dp0HelpSvc-OEMInfo.before.reg"
"%~dp0oem_probe.exe" --rename %OLD% --out "%~dp0rename-restore.json"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v Hostname /t REG_SZ /d "%OLD%" /f
