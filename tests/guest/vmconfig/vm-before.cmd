@echo off
rem Run once in an interactive VM before its offline update. Backs up the OEM
rem text, Help and Support's OEM copy and the computer name, records System
rem Properties, sets Help and Support's copy to the QuoolAI values and renames
rem the computer (effective at the next start).
rem usage: D:\vm-before.cmd NEW-COMPUTER-NAME
setlocal EnableDelayedExpansion
set R=C:\xp25\vmconfig-20261025
set B=%R%\backup
set C=%R%\check
set L=%C%\before.log
if "%~1"=="" exit /b 4
if exist %R% exit /b 3
mkdir %R%
mkdir %B%
mkdir %C%
echo COMPUTERNAME_BEFORE=%COMPUTERNAME%>>%L%
echo TARGET_NAME=%~1>>%L%
echo %COMPUTERNAME%>%B%\computername.before.txt
net localgroup administrators>>%L% 2>&1
copy /b %SystemRoot%\system32\oeminfo.ini %B%\OEMINFO.INI.before>>%L% 2>&1
echo COPY_EXIT=!ERRORLEVEL!>>%L%
reg export "HKLM\SOFTWARE\Microsoft\PCHealth\HelpSvc\OEMInfo" %B%\HelpSvc-OEMInfo.before.reg>>%L% 2>&1
echo REG_EXPORT_OEM_EXIT=!ERRORLEVEL!>>%L%
reg export "HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName" %B%\ComputerName.before.reg>>%L% 2>&1
echo REG_EXPORT_NAME_EXIT=!ERRORLEVEL!>>%L%
reg export "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" %B%\Tcpip-Parameters.before.reg>>%L% 2>&1
echo REG_EXPORT_TCPIP_EXIT=!ERRORLEVEL!>>%L%
copy /b D:\vm-restore.cmd %B%\restore.cmd>>%L% 2>&1
echo RESTORE_SCRIPT_COPY_EXIT=!ERRORLEVEL!>>%L%
copy /b D:\oem_probe.exe %B%\oem_probe.exe>>%L% 2>&1
echo PROBE_COPY_EXIT=!ERRORLEVEL!>>%L%
D:\oem_probe.exe --out %C%\check-before.json
echo PROBE_EXIT=!ERRORLEVEL!>>%L%
reg add "HKLM\SOFTWARE\Microsoft\PCHealth\HelpSvc\OEMInfo" /v Manufacturer /t REG_SZ /d "QuoolAI" /f>>%L% 2>&1
echo REG_MANUFACTURER_EXIT=!ERRORLEVEL!>>%L%
reg add "HKLM\SOFTWARE\Microsoft\PCHealth\HelpSvc\OEMInfo" /v Model /t REG_SZ /d "Windows XP 25th Anniversary Edition" /f>>%L% 2>&1
echo REG_MODEL_EXIT=!ERRORLEVEL!>>%L%
D:\oem_probe.exe --rename %~1 --out %C%\rename.json
set RC=!ERRORLEVEL!
echo RENAME_EXIT=!RC!>>%L%
rem The original winlogon.exe copies NV Hostname to the active Hostname at
rem startup; the independent XP25 Winlogon does not, so set it here.
if "!RC!"=="0" reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v Hostname /t REG_SZ /d "%~1" /f>>%L% 2>&1
echo REG_HOSTNAME_EXIT=!ERRORLEVEL!>>%L%
echo XP25_VM_BEFORE_DONE>>%L%
