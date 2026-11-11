@echo off
rem Run in each VM while both VMs are running: computer name, address and
rem routes, isolated DNS host, the other VM, an outside address, and branding.
rem usage: D:\vm-verify.cmd PEER-IP
setlocal EnableDelayedExpansion
set C=C:\xp25\vmconfig-20261025\check
set L=%C%\verify.log
if "%~1"=="" exit /b 4
if not exist %C%\before.log exit /b 2
echo COMPUTERNAME=%COMPUTERNAME%>%L%
hostname>>%L% 2>&1
ipconfig /all>>%L% 2>&1
route print>>%L% 2>&1
nbtstat -n>>%L% 2>&1
ping -n 2 -w 2000 xp25.test>>%L% 2>&1
echo PING_HOST_EXIT=!ERRORLEVEL!>>%L%
ping -n 2 -w 2000 %~1>>%L% 2>&1
echo PING_PEER_EXIT=!ERRORLEVEL!>>%L%
nbtstat -A %~1>>%L% 2>&1
echo NBTSTAT_PEER_EXIT=!ERRORLEVEL!>>%L%
ping -n 1 -w 2000 192.0.2.1>>%L% 2>&1
echo PING_OUTSIDE_EXIT=!ERRORLEVEL!>>%L%
D:\oem_probe.exe --expect --out %C%\check-after.json
echo PROBE_EXIT=!ERRORLEVEL!>>%L%
echo XP25_VM_VERIFY_DONE>>%L%
