@echo off
setlocal EnableExtensions DisableDelayedExpansion
echo NETWORK_REGRESSION_STARTED > COM1
"%~dp0xp_probe.exe" --serial
echo STANDARD_PROBE_EXIT=%ERRORLEVEL% > COM1
"%~dp0pointer_probe.exe"
echo POINTER_PROBE_EXIT=%ERRORLEVEL% > COM1
"%~dp0session_probe.exe"
echo SESSION_PROBE_EXIT=%ERRORLEVEL% > COM1
"%~dp0network_probe.exe"
echo NETWORK_PROBE_EXIT=%ERRORLEVEL% > COM1
ipconfig /all > C:\xp25\network-ipconfig.txt
route print > C:\xp25\network-routes.txt
for %%S in (Afd Tcpip Dhcp Dnscache RpcSs RTL8139) do sc qc %%S >> C:\xp25\network-services.txt
echo NETWORK_REGRESSION_FINISHED > COM1
