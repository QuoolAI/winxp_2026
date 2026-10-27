@echo off
setlocal EnableExtensions DisableDelayedExpansion
echo NETWORK_STABILITY_STARTED > COM1
set XP_NETWORK_FAILURES=0
for /l %%I in (1,1,10) do call :iteration %%I
echo NETWORK_STABILITY_FAILURES=%XP_NETWORK_FAILURES% > COM1
echo NETWORK_STABILITY_FINISHED > COM1
exit /b %XP_NETWORK_FAILURES%
:iteration
echo NETWORK_ITERATION=%1 > COM1
"%~dp0network_probe.exe"
if errorlevel 1 set /a XP_NETWORK_FAILURES+=1
exit /b 0
