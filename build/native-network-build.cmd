@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Run only in a disposable native x86 build guest with the prepared C:\nt.
if "%~1"=="" exit /b 2
if /i not "%PROCESSOR_ARCHITECTURE%"=="x86" exit /b 2
if defined PROCESSOR_ARCHITEW6432 exit /b 2
set "XP_NET_OUT=%~f1"
if not "%XP_NET_OUT: =%"=="%XP_NET_OUT%" exit /b 2
if exist "%XP_NET_OUT%" exit /b 2
if not exist C:\nt\tools\razzle.cmd exit /b 2
mkdir "%XP_NET_OUT%"
mkdir "%XP_NET_OUT%\temp"
echo NATIVE_NETWORK_BUILD_STARTED > COM1
if exist "%~dp0apply.cmd" call "%~dp0apply.cmd"
if errorlevel 1 goto failed
call C:\nt\tools\razzle.cmd offline no_urt no_title temp %XP_NET_OUT%\temp binaries_dir %XP_NET_OUT%\binaries > "%XP_NET_OUT%\environment.log" 2>&1
if not defined NTMAKEENV goto failed
pushd C:\nt\net\tcpip\winsock
if errorlevel 1 goto failed
C:\nt\tools\x86\build.exe -cZ > "%XP_NET_OUT%\wshtcpip.log" 2>&1
set XP_NET_RESULT=%ERRORLEVEL%
type "%XP_NET_OUT%\wshtcpip.log" > COM1
findstr /l /c:"BUILD: nmake.exe failed" "%XP_NET_OUT%\wshtcpip.log" >nul
if not errorlevel 1 set XP_NET_RESULT=1
for %%F in (build*.err) do if exist %%F if %%~zF GTR 0 set XP_NET_RESULT=1
if not exist obj\i386\wshtcpip.dll set XP_NET_RESULT=1
popd
if not "%XP_NET_RESULT%"=="0" goto failed
echo finished> "%XP_NET_OUT%\finished.txt"
echo NATIVE_NETWORK_BUILD_FINISHED > COM1
exit /b 0
:failed
echo failed> "%XP_NET_OUT%\failed.txt"
echo NATIVE_NETWORK_BUILD_FAILED > COM1
exit /b 1
