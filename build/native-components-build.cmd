@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Original NT 5.1 components; disposable prepared native x86 build copy only.
if "%~1"=="" exit /b 2
if /i not "%PROCESSOR_ARCHITECTURE%"=="x86" exit /b 2
if defined PROCESSOR_ARCHITEW6432 exit /b 2
if not exist C:\nt\tools\razzle.cmd exit /b 2
set "XP_COMP_OUT=%~f1"
if not "%XP_COMP_OUT: =%"=="%XP_COMP_OUT%" exit /b 2
if exist "%XP_COMP_OUT%" exit /b 2
mkdir "%XP_COMP_OUT%"
mkdir "%XP_COMP_OUT%\temp"
echo NATIVE_COMPONENT_BUILD_STARTED > COM1
if exist "%~dp0apply.cmd" call "%~dp0apply.cmd"
if errorlevel 1 goto failed
call C:\nt\tools\razzle.cmd offline no_urt no_title temp %XP_COMP_OUT%\temp binaries_dir %XP_COMP_OUT%\binaries > "%XP_COMP_OUT%\environment.log" 2>&1
if not defined NTMAKEENV goto failed
if not exist C:\nt\base\screg\sc\server\svcctl_s.c goto failed
if not exist C:\nt\base\screg\sc\inc\svcctl.h goto failed
if not exist C:\nt\base\screg\winreg\server\regrpc_s.c goto failed
if not exist C:\nt\base\screg\winreg\regrpc.h goto failed
set XP_COMP_FAILED=0
call :build sclib base\screg\sc\lib
call :build wrlib base\screg\winreg\lib
call :build pnp-idl base\pnp\idl
call :build umpnpmgr base\pnp\umpnpmgr
call :build winreg base\screg\winreg\server
call :build svcslib base\screg\sc\svcslib
call :build services base\screg\sc\server
if not "%XP_COMP_FAILED%"=="0" goto failed
if not exist C:\nt\base\screg\sc\server\obj\i386\services.exe goto failed
echo finished> "%XP_COMP_OUT%\finished.txt"
echo NATIVE_COMPONENT_BUILD_FINISHED > COM1
exit /b 0
:build
pushd C:\nt\%~2
if errorlevel 1 exit /b 1
C:\nt\tools\x86\build.exe -cZ > "%XP_COMP_OUT%\%~1.log" 2>&1
set XP_COMP_RESULT=%ERRORLEVEL%
type "%XP_COMP_OUT%\%~1.log" > COM1
findstr /l /c:"BUILD: nmake.exe failed" "%XP_COMP_OUT%\%~1.log" >nul
if not errorlevel 1 set XP_COMP_RESULT=1
for %%F in (build*.err) do if exist %%F if %%~zF GTR 0 set XP_COMP_RESULT=1
echo %~1=%XP_COMP_RESULT% >> "%XP_COMP_OUT%\results.txt"
if not "%XP_COMP_RESULT%"=="0" set XP_COMP_FAILED=1
popd
exit /b 0
:failed
echo failed> "%XP_COMP_OUT%\failed.txt"
echo NATIVE_COMPONENT_BUILD_FAILED > COM1
exit /b 1
