@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Generate original SCM RPC inputs in a disposable C:\nt only; never install SCM.
if "%~1"=="" exit /b 2
if /i not "%PROCESSOR_ARCHITECTURE%"=="x86" exit /b 2
if defined PROCESSOR_ARCHITEW6432 exit /b 2
if not exist C:\nt\tools\razzle.cmd exit /b 2
set "XP_SCM_OUT=%~f1"
if not "%XP_SCM_OUT: =%"=="%XP_SCM_OUT%" exit /b 2
if exist "%XP_SCM_OUT%" exit /b 2
mkdir "%XP_SCM_OUT%"
mkdir "%XP_SCM_OUT%\temp"
echo SCM_RPC_PREPARE_STARTED > COM1
call C:\nt\tools\razzle.cmd offline no_urt no_title temp %XP_SCM_OUT%\temp binaries_dir %XP_SCM_OUT%\binaries > "%XP_SCM_OUT%\environment.log" 2>&1
if not defined NTMAKEENV goto failed
pushd C:\nt\base\screg\winreg
if errorlevel 1 goto failed
nmake /nologo /f makefil0 > "%XP_SCM_OUT%\regrpc.log" 2>&1
set XP_SCM_RESULT=%ERRORLEVEL%
type "%XP_SCM_OUT%\regrpc.log" > COM1
popd
if not "%XP_SCM_RESULT%"=="0" goto failed
if not exist C:\nt\base\screg\winreg\server\regrpc_s.c goto failed
if not exist C:\nt\base\screg\winreg\regrpc.h goto failed
pushd C:\nt\base\screg\sc
if errorlevel 1 goto failed
nmake /nologo /f makefil0 > "%XP_SCM_OUT%\svcctl.log" 2>&1
set XP_SCM_RESULT=%ERRORLEVEL%
type "%XP_SCM_OUT%\svcctl.log" > COM1
popd
if not "%XP_SCM_RESULT%"=="0" goto failed
if not exist C:\nt\base\screg\sc\server\svcctl_s.c goto failed
if not exist C:\nt\base\screg\sc\client\svcctl_c.c goto failed
if not exist C:\nt\base\screg\sc\inc\svcctl.h goto failed
echo finished> "%XP_SCM_OUT%\finished.txt"
echo SCM_RPC_PREPARE_FINISHED > COM1
exit /b 0
:failed
echo failed> "%XP_SCM_OUT%\failed.txt"
echo SCM_RPC_PREPARE_FAILED > COM1
exit /b 1
