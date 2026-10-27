@echo off
setlocal EnableExtensions DisableDelayedExpansion
if "%~1"=="" exit /b 2
if /i not "%PROCESSOR_ARCHITECTURE%"=="x86" exit /b 2
if defined PROCESSOR_ARCHITEW6432 exit /b 2
set "XP25_UENV_OUT=%~f1"
if exist "%XP25_UENV_OUT%" exit /b 2
mkdir "%XP25_UENV_OUT%"
mkdir "%XP25_UENV_OUT%\temp"
call C:\nt\tools\razzle.cmd offline no_urt no_title temp %XP25_UENV_OUT%\temp binaries_dir %XP25_UENV_OUT%\binaries > "%XP25_UENV_OUT%\environment.log" 2>&1
if not defined NTMAKEENV exit /b 1
echo NATIVE_USERENV_REBUILD_STARTED > COM1
pushd C:\nt\ds\security\gina\userenv
if errorlevel 1 exit /b 1
C:\nt\tools\x86\build.exe -cZ > "%XP25_UENV_OUT%\userenv.log" 2>&1
set "XP25_UENV_RESULT=%ERRORLEVEL%"
findstr /l /c:"BUILD: nmake.exe failed" "%XP25_UENV_OUT%\userenv.log" >nul
if not errorlevel 1 set "XP25_UENV_RESULT=1"
for /r %%F in (build*.err) do if exist "%%F" if %%~zF GTR 0 set "XP25_UENV_RESULT=1"
type "%XP25_UENV_OUT%\userenv.log" > COM1
popd
echo NATIVE_USERENV_REBUILD_EXIT=%XP25_UENV_RESULT% > COM1
exit /b %XP25_UENV_RESULT%
