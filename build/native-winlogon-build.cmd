@echo off
setlocal EnableExtensions DisableDelayedExpansion
if "%~1"=="" exit /b 2
if /i not "%PROCESSOR_ARCHITECTURE%"=="x86" exit /b 2
if defined PROCESSOR_ARCHITEW6432 exit /b 2
set "XP25_WL_OUT=%~f1"
if exist "%XP25_WL_OUT%" exit /b 2
if exist C:\nt\xp25\winlogon exit /b 2
mkdir "%XP25_WL_OUT%"
mkdir "%XP25_WL_OUT%\temp"
mkdir C:\nt\xp25\winlogon
copy /b D:\winlogon\* C:\nt\xp25\winlogon\ > "%XP25_WL_OUT%\copy.log"
if errorlevel 1 exit /b 1
call C:\nt\tools\razzle.cmd offline no_urt no_title temp %XP25_WL_OUT%\temp binaries_dir %XP25_WL_OUT%\binaries > "%XP25_WL_OUT%\environment.log" 2>&1
if not defined NTMAKEENV exit /b 1
pushd C:\nt\xp25\winlogon
if errorlevel 1 exit /b 1
echo XP25_WINLOGON_BUILD_STARTED > COM1
C:\nt\tools\x86\build.exe -cZ > "%XP25_WL_OUT%\native.log" 2>&1
set "XP25_WL_RESULT=%ERRORLEVEL%"
findstr /l /c:"BUILD: nmake.exe failed" "%XP25_WL_OUT%\native.log" >nul
if not errorlevel 1 set "XP25_WL_RESULT=1"
for %%F in (build*.err) do if exist "%%F" if %%~zF GTR 0 set "XP25_WL_RESULT=1"
type "%XP25_WL_OUT%\native.log" > COM1
popd
echo XP25_WINLOGON_BUILD_EXIT=%XP25_WL_RESULT% > COM1
exit /b %XP25_WL_RESULT%
