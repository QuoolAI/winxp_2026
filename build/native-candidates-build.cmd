@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Compile candidates separately. This script never installs any guest component.
if "%~1"=="" exit /b 2
if /i not "%PROCESSOR_ARCHITECTURE%"=="x86" exit /b 2
if defined PROCESSOR_ARCHITEW6432 exit /b 2
set "XP_CAND_OUT=%~f1"
if not "%XP_CAND_OUT: =%"=="%XP_CAND_OUT%" exit /b 2
if exist "%XP_CAND_OUT%" exit /b 2
if not exist C:\nt\tools\razzle.cmd exit /b 2
mkdir "%XP_CAND_OUT%"
mkdir "%XP_CAND_OUT%\temp"
if exist "%~dp0apply.cmd" call "%~dp0apply.cmd"
if errorlevel 1 exit /b 1
call C:\nt\tools\razzle.cmd offline no_urt no_title temp %XP_CAND_OUT%\temp binaries_dir %XP_CAND_OUT%\binaries > "%XP_CAND_OUT%\environment.log" 2>&1
if not defined NTMAKEENV exit /b 1
echo NATIVE_CANDIDATE_BUILDS_STARTED > COM1
rem NMAKE's original private-file inference rules require existing output paths.
if not exist C:\nt\shell\lib\obj\i386 mkdir C:\nt\shell\lib\obj\i386
if not exist C:\nt\shell\inc\obj\i386 mkdir C:\nt\shell\inc\obj\i386
call :build shell-published shell\published\inc
call :build smss base\subsys\sm\server
call :build regconn base\screg\winreg\regconn
call :build regsvc base\screg\winreg\regsvc
call :build ginacomn ds\security\gina\common
call :build msgina ds\security\gina\msgina
call :build gina-idl ds\security\gina\idl
call :build rsoputil ds\security\gina\rsoputil
call :build userenv ds\security\gina\userenv
call :build shguid shell\lib\shguid
call :build ieguid shell\lib\ieguid
call :build explorer shell\explorer\winnt
echo NATIVE_CANDIDATE_BUILDS_FINISHED > COM1
exit /b 0
:build
pushd C:\nt\%~2
if errorlevel 1 exit /b 1
C:\nt\tools\x86\build.exe -cZ > "%XP_CAND_OUT%\%~1.log" 2>&1
set XP_CAND_RESULT=%ERRORLEVEL%
type "%XP_CAND_OUT%\%~1.log" > COM1
findstr /l /c:"BUILD: nmake.exe failed" "%XP_CAND_OUT%\%~1.log" >nul
if not errorlevel 1 set XP_CAND_RESULT=1
for %%F in (build*.err) do if exist %%F if %%~zF GTR 0 set XP_CAND_RESULT=1
for %%F in (build*.err) do if exist %%F copy /b /y "%%F" "%XP_CAND_OUT%\%~1-%%~nxF" >nul
echo %~1=%XP_CAND_RESULT% >> "%XP_CAND_OUT%\results.txt"
echo CANDIDATE_%~1_EXIT=%XP_CAND_RESULT% > COM1
popd
exit /b 0
