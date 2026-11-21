@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Build MerlinAI with the NT 5.1 toolchain in the build VM.
if "%~1"=="" exit /b 2
if /i not "%PROCESSOR_ARCHITECTURE%"=="x86" exit /b 2
if defined PROCESSOR_ARCHITEW6432 exit /b 2
set "XP25_MERLIN_OUT=%~f1"
if exist "%XP25_MERLIN_OUT%" exit /b 2
if exist C:\nt\xp25\merlin exit /b 2
mkdir "%XP25_MERLIN_OUT%"
mkdir "%XP25_MERLIN_OUT%\temp"
mkdir C:\nt\xp25\merlin
xcopy /e /i /q D:\merlin C:\nt\xp25\merlin > "%XP25_MERLIN_OUT%\copy.log"
if errorlevel 1 exit /b 1
call C:\nt\tools\razzle.cmd offline no_urt no_title temp %XP25_MERLIN_OUT%\temp binaries_dir %XP25_MERLIN_OUT%\binaries > "%XP25_MERLIN_OUT%\environment.log" 2>&1
if not defined NTMAKEENV exit /b 1
pushd C:\nt\xp25\merlin
if errorlevel 1 exit /b 1
echo XP25_MERLIN_BUILD_STARTED > COM1
C:\nt\tools\x86\build.exe -cZ > "%XP25_MERLIN_OUT%\native.log" 2>&1
set "XP25_MERLIN_RESULT=%ERRORLEVEL%"
findstr /l /c:"BUILD: nmake.exe failed" "%XP25_MERLIN_OUT%\native.log" >nul
if not errorlevel 1 set "XP25_MERLIN_RESULT=1"
for %%F in (build*.err) do if exist "%%F" if %%~zF GTR 0 set "XP25_MERLIN_RESULT=1"
for %%F in (merlin\client\obj\i386\MerlinClient.dll merlin\crash\obj\i386\MerlinCrash.exe merlin\app\obj\i386\MerlinAI.exe merlin\cpl\obj\i386\MerlinAI.cpl merlin\svc\obj\i386\MerlinSvc.exe merlin\testapp\obj\i386\MerlinTest.exe) do if not exist %%F set "XP25_MERLIN_RESULT=1"
type "%XP25_MERLIN_OUT%\native.log" > COM1
for %%F in (build*.err build*.wrn) do if exist "%%F" type "%%F" > COM1
copy /y build*.* "%XP25_MERLIN_OUT%\" >nul 2>&1
popd
echo XP25_MERLIN_BUILD_EXIT=%XP25_MERLIN_RESULT% > COM1
exit /b %XP25_MERLIN_RESULT%
