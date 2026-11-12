@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Build the XP25 security components with the NT 5.1 toolchain in the build VM.
if "%~1"=="" exit /b 2
if /i not "%PROCESSOR_ARCHITECTURE%"=="x86" exit /b 2
if defined PROCESSOR_ARCHITEW6432 exit /b 2
set "XP25_SEC_OUT=%~f1"
if exist "%XP25_SEC_OUT%" exit /b 2
if exist C:\nt\xp25\security exit /b 2
mkdir "%XP25_SEC_OUT%"
mkdir "%XP25_SEC_OUT%\temp"
mkdir C:\nt\xp25\security
xcopy /e /i /q D:\security C:\nt\xp25\security > "%XP25_SEC_OUT%\copy.log"
if errorlevel 1 exit /b 1
call C:\nt\tools\razzle.cmd offline no_urt no_title temp %XP25_SEC_OUT%\temp binaries_dir %XP25_SEC_OUT%\binaries > "%XP25_SEC_OUT%\environment.log" 2>&1
if not defined NTMAKEENV exit /b 1
pushd C:\nt\xp25\security
if errorlevel 1 exit /b 1
echo XP25_SECURITY_BUILD_STARTED > COM1
C:\nt\tools\x86\build.exe -cZ > "%XP25_SEC_OUT%\native.log" 2>&1
set "XP25_SEC_RESULT=%ERRORLEVEL%"
findstr /l /c:"BUILD: nmake.exe failed" "%XP25_SEC_OUT%\native.log" >nul
if not errorlevel 1 set "XP25_SEC_RESULT=1"
for %%F in (build*.err) do if exist "%%F" if %%~zF GTR 0 set "XP25_SEC_RESULT=1"
for %%F in (xp25sec\obj\i386\XP25Sec.exe xp25audit\obj\i386\XP25Audit.exe) do if not exist %%F set "XP25_SEC_RESULT=1"
type "%XP25_SEC_OUT%\native.log" > COM1
for %%F in (build*.err build*.wrn) do if exist "%%F" type "%%F" > COM1
copy /y build*.* "%XP25_SEC_OUT%\" >nul 2>&1
popd
echo XP25_SECURITY_BUILD_EXIT=%XP25_SEC_RESULT% > COM1
exit /b %XP25_SEC_RESULT%
