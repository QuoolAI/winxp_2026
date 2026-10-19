@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Run in a disposable, offline, 32-bit Windows XP-or-later build guest.
rem Arguments: NT-source-copy x86|amd64 checked|free kernel|base|all output-dir
if "%~5"=="" exit /b 2
if /i not "%PROCESSOR_ARCHITECTURE%"=="x86" (
  echo BLOCKED: use a 32-bit Windows build host; full tree uses 16-bit tools.
  exit /b 2
)
if defined PROCESSOR_ARCHITEW6432 (
  echo BLOCKED: WOW64 cannot run the full tree's 16-bit build tools.
  exit /b 2
)
set "XP_SOURCE=%~f1"
set "XP_ARCH=%~2"
set "XP_FLAVOR=%~3"
set "XP_SCOPE=%~4"
set "XP_OUTPUT=%~f5"
for %%P in ("%~dp0..\Source\XPSP1\NT") do set "XP_REFERENCE=%%~fP"
if /i "%XP_SOURCE%"=="%XP_REFERENCE%" (
  echo BLOCKED: reference Source tree is protected; use a disposable source copy.
  exit /b 2
)
if /i not "%XP_ARCH%"=="x86" if /i not "%XP_ARCH%"=="amd64" exit /b 2
if /i not "%XP_FLAVOR%"=="checked" if /i not "%XP_FLAVOR%"=="free" exit /b 2
if /i not "%XP_SCOPE%"=="kernel" if /i not "%XP_SCOPE%"=="base" if /i not "%XP_SCOPE%"=="all" exit /b 2
rem Original scripts contain unquoted paths; a short path is required.
if not "%XP_SOURCE: =%"=="%XP_SOURCE%" exit /b 2
if not "%XP_OUTPUT: =%"=="%XP_OUTPUT%" exit /b 2
if not exist "%XP_SOURCE%\tools\razzle.cmd" exit /b 2
if not exist "%XP_OUTPUT%" mkdir "%XP_OUTPUT%"
if exist "%XP_OUTPUT%\native.log" (
  echo BLOCKED: choose a fresh output directory to preserve diagnostics.
  exit /b 2
)
set "XP_RAZZLE=offline no_urt no_title"
if /i "%XP_ARCH%"=="amd64" set "XP_RAZZLE=%XP_RAZZLE% Win64 Amd64"
if /i "%XP_FLAVOR%"=="free" set "XP_RAZZLE=%XP_RAZZLE% free"
mkdir "%XP_OUTPUT%\temp"
rem Razzle retains argument quotes in TEMP and BinariesDir. Spaces were rejected above.
call "%XP_SOURCE%\tools\razzle.cmd" %XP_RAZZLE% temp %XP_OUTPUT%\temp binaries_dir %XP_OUTPUT%\binaries > "%XP_OUTPUT%\native.log" 2>&1
if not defined NTMAKEENV exit /b 2
if not defined _NTTREE exit /b 2
set "XP_TARGET=%XP_SOURCE%"
if /i "%XP_SCOPE%"=="kernel" set "XP_TARGET=%XP_SOURCE%\base\ntos"
if /i "%XP_SCOPE%"=="base" set "XP_TARGET=%XP_SOURCE%\base"
pushd "%XP_TARGET%"
if errorlevel 1 exit /b 2
"%XP_SOURCE%\tools\x86\build.exe" -Z >> "%XP_OUTPUT%\native.log" 2>&1
set "XP_RESULT=%ERRORLEVEL%"
rem This legacy build.exe can return zero after child NMAKE failures.
findstr /l /c:"BUILD: nmake.exe failed" "%XP_OUTPUT%\native.log" >nul
if not errorlevel 1 set "XP_RESULT=1"
for %%F in (build*.err) do if exist "%%F" if %%~zF GTR 0 set "XP_RESULT=1"
for %%F in (build*.log build*.err build*.wrn) do if exist "%%F" copy /y "%%F" "%XP_OUTPUT%\" >nul
popd
echo Native build command exit code: %XP_RESULT%
exit /b %XP_RESULT%
