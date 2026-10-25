@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Build the XP25 AI components with the NT 5.1 toolchain in the build VM.
if "%~1"=="" exit /b 2
if /i not "%PROCESSOR_ARCHITECTURE%"=="x86" exit /b 2
if defined PROCESSOR_ARCHITEW6432 exit /b 2
set "XP25_AI_OUT=%~f1"
if exist "%XP25_AI_OUT%" exit /b 2
if exist C:\nt\xp25\ai exit /b 2
mkdir "%XP25_AI_OUT%"
mkdir "%XP25_AI_OUT%\temp"
mkdir C:\nt\xp25\ai
xcopy /e /i /q D:\ai C:\nt\xp25\ai > "%XP25_AI_OUT%\copy.log"
if errorlevel 1 exit /b 1
call C:\nt\tools\razzle.cmd offline no_urt no_title temp %XP25_AI_OUT%\temp binaries_dir %XP25_AI_OUT%\binaries > "%XP25_AI_OUT%\environment.log" 2>&1
if not defined NTMAKEENV exit /b 1
pushd C:\nt\xp25\ai
if errorlevel 1 exit /b 1
echo XP25_AI_BUILD_STARTED > COM1
C:\nt\tools\x86\build.exe -cZ > "%XP25_AI_OUT%\native.log" 2>&1
set "XP25_AI_RESULT=%ERRORLEVEL%"
findstr /l /c:"BUILD: nmake.exe failed" "%XP25_AI_OUT%\native.log" >nul
if not errorlevel 1 set "XP25_AI_RESULT=1"
for %%F in (build*.err) do if exist "%%F" if %%~zF GTR 0 set "XP25_AI_RESULT=1"
for %%F in (xp25-agent\dll\obj\i386\xp25agent.dll clippyai\app\obj\i386\ClippyAI.exe roverai\app\obj\i386\RoverAI.exe roverai\explorer\obj\i386\RoverAIBand.dll xp25-agent\broker\obj\i386\XP25Broker.exe) do if not exist %%F set "XP25_AI_RESULT=1"
type "%XP25_AI_OUT%\native.log" > COM1
for %%F in (build*.err build*.wrn) do if exist "%%F" type "%%F" > COM1
copy /y build*.* "%XP25_AI_OUT%\" >nul 2>&1
popd
echo XP25_AI_BUILD_EXIT=%XP25_AI_RESULT% > COM1
exit /b %XP25_AI_RESULT%
