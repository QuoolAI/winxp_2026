@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Relink the checked x86 kernels in the build VM after adding kernel exports
rem to ntoskrnl.src. C:\nt is the disposable source copy that already holds the
rem objects of the verified kernel build; no kernel source file is changed.
if "%~1"=="" exit /b 2
if /i not "%PROCESSOR_ARCHITECTURE%"=="x86" exit /b 2
if defined PROCESSOR_ARCHITEW6432 exit /b 2
set "XP25_KX_OUT=%~f1"
if exist "%XP25_KX_OUT%" exit /b 2
if not exist C:\nt\base\ntos\init\ntoskrnl.src exit /b 2
mkdir "%XP25_KX_OUT%"
mkdir "%XP25_KX_OUT%\temp"
echo XP25_KEXPORT_STARTED > COM1
fc /b D:\original\ntoskrnl.src C:\nt\base\ntos\init\ntoskrnl.src > "%XP25_KX_OUT%\source-compare.log"
if errorlevel 1 goto mismatch
copy /y D:\patched\ntoskrnl.src C:\nt\base\ntos\init\ntoskrnl.src > nul
if errorlevel 1 goto mismatch
call C:\nt\tools\razzle.cmd offline no_urt no_title temp %XP25_KX_OUT%\temp binaries_dir %XP25_KX_OUT%\binaries > "%XP25_KX_OUT%\environment.log" 2>&1
if not defined NTMAKEENV exit /b 1
pushd C:\nt\base\ntos\init
if errorlevel 1 exit /b 1
C:\nt\tools\x86\build.exe -Z > "%XP25_KX_OUT%\native.log" 2>&1
set "XP25_KX_RESULT=%ERRORLEVEL%"
findstr /l /c:"BUILD: nmake.exe failed" "%XP25_KX_OUT%\native.log" >nul
if not errorlevel 1 set "XP25_KX_RESULT=1"
for %%F in (build*.err) do if exist "%%F" if %%~zF GTR 0 set "XP25_KX_RESULT=1"
for %%F in (up\obj\i386\ntoskrnl.exe mp\obj\i386\ntkrnlmp.exe) do if not exist %%F set "XP25_KX_RESULT=1"
type "%XP25_KX_OUT%\native.log" > COM1
copy /y build*.* "%XP25_KX_OUT%\" >nul 2>&1
popd
echo XP25_KEXPORT_BUILD_EXIT=%XP25_KX_RESULT% > COM1
exit /b %XP25_KX_RESULT%
:mismatch
echo XP25_KEXPORT_SOURCE_MISMATCH > COM1
exit /b 1
