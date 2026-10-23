@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Prepared native 32-bit XP build guest only. C:\nt is a disposable source copy.
rem Run from generated private CD: D:\build.cmd C:\xpout\fresh-output-name
if "%~1"=="" exit /b 2
if /i not "%PROCESSOR_ARCHITECTURE%"=="x86" exit /b 2
if defined PROCESSOR_ARCHITEW6432 exit /b 2
set "XP_BOOT_OUT=%~f1"
if not "%XP_BOOT_OUT: =%"=="%XP_BOOT_OUT%" exit /b 2
if exist "%XP_BOOT_OUT%" exit /b 2
if not exist C:\nt\tools\razzle.cmd exit /b 2
if not exist "%~dp0apply.cmd" exit /b 2
if not exist "%~dp0restore.cmd" exit /b 2
mkdir "%XP_BOOT_OUT%"
if errorlevel 1 exit /b 2
echo started> "%XP_BOOT_OUT%\started.txt"
echo NATIVE_BOOT_PIPELINE_STARTED > COM1
call "%~dp0apply.cmd"
if errorlevel 1 goto failed
mkdir "%XP_BOOT_OUT%\temp"
call C:\nt\tools\razzle.cmd offline no_urt no_title temp %XP_BOOT_OUT%\temp binaries_dir %XP_BOOT_OUT%\binaries > "%XP_BOOT_OUT%\environment.log" 2>&1
if not defined NTMAKEENV goto failed
pushd C:\nt\base\ntos
C:\nt\tools\x86\build.exe -cZ > "%XP_BOOT_OUT%\kernel-clean.log" 2>&1
echo KERNEL_CLEAN_EXIT=%ERRORLEVEL% > COM1
type "%XP_BOOT_OUT%\kernel-clean.log" > COM1
rem The clean pass exposes the documented absent executive C files/objects.
rem Preserve that failure, restore only the four hash-pinned supplied objects,
rem and require a successful final build with no nonempty error log.
popd
call "%~dp0restore.cmd"
if errorlevel 1 goto failed
call :component kernel C:\nt\base\ntos -Z
if errorlevel 1 goto failed
call :component hal-up C:\nt\base\hals\halacpi\apic -cZ
if errorlevel 1 goto failed
call :component hal-mp C:\nt\base\hals\halacpi\mpapic -cZ
if errorlevel 1 goto failed
call :component hal-pic C:\nt\base\hals\halacpi\picacpi -cZ
if errorlevel 1 goto failed
call :component ntdll C:\nt\base\ntdll\daytona -cZ
if errorlevel 1 goto failed
call :component kernel32 C:\nt\base\win32\client\daytona -cZ
if errorlevel 1 goto failed
echo NATIVE_BOOT_PIPELINE_FINISHED > COM1
echo finished> "%XP_BOOT_OUT%\finished.txt"
exit /b 0
:component
echo BUILDING_%~1 > COM1
pushd %~2
if errorlevel 1 exit /b 1
C:\nt\tools\x86\build.exe %~3 > "%XP_BOOT_OUT%\%~1.log" 2>&1
set XP_BOOT_RESULT=%ERRORLEVEL%
type "%XP_BOOT_OUT%\%~1.log" > COM1
findstr /l /c:"BUILD: nmake.exe failed" "%XP_BOOT_OUT%\%~1.log" >nul
if not errorlevel 1 set XP_BOOT_RESULT=1
for %%F in (build*.err) do if exist %%F if %%~zF GTR 0 set XP_BOOT_RESULT=1
popd
exit /b %XP_BOOT_RESULT%
:failed
echo NATIVE_BOOT_PIPELINE_FAILED > COM1
echo failed> "%XP_BOOT_OUT%\failed.txt"
exit /b 1
