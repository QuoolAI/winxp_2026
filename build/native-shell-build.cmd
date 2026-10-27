@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Native original Explorer and its original support/import libraries only.
if "%~1"=="" exit /b 2
set "XP_SHELL_OUT=%~f1"
if exist "%XP_SHELL_OUT%" exit /b 2
if not "%XP_SHELL_OUT: =%"=="%XP_SHELL_OUT%" exit /b 2
if /i not "%PROCESSOR_ARCHITECTURE%"=="x86" exit /b 2
if defined PROCESSOR_ARCHITEW6432 exit /b 2
mkdir "%XP_SHELL_OUT%"
mkdir "%XP_SHELL_OUT%\temp"
call C:\nt\tools\razzle.cmd offline no_urt no_title temp %XP_SHELL_OUT%\temp binaries_dir %XP_SHELL_OUT%\binaries > "%XP_SHELL_OUT%\environment.log" 2>&1
if not defined NTMAKEENV exit /b 1
echo NATIVE_SHELL_BUILD_STARTED > COM1
set "XP_SHELL_FAILED=0"
if not exist C:\nt\shell\lib\obj\i386 mkdir C:\nt\shell\lib\obj\i386
call :imports browseui
call :imports shdocvw
call :build shfusion shell\lib\shfusion\native
call :build stockthk shell\lib\stockthk
call :build stock shell\lib\stock
call :build desktop2 shell\explorer\desktop2
call :build explorer shell\explorer\winnt
echo NATIVE_SHELL_BUILD_FINISHED > COM1
exit /b %XP_SHELL_FAILED%
:imports
rem Match shell\makefile.inc's public and two-pass private preprocessing rules.
rem Without DLL implementation objects, LIB needs explicit x86 stdcall decoration.
rem Every decorated entry is NONAME: the original runtime ordinal is unchanged.
set "XP_SHELL_DECORATE="
if /i "%~1"=="browseui" set "XP_SHELL_DECORATE=/DSHCreateFromDesktop=SHCreateFromDesktop@4 /DSHExplorerParseCmdLine=SHExplorerParseCmdLine@4 /DUEMRegisterNotify=UEMRegisterNotify@8 /DGetInfoTip=GetInfoTip@16"
if /i "%~1"=="shdocvw" set "XP_SHELL_DECORATE=/DWinList_Init=WinList_Init@0 /DWinList_Terminate=WinList_Terminate@0 /DRunInstallUninstallStubs=RunInstallUninstallStubs@0"
cl /nologo /EP /TC /DWIN32 /D_WIN32 /DUNICODE /D_UNICODE /DNT /DWINNT %XP_SHELL_DECORATE% /DULTRAPRIVATE=PRIVATE "C:\nt\shell\%~1\%~1.src" > "%XP_SHELL_OUT%\%~1.def" 2> "%XP_SHELL_OUT%\%~1-preprocess.err"
if errorlevel 1 goto :importfail
lib /nologo /machine:i386 /def:"%XP_SHELL_OUT%\%~1.def" /out:"C:\nt\shell\lib\obj\i386\%~1.lib" > "%XP_SHELL_OUT%\%~1-lib.log" 2>&1
if errorlevel 1 goto :importfail
cl /nologo /EP /TC /DWIN32 /D_WIN32 /DUNICODE /D_UNICODE /DNT /DWINNT %XP_SHELL_DECORATE% /DPRIVATE= "C:\nt\shell\%~1\%~1.src" > "%XP_SHELL_OUT%\%~1.dfp" 2>> "%XP_SHELL_OUT%\%~1-preprocess.err"
if errorlevel 1 goto :importfail
cl /nologo /EP /TC /DULTRAPRIVATE=PRIVATE "%XP_SHELL_OUT%\%~1.dfp" > "%XP_SHELL_OUT%\%~1p.def" 2>> "%XP_SHELL_OUT%\%~1-preprocess.err"
if errorlevel 1 goto :importfail
lib /nologo /machine:i386 /def:"%XP_SHELL_OUT%\%~1p.def" /out:"C:\nt\shell\lib\obj\i386\%~1p.lib" > "%XP_SHELL_OUT%\%~1p-lib.log" 2>&1
if errorlevel 1 goto :importfail
echo %~1-imports=0 >> "%XP_SHELL_OUT%\results.txt"
echo SHELL_%~1_IMPORTS_EXIT=0 > COM1
exit /b 0
:importfail
set "XP_SHELL_FAILED=1"
echo %~1-imports=1 >> "%XP_SHELL_OUT%\results.txt"
echo SHELL_%~1_IMPORTS_EXIT=1 > COM1
exit /b 0
:build
pushd C:\nt\%~2
if errorlevel 1 (
    set "XP_SHELL_FAILED=1"
    exit /b 1
)
C:\nt\tools\x86\build.exe -cZ > "%XP_SHELL_OUT%\%~1.log" 2>&1
set XP_SHELL_RESULT=%ERRORLEVEL%
findstr /l /c:"BUILD: nmake.exe failed" "%XP_SHELL_OUT%\%~1.log" >nul
if not errorlevel 1 set XP_SHELL_RESULT=1
for %%F in (build*.err) do if exist %%F if %%~zF GTR 0 set XP_SHELL_RESULT=1
if not "%XP_SHELL_RESULT%"=="0" set "XP_SHELL_FAILED=1"
for %%F in (build*.err) do if exist %%F copy /b /y "%%F" "%XP_SHELL_OUT%\%~1-%%~nxF" >nul
type "%XP_SHELL_OUT%\%~1.log" > COM1
echo %~1=%XP_SHELL_RESULT% >> "%XP_SHELL_OUT%\results.txt"
echo SHELL_%~1_EXIT=%XP_SHELL_RESULT% > COM1
popd
exit /b 0
