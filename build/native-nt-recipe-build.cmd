@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem MerlinAI Builder: rebuild a component of the NT reference tree in the build VM's C:\nt, a disposable copy
rem that holds the objects of the verified build. Made by build/prepare_recipe.py:
rem   D:\files.txt     changed files, paths below C:\nt
rem   D:\dirs.txt      directories to build, in order (the link directory last)
rem   D:\outputs.txt   built files to collect, paths below C:\nt
rem   D:\original\     reference copies; each must equal the build VM's file before anything changes
rem   D:\control\      XP25's effective sources: this build must reproduce the installed binary
rem   D:\candidate\    the job's sources
rem Results go to <out>\control and <out>\candidate; COM1 gets XP25_RECIPE_BUILD_EXIT=<n>.
if "%~1"=="" exit /b 2
if /i not "%PROCESSOR_ARCHITECTURE%"=="x86" exit /b 2
if defined PROCESSOR_ARCHITEW6432 exit /b 2
set "XP25_NT_OUT=%~f1"
if exist "%XP25_NT_OUT%" exit /b 2
mkdir "%XP25_NT_OUT%"
mkdir "%XP25_NT_OUT%\temp"
mkdir "%XP25_NT_OUT%\control"
mkdir "%XP25_NT_OUT%\candidate"
echo XP25_RECIPE_BUILD_STARTED > COM1
set "XP25_NT_RESULT=0"
for /f "usebackq delims=" %%F in ("D:\files.txt") do call :verify "%%F"
if not "%XP25_NT_RESULT%"=="0" goto done
call C:\nt\tools\razzle.cmd offline no_urt no_title temp %XP25_NT_OUT%\temp binaries_dir %XP25_NT_OUT%\binaries > "%XP25_NT_OUT%\environment.log" 2>&1
if not defined NTMAKEENV set "XP25_NT_RESULT=1"
if not "%XP25_NT_RESULT%"=="0" goto done
call :build control
if not "%XP25_NT_RESULT%"=="0" goto done
call :build candidate
:done
echo XP25_RECIPE_BUILD_EXIT=%XP25_NT_RESULT% > COM1
exit /b %XP25_NT_RESULT%

:verify
fc /b "D:\original\%~1" "C:\nt\%~1" > nul
if errorlevel 1 (
  echo XP25_RECIPE_SOURCE_MISMATCH %~1 > COM1
  set "XP25_NT_RESULT=1"
)
goto :eof

:build
set "XP25_NT_STAGE=%~1"
set "XP25_NT_N=0"
for /f "usebackq delims=" %%O in ("D:\outputs.txt") do if exist "C:\nt\%%O" del /f "C:\nt\%%O"
for /f "usebackq delims=" %%F in ("D:\files.txt") do call :place "%%F"
for /f "usebackq delims=" %%D in ("D:\dirs.txt") do call :builddir "%%D"
for /f "usebackq delims=" %%O in ("D:\outputs.txt") do call :collect "%%O"
echo XP25_RECIPE_STAGE_DONE %XP25_NT_STAGE% %XP25_NT_RESULT% > COM1
goto :eof

:place
attrib -r "C:\nt\%~1" > nul 2>&1
copy /y "D:\%XP25_NT_STAGE%\%~1" "C:\nt\%~1" > nul
if errorlevel 1 set "XP25_NT_RESULT=1"
attrib -r "C:\nt\%~1" > nul 2>&1
rem A fresh time stamp: the second build must see its files as newer than the first build's outputs.
for %%G in ("C:\nt\%~1") do call :touch "%%~dpG" "%%~nxG"
goto :eof

:touch
pushd "%~1"
copy /b "%~2" +,, > nul
popd
goto :eof

:builddir
set /a XP25_NT_N+=1
if not exist "C:\nt\%~1\" (
  echo XP25_RECIPE_DIRECTORY_MISSING %~1 > COM1
  set "XP25_NT_RESULT=1"
  goto :eof
)
pushd "C:\nt\%~1"
C:\nt\tools\x86\build.exe -Z > "%XP25_NT_OUT%\%XP25_NT_STAGE%-%XP25_NT_N%.log" 2>&1
findstr /l /c:"BUILD: nmake.exe failed" "%XP25_NT_OUT%\%XP25_NT_STAGE%-%XP25_NT_N%.log" > nul
if not errorlevel 1 set "XP25_NT_RESULT=1"
for %%E in (build*.err) do if %%~zE GTR 0 set "XP25_NT_RESULT=1"
for %%E in (build*.err build*.wrn) do if exist "%%E" copy /y "%%E" "%XP25_NT_OUT%\%XP25_NT_STAGE%-%XP25_NT_N%-%%E" > nul
type "%XP25_NT_OUT%\%XP25_NT_STAGE%-%XP25_NT_N%.log" > COM1
popd
goto :eof

:collect
if exist "C:\nt\%~1" (
  copy /y "C:\nt\%~1" "%XP25_NT_OUT%\%XP25_NT_STAGE%\" > nul
) else (
  echo XP25_RECIPE_OUTPUT_MISSING %XP25_NT_STAGE% %~1 > COM1
  set "XP25_NT_RESULT=1"
)
goto :eof
