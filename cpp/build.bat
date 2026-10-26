@echo off
rem Builds the C++ core: build\alicore.dll (the engine src\cpp_core.py loads) and
rem build\alicore_tests.exe (its own tests).  Needs Visual Studio 2022 (MSVC).
rem   build.bat [folder]   into that folder instead of build\ (a development copy
rem                        while tests run on build\: ALISIM_CPP_DLL points at it)
setlocal
cd /d "%~dp0"
set OUT=build
if not "%~1"=="" set OUT=%~1
if not defined VCINSTALLDIR (
  call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 >nul 2>&1
)
if not exist %OUT% mkdir %OUT%
set CFLAGS=/nologo /O2 /Oi /GL /EHsc /std:c++17 /W3 /DNDEBUG /MT /Iemulator
set SRC=emulator\alicore.cpp emulator\alicore_exec.cpp emulator\alicore_fpu.cpp
cl %CFLAGS% /LD %SRC% emulator\alicore_api.cpp /Fo%OUT%\ /Fe:%OUT%\alicore.dll /link /LTCG /OPT:REF >%OUT%\build.log 2>&1
if errorlevel 1 (
  type %OUT%\build.log
  echo BUILD FAILED
  exit /b 1
)
cl %CFLAGS% %SRC% tests\alicore_tests.cpp /Fo%OUT%\ /Fe:%OUT%\alicore_tests.exe /link /LTCG >>%OUT%\build.log 2>&1
if errorlevel 1 (
  type %OUT%\build.log
  echo BUILD FAILED
  exit /b 1
)
echo built %OUT%\alicore.dll and %OUT%\alicore_tests.exe
