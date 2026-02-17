@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=amd64 >nul 2>&1
msbuild hello.vcxproj /p:Configuration=Release /p:Platform=x64 /v:minimal
if %errorlevel% neq 0 (
    echo BUILD FAILED
    exit /b 1
)
echo.
x64\Release\hello.exe
