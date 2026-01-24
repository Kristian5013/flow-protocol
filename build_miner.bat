@echo off
REM FTC Miner Build Script
REM Uses PowerShell to properly set MSYS2 environment

powershell -Command "$env:PATH = 'C:\msys64\ucrt64\bin;' + $env:PATH; cd c:\flow-protocol-main\ftc-miner-v2; if (Test-Path build) { Remove-Item -Recurse -Force build }; New-Item -ItemType Directory build | Out-Null; cd build; & 'C:\Program Files\CMake\bin\cmake.exe' .. -G 'MinGW Makefiles'; mingw32-make -j4"

if errorlevel 1 (
    echo Build failed
    pause
    exit /b 1
)

copy c:\flow-protocol-main\ftc-miner-v2\build\ftc-miner.exe c:\flow-protocol-main\dist\windows\ftc-miner.exe

echo.
echo Build successful!
echo Binary: c:\flow-protocol-main\dist\windows\ftc-miner.exe
