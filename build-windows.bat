@echo off
REM FTC Build Script for Windows
REM Kristian Pilatovich 20091227 - First Real P2P

echo ========================================
echo   FTC Build Script for Windows
echo ========================================
echo.

REM Create dist directory
if not exist dist mkdir dist

REM Build ftc-node
echo Building ftc-node...
cd ftc-node
if not exist build mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
copy Release\ftc-node.exe ..\..\dist\
cd ..\..
echo ftc-node built!

REM Build ftc-wallet
echo Building ftc-wallet...
cd ftc-wallet
if not exist build mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
copy Release\ftc-wallet.exe ..\..\dist\
cd ..\..
echo ftc-wallet built!

REM Build ftc-miner
echo Building ftc-miner...
cd ftc-miner-v2
if not exist build mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
copy Release\ftc-miner.exe ..\..\dist\
cd ..\..
echo ftc-miner built!

REM Build ftc-full
echo Building ftc-full...
cd ftc-full
if not exist build mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
copy Release\ftc-full.exe ..\..\dist\
cd ..\..
echo ftc-full built!

echo.
echo ========================================
echo Build complete!
echo ========================================
echo.
echo Binaries are in .\dist\
dir dist\*.exe
echo.
echo Usage:
echo   dist\ftc-full -a ftc1q...
echo   dist\ftc-node
echo   dist\ftc-miner -a ftc1q...
echo   dist\ftc-wallet new
