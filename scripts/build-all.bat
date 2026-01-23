@echo off
REM FTC Build Script for Windows
REM Requires: Visual Studio 2019/2022 with CMake, vcpkg (optional)

setlocal enabledelayedexpansion

echo ========================================
echo FTC Build Script (Windows)
echo ========================================
echo.

REM Set directories
set ROOT_DIR=%~dp0..
set BUILD_TYPE=Release

REM Parse arguments
:parse_args
if "%~1"=="" goto :done_args
if /i "%~1"=="--debug" set BUILD_TYPE=Debug
if /i "%~1"=="-d" set BUILD_TYPE=Debug
if /i "%~1"=="--clean" set CLEAN_BUILD=1
shift
goto :parse_args
:done_args

echo Build type: %BUILD_TYPE%
echo Root directory: %ROOT_DIR%
echo.

REM Check for CMake
where cmake >nul 2>&1
if errorlevel 1 (
    echo ERROR: CMake not found! Please install CMake and add to PATH.
    exit /b 1
)

REM Clean if requested
if defined CLEAN_BUILD (
    echo Cleaning build directories...
    if exist "%ROOT_DIR%\ftc-node\build" rmdir /s /q "%ROOT_DIR%\ftc-node\build"
    if exist "%ROOT_DIR%\ftc-miner-v2\build" rmdir /s /q "%ROOT_DIR%\ftc-miner-v2\build"
    if exist "%ROOT_DIR%\ftc-wallet\build" rmdir /s /q "%ROOT_DIR%\ftc-wallet\build"
    if exist "%ROOT_DIR%\ftc-keygen\build" rmdir /s /q "%ROOT_DIR%\ftc-keygen\build"
    echo.
)

REM Create output directory
if not exist "%ROOT_DIR%\bin" mkdir "%ROOT_DIR%\bin"

REM Build ftc-node
echo ========================================
echo Building ftc-node...
echo ========================================
if not exist "%ROOT_DIR%\ftc-node\build" mkdir "%ROOT_DIR%\ftc-node\build"
pushd "%ROOT_DIR%\ftc-node\build"
cmake .. -DCMAKE_BUILD_TYPE=%BUILD_TYPE%
if errorlevel 1 (
    echo ERROR: CMake configuration failed for ftc-node
    popd
    exit /b 1
)
cmake --build . --config %BUILD_TYPE%
if errorlevel 1 (
    echo ERROR: Build failed for ftc-node
    popd
    exit /b 1
)
copy /Y "%BUILD_TYPE%\ftc-node.exe" "%ROOT_DIR%\bin\" 2>nul
popd
echo ftc-node built successfully!
echo.

REM Build ftc-miner-v2
echo ========================================
echo Building ftc-miner-v2...
echo ========================================
if not exist "%ROOT_DIR%\ftc-miner-v2\build" mkdir "%ROOT_DIR%\ftc-miner-v2\build"
pushd "%ROOT_DIR%\ftc-miner-v2\build"
cmake .. -DCMAKE_BUILD_TYPE=%BUILD_TYPE%
if errorlevel 1 (
    echo ERROR: CMake configuration failed for ftc-miner-v2
    popd
    exit /b 1
)
cmake --build . --config %BUILD_TYPE%
if errorlevel 1 (
    echo ERROR: Build failed for ftc-miner-v2
    popd
    exit /b 1
)
copy /Y "%BUILD_TYPE%\ftc-miner.exe" "%ROOT_DIR%\bin\" 2>nul
popd
echo ftc-miner built successfully!
echo.

REM Build ftc-wallet
echo ========================================
echo Building ftc-wallet...
echo ========================================
if not exist "%ROOT_DIR%\ftc-wallet\build" mkdir "%ROOT_DIR%\ftc-wallet\build"
pushd "%ROOT_DIR%\ftc-wallet\build"
cmake .. -DCMAKE_BUILD_TYPE=%BUILD_TYPE%
if errorlevel 1 (
    echo ERROR: CMake configuration failed for ftc-wallet
    popd
    exit /b 1
)
cmake --build . --config %BUILD_TYPE%
if errorlevel 1 (
    echo ERROR: Build failed for ftc-wallet
    popd
    exit /b 1
)
copy /Y "%BUILD_TYPE%\ftc-wallet.exe" "%ROOT_DIR%\bin\" 2>nul
popd
echo ftc-wallet built successfully!
echo.

REM Build ftc-keygen
echo ========================================
echo Building ftc-keygen...
echo ========================================
if not exist "%ROOT_DIR%\ftc-keygen\build" mkdir "%ROOT_DIR%\ftc-keygen\build"
pushd "%ROOT_DIR%\ftc-keygen\build"
cmake .. -DCMAKE_BUILD_TYPE=%BUILD_TYPE%
if errorlevel 1 (
    echo ERROR: CMake configuration failed for ftc-keygen
    popd
    exit /b 1
)
cmake --build . --config %BUILD_TYPE%
if errorlevel 1 (
    echo ERROR: Build failed for ftc-keygen
    popd
    exit /b 1
)
copy /Y "%BUILD_TYPE%\ftc-keygen.exe" "%ROOT_DIR%\bin\" 2>nul
popd
echo ftc-keygen built successfully!
echo.

echo ========================================
echo BUILD COMPLETE!
echo ========================================
echo.
echo Binaries are located in: %ROOT_DIR%\bin\
echo.
dir /b "%ROOT_DIR%\bin\*.exe" 2>nul
echo.
echo Run with:
echo   ftc-node.exe          - Start the blockchain node
echo   ftc-miner.exe         - Start GPU mining
echo   ftc-wallet.exe        - Wallet operations
echo   ftc-keygen.exe        - Generate new wallet keys

endlocal
