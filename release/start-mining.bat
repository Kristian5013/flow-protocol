@echo off
title FTC Mining - Node + Miner
echo ==========================================
echo   FTC Mining Suite
echo   Kristian Pilatovich - First Real P2P
echo ==========================================
echo.

:: Check if node is already running
tasklist /FI "IMAGENAME eq ftc-node.exe" 2>NUL | find /I /N "ftc-node.exe">NUL
if "%ERRORLEVEL%"=="0" (
    echo [*] Node already running
) else (
    echo [+] Starting FTC Node...
    start /MIN "FTC Node" ftc-node.exe
    timeout /t 3 /nobreak >nul
)

echo [+] Starting FTC Miner...
echo.
ftc-miner.exe

:: When miner exits, ask about node
echo.
echo Miner stopped.
choice /C YN /M "Keep node running in background"
if errorlevel 2 (
    echo [*] Stopping node...
    taskkill /IM ftc-node.exe /F >nul 2>&1
)
