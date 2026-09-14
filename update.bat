@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"
title Imno Updater - Incremental (only changed files)

REM ================= CONFIG =================
set "REPO=hodakaram1/masrt"
set "BRANCH=main"
REM If you work on arena branch, change to arena/01a0a0d5-masrt
REM set "BRANCH=arena/01a0a0d5-masrt"
set "RAW_BASE=https://raw.githubusercontent.com/%REPO%/%BRANCH%/"
set "MANIFEST_FILE=update_manifest.json"
set "VERSION_FILE=version.txt"
set "LOCAL_VERSION=0.0.0"
set "REMOTE_VERSION=0.0.0"

echo ==========================================
echo   Imno Incremental Updater
echo   Repo: %REPO%  Branch: %BRANCH%
echo ==========================================
echo.

REM --- Check for PowerShell ---
where powershell >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] PowerShell not found! Please install PowerShell 5.1+
    pause
    exit /b 1
)

REM --- Read local version ---
if exist "%VERSION_FILE%" (
    set /p LOCAL_VERSION=<"%VERSION_FILE%"
) else (
    set "LOCAL_VERSION=0.0.0"
)
echo [LOCAL] Version: %LOCAL_VERSION%

REM --- Download remote version.txt ---
echo [REMOTE] Checking %RAW_BASE%%VERSION_FILE% ...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop'; try { $v=(Invoke-WebRequest -Uri '%RAW_BASE%%VERSION_FILE%' -UseBasicParsing -TimeoutSec 15).Content.Trim(); $v | Out-File -Encoding ascii 'version_remote.txt'; Write-Host \"[REMOTE] Version: $v\" } catch { Write-Host \"[ERROR] Could not fetch remote version: $_\" -ForegroundColor Red; exit 1 }"

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to fetch remote version. Check internet / repo URL.
    pause
    exit /b 1
)

set /p REMOTE_VERSION=<"version_remote.txt"
del /f /q "version_remote.txt" 2>nul

echo [LOCAL]  %LOCAL_VERSION%
echo [REMOTE] %REMOTE_VERSION%
echo.

REM --- Compare versions (simple string compare, for proper semver we use PowerShell) ---
powershell -NoProfile -Command ^
  "$lv=[version]'%LOCAL_VERSION%'; $rv=[version]'%REMOTE_VERSION%'; if ($rv -gt $lv) { exit 0 } else { exit 1 }"

if %ERRORLEVEL% NEQ 0 (
    echo [INFO] Already up to date! No update needed.
    echo Local %LOCAL_VERSION% is same or newer than remote %REMOTE_VERSION%
    pause
    exit /b 0
)

echo [UPDATE] New version available! %LOCAL_VERSION% -> %REMOTE_VERSION%
echo [UPDATE] Downloading manifest %MANIFEST_FILE% ...
powershell -NoProfile -Command "Invoke-WebRequest -Uri '%RAW_BASE%%MANIFEST_FILE%' -OutFile '%MANIFEST_FILE%.remote' -UseBasicParsing"

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Could not download manifest.
    pause
    exit /b 1
)

echo [UPDATE] Checking changed files (SHA256) ...
echo.

REM --- PowerShell does the heavy lifting: compare hashes and download only changed ---
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\Update-Helper.ps1" -Manifest "%MANIFEST_FILE%.remote" -RawBase "%RAW_BASE%"

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Update failed in helper script.
    pause
    exit /b 1
)

REM --- Replace local manifest and version ---
move /y "%MANIFEST_FILE%.remote" "%MANIFEST_FILE%" >nul
echo %REMOTE_VERSION% > "%VERSION_FILE%"

echo.
echo ==========================================
echo   UPDATE SUCCESSFUL to %REMOTE_VERSION%
echo ==========================================
echo   Changed files have been downloaded.
echo   Now rebuilding via build.bat ...
echo.

REM --- Auto rebuild if build.bat exists ---
if exist "build.bat" (
    choice /M "Do you want to rebuild Imno.exe and DBK64.sys now"
    if !ERRORLEVEL! EQU 1 (
        call build.bat Release
    )
)

echo.
echo Done! Press any key to exit.
pause
exit /b 0
