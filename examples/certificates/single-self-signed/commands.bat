@echo off
setlocal

REM Sanity check: Ensure OpenSSL is present in PATH
where /q openssl
if %ERRORLEVEL% neq 0 (
    echo [ERROR] OpenSSL was not found in your PATH.
    echo Please install OpenSSL and ensure it is present in your PATH.
    if "%~1"=="" pause
    exit /b 1
)

REM Select PowerShell engine: pwsh or powershell
set "PSEXE=pwsh"
where /q pwsh >nul 2>&1 || set "PSEXE=powershell"

"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0commands.ps1" %*
set "EXIT_CODE=%ERRORLEVEL%"
if "%~1"=="" pause
exit /b %EXIT_CODE%
