@echo off
REM See launch_web.bat for why the shell is chosen up front rather than by retrying.

setlocal
set "PSEXE=pwsh"
where /q pwsh || set "PSEXE=powershell"

"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0check_scripts.ps1" %*
exit /b %ERRORLEVEL%
