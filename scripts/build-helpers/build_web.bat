@echo off
REM Builds the web static export (apps/web/out).
REM
REM   scripts\build-helpers\build_web.bat                 build it
REM   scripts\build-helpers\build_web.bat -Clean          delete output first and bypass the turbo cache
REM   scripts\build-helpers\build_web.bat -Serve          build, then serve it on http://localhost:3000
REM
REM See launch_web.bat for why the shell is chosen up front rather than by retrying.

setlocal
set "PSEXE=pwsh"
where /q pwsh || set "PSEXE=powershell"

"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0build_web.ps1" %*
exit /b %ERRORLEVEL%
