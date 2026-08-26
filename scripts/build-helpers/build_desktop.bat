@echo off
REM Builds the Electron desktop app, and optionally its installer.
REM
REM   scripts\build-helpers\build_desktop.bat                    build web + renderer + main bundle
REM   scripts\build-helpers\build_desktop.bat -Clean -Smoke      clean build, then check it really loads
REM   scripts\build-helpers\build_desktop.bat -Package           also produce the setup .exe
REM   scripts\build-helpers\build_desktop.bat -Package -Arch x64,arm64
REM
REM See launch_web.bat for why the shell is chosen up front rather than by retrying.

setlocal
set "PSEXE=pwsh"
where /q pwsh || set "PSEXE=powershell"

"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0build_desktop.ps1" %*
exit /b %ERRORLEVEL%
