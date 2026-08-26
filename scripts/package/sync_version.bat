@echo off
REM Brings every workspace package.json in line with the root version file.
REM
REM   scripts\package\sync_version.bat              sync to whatever the version file says
REM   scripts\package\sync_version.bat -Set 0.2.0   bump the file and the manifests together
REM   scripts\package\sync_version.bat -Check       fail if anything disagrees, write nothing
REM
REM See launch_web.bat for why the shell is chosen up front rather than by retrying.

setlocal
set "PSEXE=pwsh"
where /q pwsh || set "PSEXE=powershell"

"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0sync_version.ps1" %*
exit /b %ERRORLEVEL%
