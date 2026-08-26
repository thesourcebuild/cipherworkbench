@echo off
REM Regenerates apps\desktop\resources\icon.png and icon.ico from the design in icon.svg.
REM
REM   scripts\package\make_icon.bat                     write both into apps\desktop\resources
REM   scripts\package\make_icon.bat -OutDir C:\somewhere write them elsewhere
REM
REM Uses System.Drawing rather than a real rasteriser, so it needs nothing installed.
REM
REM See launch_web.bat for why the shell is chosen up front rather than by retrying.

setlocal
set "PSEXE=pwsh"
where /q pwsh || set "PSEXE=powershell"

"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0make_icon.ps1" %*
exit /b %ERRORLEVEL%
