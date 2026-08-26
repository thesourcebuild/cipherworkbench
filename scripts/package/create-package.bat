@echo off
REM Creates a shareable release package. Forwards all arguments to create-package.ps1.
REM
REM   scripts\package\create-package.bat -Release -Verify     source + binary, with the quality gate
REM   scripts\package\create-package.bat -Source              source archive only (seconds)
REM   scripts\package\create-package.bat -Binary              web zip + installer
REM   scripts\package\create-package.bat -Release -Zip        also produce one archive of the release
REM   scripts\package\create-package.bat -Binary -Arch x64,arm64
REM
REM With none of -Source/-Binary/-Release given, it produces the full release.
REM Output lands in dist\<version>\ with SHA256SUMS.txt and RELEASE.md.
REM
REM See launch_web.bat for why the shell is chosen up front rather than by retrying.

setlocal
set "PSEXE=pwsh"
where /q pwsh || set "PSEXE=powershell"

"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0create-package.ps1" %*
exit /b %ERRORLEVEL%
