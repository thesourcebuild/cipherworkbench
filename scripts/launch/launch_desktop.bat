@echo off
REM See launch_web.bat for why the shell is chosen up front rather than by retrying.

REM No IF/ELSE block on purpose. The paths below sit inside `%~dp0`, and an absolute path to
REM this repo contains parentheses -- which cmd's parser handles inside a parenthesised block
REM only because they are quoted. Setting a variable instead removes the class of problem, and
REM matches how the command generator this repo is modelled on writes its launchers.
setlocal
set "PSEXE=pwsh"
where /q pwsh || set "PSEXE=powershell"

"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0launch_desktop.ps1" %*
exit /b %ERRORLEVEL%
