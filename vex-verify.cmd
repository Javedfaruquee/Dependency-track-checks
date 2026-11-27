@echo off
rem Gap 1: checks the VEX upload on the Dependency-Track test stack, and pushes the fix to GitHub only if the check passes.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0vex-verify.ps1"
echo.
echo Finished. Results are in vex-verify-results.json in this folder. You can close this window.
pause
