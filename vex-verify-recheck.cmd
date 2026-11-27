@echo off
rem Gap 1 re-check after a Dependency-Track upgrade (now 5.2.2): runs the VEX upload checks again and pushes only the results to GitHub if they pass. Takes about 5 to 10 minutes.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0vex-verify.ps1" -Recheck
echo.
echo Finished. Results are in vex-verify-results.json in this folder. You can close this window.
pause
