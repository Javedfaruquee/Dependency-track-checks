@echo off
rem Gap 2: upgrades the Dependency-Track test stack to 5.2.2 (NVD feed adapter 2.2 first; data volumes kept), then checks that stale or failing vulnerability data is reported on it (real faults, all restored), and pushes the fix to GitHub only if the check passes. Takes about 1 to 2 hours; the window can stay in the background.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0dt-health-verify.ps1"
echo.
echo Finished. Results are in dt-health-verify-results.json in this folder. You can close this window.
pause
