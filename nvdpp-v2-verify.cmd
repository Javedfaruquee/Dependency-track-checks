@echo off
rem Verifies NVD feed adapter v2 on the real stack (feeds rebuilt, NVD mirror, findings). Can take up to 2 hours the first time.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0nvdpp-v2-verify.ps1"
echo.
echo Finished. Results are in nvdpp-v2-verify-results.json. You can close this window.
pause
