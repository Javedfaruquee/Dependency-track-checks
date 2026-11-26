@echo off
rem Runs the Dependency-Track v5 C++ SBOM test. Safe to re-run.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run-dt5-test.ps1"
echo.
echo Finished. Results are in results.json in this folder. You can close this window.
pause
