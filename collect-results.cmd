@echo off
rem Re-collects Dependency-Track v5 results (starts the containers if needed, stops them after).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0collect-results.ps1"
echo.
echo Finished. You can close this window.
pause
