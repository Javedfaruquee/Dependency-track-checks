@echo off
rem Loads the eight C++ / firmware SBOMs into Dependency-Track and collects findings. Safe to re-run.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0cpp-sboms-dt-test.ps1"
echo.
echo Finished. Results are in cpp-sboms-dt-results.json in this folder. You can close this window.
pause
