@echo off
rem Adds OSV ecosystems PyPI, npm, NuGet, Maven, tests them and saves the analyzer/KEV settings schemas (starts and stops the containers).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0osv-more.ps1"
echo.
echo Finished. You can close this window.
pause
