@echo off
rem Adds a Trivy server to the DT test stack, connects DT to it, re-analyses and collects results (starts and stops the containers).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0trivy-setup.ps1"
echo.
echo Finished. You can close this window.
pause
