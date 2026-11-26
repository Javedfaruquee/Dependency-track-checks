@echo off
rem Asks for the Sonatype OSS Index and VulnCheck tokens, stores them as DT secrets, enables both, re-analyses (starts and stops the containers).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0set-api-keys.ps1"
echo.
echo Finished. You can close this window.
pause
