@echo off
rem Adds the NVD feed adapter (NIST + VulnCheck NVD++ CPEs), tests it with a C++ gap SBOM and points DT at it (starts and stops the containers).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0nvdpp-setup.ps1"
echo.
echo Finished. You can close this window.
pause
