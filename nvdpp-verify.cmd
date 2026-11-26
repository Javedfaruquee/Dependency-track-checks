@echo off
rem Verifies the NVD feed adapter with a C/C++ gap SBOM, then runs the conan audit test (asks for the Conan Audit token).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0nvdpp-verify.ps1"
echo.
echo Finished. You can close this window.
pause
