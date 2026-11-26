@echo off
rem Runs conan audit (ConanCenter provider) on the C++ test SBOMs and a few references, in a throw-away container.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0conan-audit-test.ps1"
echo.
echo Finished. You can close this window.
pause
