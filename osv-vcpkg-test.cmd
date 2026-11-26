@echo off
rem Removes ConanCenter from OSV and tests the OSV vcpkg ecosystem (starts and stops the containers).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0osv-vcpkg-test.ps1"
echo.
echo Finished. You can close this window.
pause
