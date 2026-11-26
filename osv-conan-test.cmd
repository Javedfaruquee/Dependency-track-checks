@echo off
rem Tests Conan/vcpkg package URLs against OSV ConanCenter and vcpkg advisories (starts and stops the containers).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0osv-conan-test.ps1"
echo.
echo Finished. You can close this window.
pause
