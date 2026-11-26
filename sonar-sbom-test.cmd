@echo off
rem Imports the sample C++ / firmware SBOMs into SonarQube staging and collects the results. Asks for a Sonar token (hidden).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0sonar-sbom-test.ps1"
echo.
echo Finished. Results are in sonar-sca-test\results.json. You can close this window.
pause
