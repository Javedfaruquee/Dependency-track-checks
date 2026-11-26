@echo off
rem Runs Trivy 0.76.2 alone (no OSS Index, no NVD CPE matching) on the Conan SBOMs, using the cached Trivy database.
cd /d "%~dp0"
for %%F in (cpp-conan-native cpp-conan-normalised) do (
  echo Scanning %%F ...
  docker run --rm -v dt5-test_trivy-cache:/root/.cache/trivy -v "%cd%:/work" ghcr.io/aquasecurity/trivy:0.76.2 sbom --skip-db-update --cache-dir /root/.cache/trivy --format json --output /work/trivy-only-%%F.json /work/sboms/%%F.cdx.json
)
echo.
echo Finished. You can close this window.
pause
