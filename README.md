# Dependency-Track v5 checks

Hands-on test of OWASP Dependency-Track 5.2.1 as the SBOM system of record, with a focus on C/C++ (Conan, vcpkg, vendored code) and on which vulnerability sources improve results. Run on Docker Desktop (Windows), November 2026.

## Stack (`compose.yaml`)

| Service | Image | Port |
|---|---|---|
| PostgreSQL | `postgres:18-alpine` | internal |
| Dependency-Track API server | `ghcr.io/dependencytrack/apiserver:5.2.1` | 8081 |
| Dependency-Track UI | `ghcr.io/dependencytrack/frontend:5.2.1` | 8080 |
| Trivy server | `ghcr.io/aquasecurity/trivy:0.76.2` | 4954 |
| NVD feed adapter | `python:3.13-slim` running `nvdpp/adapter.py` | 8090 (`/stats`) |

Start with `docker compose up -d`, open http://localhost:8080 (test login `admin` / `DtTest-2026!`; change it for anything beyond a local test), stop with `docker compose stop`. Data and vulnerability databases stay in Docker volumes.

Tokens live in `.env` (not committed): `TRIVY_TOKEN`, `VULNCHECK_TOKEN`. The scripts ask for tokens in a hidden prompt and never log them.

## Tests (run in this order; each `.cmd` starts its `.ps1`)

| Script | What it tests | Results |
|---|---|---|
| `run-dt5-test.cmd`, `collect-results.cmd` | Install DT, mirror NVD and OSV, load the C++ and Python SBOMs | `results.json`, `log.txt`, `collect-log.txt` |
| `osv-conan-test.cmd`, `osv-vcpkg-test.cmd` | OSV ConanCenter and vcpkg ecosystems (no data published: HTTP 404) | `osv-conan-*.json`, `osv-vcpkg-*.json` |
| `osv-more.cmd` | OSV PyPI, npm, NuGet, Maven; npm, NuGet and Maven control SBOMs; DT settings dump | `osv-more-results.json`, `dt5-extensions.json` |
| `set-api-keys.cmd` | Sonatype OSS Index and VulnCheck KEV keys as DT managed secrets | log only |
| `trivy-setup.cmd`, `trivy-conan-check.cmd` | Trivy analyzer in DT, and Trivy alone on the Conan SBOMs | `trivy-results.json`, `trivy-only-*.json` |
| `nvdpp-setup.cmd`, `nvdpp-verify.cmd` | NVD feed adapter adding VulnCheck NVD++ CPEs for CVEs NIST left without CPEs; C/C++ gap SBOM | `nvdpp-results.json`, `nvdpp-verify-results.json` |
| `conan-audit-test.cmd` | `conan audit` (ConanCenter provider) on the same SBOMs and references | `conan-audit/`, `conan-audit-log.txt` |
| `cpp-sboms-dt-test.cmd` | The eight CMake-only C++ and firmware SBOMs from `cpp-sboms/`, plus two variants with ConanCenter identifiers | `cpp-sboms-dt-results.json`, `cpp-sboms/dt-exports/`, `cpp-sboms-dt-log.txt` |

Test SBOMs are in `sboms/`.

## Key results

- C++ SBOMs need identifiers: Conan's own SBOM matched 0 CVEs on NVD and OSV alone, 52 with OSS Index, and 79 to 82 with CPEs added plus OSS Index and the VulnCheck adapter.
- DT 5.2.1 still rejects SPDX; convert to CycloneDX first.
- OSV publishes no ConanCenter or vcpkg data; one missing ecosystem fails the whole OSV mirror.
- VulnCheck NVD++ (free community token) adds CPEs to 56,106 CVEs that NIST left without them; on a C/C++ gap SBOM, 178 of 293 findings came only through VulnCheck CPEs.
- Trivy alone found 5 Conan CVEs; `conan audit` found 54, all also found by DT.
- Totals count GHSA, PYSEC and CVE IDs for one issue separately: turn on alias sync and report distinct issues.
- CMake-only C++ and firmware (`cpp-sboms/`): the complete build-derived SBOMs matched 61 and 160 CVEs, all through CPEs. The cve-bin-tool SBOM missed all 50 OpenSSL and cJSON CVEs. ConanCenter identifiers added 6 and 20 through OSS Index. Dependency-Track's own export loses BSI TR-03183-2 v2.1 fields (score 10 falls to 7.4–7.6), so keep the original signed SBOM.

## NVD feed adapter (`nvdpp/adapter.py`)

Point DT's NVD source at `http://nvdpp:8080/feeds`. The adapter passes NIST's yearly feeds through unchanged and rebuilds the modified feed with VulnCheck CPEs for CVEs NIST did not enrich. It refreshes itself while running (no cron or CI job) and falls back to NIST data if VulnCheck is unavailable. VulnCheck community terms require attribution where its CPE data is used.

Open issue: on a second update DT re-ingested the 56,106 enriched CVEs although the adapter had marked them delivered (harmless, about 30 s). Investigate before production use.
