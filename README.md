# Dependency-Track v5 checks

Hands-on test of OWASP Dependency-Track 5.2 (5.2.1, upgraded to 5.2.2 on 27 November 2026) as the SBOM system of record, with a focus on C/C++ (Conan, vcpkg, vendored code) and on which vulnerability sources improve results. Run on Docker Desktop (Windows), November 2026.

## Stack (`compose.yaml`)

| Service | Image | Port |
|---|---|---|
| PostgreSQL | `postgres:18-alpine` | internal |
| Dependency-Track API server | `ghcr.io/dependencytrack/apiserver:5.2.2` | 8081 |
| Dependency-Track UI | `ghcr.io/dependencytrack/frontend:5.2.2` | 8080 |
| Trivy server | `ghcr.io/aquasecurity/trivy:0.76.2` | 4954 |
| NVD feed adapter | `python:3.13-slim` running `nvdpp/adapter.py` | 8090 (`/stats`, `/health`) |

Start with `docker compose up -d`, open http://localhost:8080 (test login `admin` / `DtTest-2026!`; change it for anything beyond a local test), stop with `docker compose stop`. Data and vulnerability databases stay in Docker volumes.

Tokens live in `.env` (not committed): `TRIVY_TOKEN`, `VULNCHECK_TOKEN`. The scripts ask for tokens in a hidden prompt and never log them.

## Upgrade to 5.2.2 (27 Nov 2026)

ENISA moved its EU KEV feed on 16 Nov 2026 and changed its format. On DT 5.2.1 every ENISA mirror then failed with HTTP 404. The gap 2 health check reported it, and so did DT's own alert for failed mirrors. DT 5.2.2 (18 Nov 2026) reads the new feed. It also pins FreeMarker 2.3.35 and snappy-java 1.1.10.12 for known CVEs, sets a JVM flag against CVE-2026-114938, and revokes a user's sessions when the password changes or the account is suspended.

- `compose.yaml` pins `apiserver` and `frontend` to 5.2.2. The data volumes stay.
- **Set the ENISA feed URL after upgrading.** DT stores an extension's default settings when it first starts, so an existing install keeps the old URL. The new one is `https://raw.githubusercontent.com/enisaeu/CNW/main/eukev/eukev.json`. `dt-health-verify.cmd` sets it on this stack.
- 5.2.2 skips NVD's yearly feeds while its watermark is less than 6 days old. NVD feed adapter 2.2 also puts recently rewritten CVEs into `modified` (see `nvdpp/README.md`).
- Start the adapter before DT: `dt-health-verify.cmd` starts adapter 2.2, waits until it has built `modified`, then starts DT 5.2.2.
- Rollback: set both tags back to 5.2.1. 5.2.2 has no database migrations. ENISA then fails again (5.2.1 cannot read the new feed, and the old URL is gone). Keep adapter 2.2; it works with 5.2.1.

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
| `nvdpp-v2-verify.cmd` | NVD feed adapter version 2 on the stack: all feeds rebuilt, NVD mirror, findings for the `cpp-sbom-*` projects | `nvdpp-v2-verify-results.json`, `nvdpp-alias-suggestions.json` |
| `sonar-sbom-test.cmd` | SonarQube staging: imports three sample SBOMs with `sonar.sca.sbomImportPaths` (asks for a Sonar token, hidden) | `sonar-sca-test/` (not in git: internal server data) |
| `vex-verify.cmd` | Gap 1, VEX upload on DT 5.2.1: reproduces the lost-VEX race, runs `cpp-sboms/ci/dt-vex-upload.py` with a least-privilege CI key, checks DT's findings independently; commits and pushes only on PASS | `vex-verify-results.json` |
| `vex-verify-recheck.cmd` | Gap 1 re-check after a DT upgrade (run on 5.2.2): the same checks as `vex-verify.cmd`; commits only the results, and only on PASS | `vex-verify-results.json` |
| `dt-health-verify.cmd` | Gap 2, vulnerability data health on DT 5.2.2: upgrades the stack from 5.2.1 and sets ENISA's new feed URL, loads adapter 2.2, runs every mirror, then injects six real faults one at a time (stale threshold, OSS Index token revoked, Trivy analyzer disabled, Trivy server stopped, adapter stopped, VulnCheck token rejected), checks that `cpp-sboms/ci/dt-health-check.py` reports each one, and restores it; checks DT's own failed-mirror alert end to end; runs the check during a burst of 150 uploads; commits and pushes only on PASS | `dt-health-verify-results.json` |

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

Version 2 (26 Nov 2026) replaces this section's version 1 behaviour; see `nvdpp/README.md`. It rewrites every feed file, not only `modified`, gives each rewritten CVE a stable `lastModified` stored in the cache, and applies CPE vendor aliases from `nvdpp/cpe-aliases.json`. That fixes two version 1 problems: CVEs losing their VulnCheck CPEs after a restart, and all 56,106 enriched CVEs being re-ingested. `nvdpp/tests/test_adapter.py` reproduces both against a client that follows Dependency-Track's NVD rules.

Version 2.2 (27 Nov 2026) is for DT 5.2.2, which reads only the modified feed on its daily mirrors: CVEs that VulnCheck enriches or that gain an alias also go into `modified`, copied from the adapter's own yearly feed.

Version 2.1 (27 Nov 2026) adds `/health`. It answers 503, with the reasons, when NIST or VulnCheck data is stale, the VulnCheck token is rejected or missing, or a drop guard stopped a much smaller VulnCheck backup or NIST file. `/healthz` stays a plain liveness answer. See `nvdpp/README.md`.
