# SBOM release gate for CI

The same four steps run in GitHub Actions, GitLab CI and TeamCity. Every CI system calls one script, `sbom-release.sh`, so the rules stay the same across the three systems.

| Step | What it does | Fails the build when |
|---|---|---|
| 1. Generate | `cmake-sbom.py` or `fw-sbom.py` builds the SBOM from what the build used | A FetchContent dependency has no identifier mapping, or a declared version doesn't match the source or the binary |
| 2. Gate | `sbom-gate.py` runs sbomqs v2.1.3 (pinned and checksum-checked), a coverage check and an identifier check | Any required BSI TR-03183-2 v2.1 field scores below 10, the NTIA 2026 score is below 10, a library on the CMake link line is missing from the SBOM, an ELF file in the firmware image isn't listed, or a third-party component has no usable CPE |
| 3. Sign (release builds) | `sign-sbom.sh` makes a detached CMS signature through the SignPath Cryptoki provider (hash-based), then an RFC 3161 timestamp | Signing or the timestamp fails |
| 4. Publish | Uploads the SBOM to Dependency-Track. With a VEX for the release (`OPENVEX_FILE` or `VEX_FILE`), `dt-vex-upload.py` waits for DT's analysis, uploads the VEX and checks every statement. Then uploads the SBOM, signature, gate report, VEX and VEX report to Artifactory (`jf rt upload`) | An upload fails, the OpenVEX breaks the VEX policy, or DT did not apply a VEX statement (with `VEX_FAIL_ON_PENDING=true`, also when a statement can't be applied yet) |

**Why there's a coverage check.** When OpenSSL was removed from the firmware SBOM, the SBOM still scored 10 out of 10 on both BSI and NTIA. Only the check that every ELF file in the image is listed caught it. A compliance score shows the fields are filled in. It doesn't show the list is complete.

**Why there's an identifier check.** Dependency-Track checks C/C++ components against NVD by CPE only; package-URL sources (OSS Index, OSV) cover few C/C++ libraries. A third-party component without a usable CPE is listed but never checked, and no score shows it: an SBOM with cJSON's CPE removed still scores 10 on BSI and NTIA. The gate therefore needs every third-party component to have a CPE 2.3 with a product, a real version (not `*` or `-`) and the component's version. Distro suffixes such as `1.33.1-r0` or `2.39-0ubuntu8.9` are fine. A wildcard vendor (`cpe:2.3:a:*:cjson:…`) passes with a warning, because it matches every vendor's product of that name. Third-party means the supplier differs from the SBOM's manufacturer and supplier. `--own-supplier` sets our own supplier names instead.

Some libraries have no NVD entry at all. List them in a file and point `SBOM_CPE_EXCEPTIONS` at it. Each needs a reason, and the gate reports every exception it used as a warning and every unused one too:

```json
{"exceptions": [
  {"name": "tinyxml-fork", "version": "*", "reason": "Internal fork of TinyXML 2.6.2, no NVD entry; watched by the platform team"}
]}
```

**Why the VEX upload waits and checks.** Dependency-Track 5.2.1 imports a VEX in the background and reports nothing back. It skips the whole VEX when the project has no findings yet, which is the case right after a BOM upload while the analysis is still running. It also skips statements for vulnerabilities it doesn't know. The upload looks successful either way. `dt-vex-upload.py` therefore waits on the BOM token (DT gives the analysis run the same token), uploads, and then asks DT for the analysis of every statement and component. Each one ends up as one of these:

| Result | Meaning | Build |
|---|---|---|
| `APPLIED` | DT holds the expected state, suppression, justification, response and details on an existing finding | passes |
| `STORED` | DT knows the CVE and holds the analysis, but has no finding for that component yet; it applies if one appears | passes |
| `OPEN_UNDER_ALIAS` | the analysis is stored, but the component's finding is another record of the same issue (a GHSA, or another source), which stays open; add a statement for that id | passes with a warning; fails with `VEX_FAIL_ON_PENDING=true` |
| `PENDING_UNKNOWN_VULN` | DT doesn't know the CVE yet | as above |
| `PENDING_NO_FINDINGS` | the project has no findings, so DT would ignore the VEX; nothing is uploaded | as above |
| `NO_COMPONENT` | the VEX names a component the project doesn't have (checked first, before anything is uploaded) | fails |
| `AMBIGUOUS_VULN` | no source given and the id exists in several sources; DT skips it | fails |
| `NOT_APPLIED` | DT holds no analysis, or a different one | fails |

A VEX without statements fails too. The script also fails when a VEX is set but `DT_URL` or `DT_API_KEY` isn't, and when the BOM upload returns no token.

**Re-running pending statements.** DT overwrites an analysis whenever an uploaded statement differs from it, so uploading the whole VEX again would undo later manual triage. A daily job should re-apply only what was pending, using the previous report:

```
dt-vex-upload.py --url "$DT_URL" --vex product.vex.cdx.json --project-uuid "$UUID" --pending-from yesterday.json --report today.json
```

**API key.** The CI key needs `BOM_UPLOAD` and `PROJECT_CREATION_UPLOAD` for the SBOM, and `VIEW_PORTFOLIO`, `VIEW_VULNERABILITY` and `VULNERABILITY_ANALYSIS_UPDATE` for the VEX check. DT's default Automation team lacks the last two, so a VEX upload with it fails with HTTP 403. `vex-verify` tests with exactly these five permissions. The tool refuses `http://` to a server other than localhost or a container name.

The converter (`openvex-to-cdx-vex.py` 1.1) enforces the VEX policy before anything is uploaded:
- **It stops, and writes nothing,** when:
  - a `not_affected` statement has no justification or no impact statement;
  - an `affected` statement has no action statement;
  - no product of a statement is in the SBOM;
  - a status or vulnerability id is unusable.
- **Product matching.** Products are matched on their `@id`, `identifiers` and subcomponents, against SBOM components at any depth and the root. A product that is the root applies to the whole project. `sbom-cve-check` writes one product per identifier of the same component, often with a second CPE that isn't in the SBOM; such identifiers are listed as warnings, not errors.
- **Repeats and metadata.** When statements repeat for the same vulnerability and component, the latest timestamp wins. It keeps the OpenVEX author and timestamps.

## Watch the data (`dt-health-check.py`)

The release gate only helps if Dependency-Track's vulnerability data is current. In DT 5.2 (5.2.1 and 5.2.2), that data can stop without anyone noticing:

- **Mirrors.** A mirror that fails or stops running leaves the last data in place. A run stuck in `PENDING` blocks every later run. This happened for real: ENISA moved its EU KEV feed on 16 Nov 2026, and every ENISA mirror run on the test stack then failed with HTTP 404. The health check reported it, and DT's own alert reached the receiver. DT 5.2.2 reads the new feed, but an existing install keeps the old URL, because DT stores an extension's default settings at first start. After upgrading, set the ENISA source's feed URL to `https://raw.githubusercontent.com/enisaeu/CNW/main/eukev/eukev.json`.
- **The NVD feed adapter.** It kept serving its last build when NIST or VulnCheck failed, and DT's NVD mirror still reported `COMPLETED`.
- **Failed analyzers.** An analyzer that fails (for example, the Trivy server is down) keeps the findings it reported before, so they look current. DT only sends an `ANALYZER` notification, once per project.
- **Disabled analyzers.** An analyzer that someone switches off loses its findings at the next analysis.
- **OSS Index.** Results are cached for 24 hours, so a revoked token shows up a day late.
- **Portfolio re-analysis.** DT re-analyses every project daily. If that stops, new CVEs never reach existing products.
- **Trivy's database.** Trivy keeps scanning with an old database when it can't update it.

Two things watch for this:

1. **DT's own alert for failed mirrors.** Add a notification rule: scope SYSTEM, group `DATASOURCE_MIRRORING`, level ERROR, to the platform team's channel. It sends one alert per failed mirror run, between health check runs.
   - Do not send `ANALYZER` to people. DT sends it once per project, and re-analyses projects around the clock, so a Trivy outage would send thousands. Route it to a receiver that groups alerts, or rely on the canary below.
2. **`dt-health-check.py`, once a day** after the mirrors. Run it as a Kubernetes CronJob next to DT (`templates/dt-health.cronjob.yaml`), or from CI (`templates/dt-health.github-workflow.yml`). Keep `--state` between runs. It fails when any check finds a problem:

| Check | Problem when |
|---|---|
| Mirror runs | the latest run of an enabled vulnerability or KEV source is `FAILED`, missing, older than `max_age_hours` (30), or `PENDING`/`RUNNING` for longer than that (needs `--state` when DT gives no start time) |
| Configuration | a source or analyzer in `require_enabled` is disabled, or the NVD source no longer reads `nvd_feeds_url` (the adapter) |
| DT's own alerts | no enabled SYSTEM rule covers `DATASOURCE_MIRRORING`. A rule that sends `ANALYZER` to Slack, Teams, Mattermost, Webex, e-mail or Jira gives a warning |
| Live tests (`--test-extensions`) | DT's own extension test fails, for example the OSS Index token or the NVD feed URL, or DT refuses the test |
| Adapter | its `/health` reports a problem (see `nvdpp/README.md`), answers anything else without a reason, or doesn't answer |
| VulnCheck CPEs in DT | fewer than 90% of a sample of CVEs that the adapter first served at least 6 hours before DT's last NVD mirror run have CPE data in DT |
| Portfolio re-analysis | more than 10% of a sample of active projects (the 20 with the oldest BOM import, plus 100 at random) were last analysed more than 36 hours ago. Raise `max_age_hours` with DT's `dt.task.portfolio-analysis.max-analysis-age-ms` |
| Trivy database | `<trivy>/version` shows a database older than 48 hours. If the server gives no database metadata, this is a warning only |
| Canary | an expectation fails (for example, the internal analyzer doesn't report CVE-2022-37434 on zlib 1.2.11 by CPE), or every analyzer failed (DT marks the canary's token `FAILED`) |
| Analysis latency | DT took longer than `max_analysis_minutes` (30) to analyse the canary: its analysis is behind, so every finding is older than it looks. Over `warn_analysis_minutes` (10) is a warning |
| Trend (`--state`) | a count drops by more than 20% since the last run (a warning only) |

**How the canary works.** The canary is a small project, `dt-health-canary`, built from `health/dt-health-canary.cdx.json`.

| Component | Reported by |
|---|---|
| zlib with a CPE | internal analyzer, NVD data (CVE-2022-37434) |
| cJSON under the other vendor name | internal analyzer, through the adapter's alias (CVE-2019-11834) |
| zlib with a Conan purl | OSS Index (OSV and GitHub publish no ConanCenter data) |
| System.Net.Http 4.3.0 | internal analyzer with OSV/GitHub data (GHSA-7jgj-8wvc-jh57), and Trivy (CVE-2018-8292, which OSS Index doesn't report for it) |

DT's findings list shows only the first analyzer that reported a finding. So each expectation uses a component or an ID that only one analyzer reports. If OSS Index starts reporting CVE-2018-8292, the Trivy expectation fails; the message lists every finding on the component, so the cause is visible.

Every run re-creates the components, because their `group` alternates. This stops a failed analyzer's old findings from hiding the failure. It has one cost: DT reports about 15 canary findings as new on every run. Limit notification rules to projects or tags (the project is tagged `dt-health-canary`), and exclude it from dashboards. With `"rotate": false` the components stay, and only `--test-extensions` and DT's `ANALYZER` notifications catch failing analyzers.

**Scale.** The check's cost doesn't grow with the portfolio. A run makes about 40 to 50 API calls, whether DT holds 50 projects or 10,000. The test suite checks this with 5,000 and 10,000 projects, and fails above 80 calls.

- **What the calls cover:** each enabled source and analyzer, 20 sampled CVEs, the canary, and at most 6 calls for the portfolio sample. The report states the count (`apiCallsExcludingPolls`).
- **Token polls are counted separately (`tokenPolls`).** While DT works through a backlog, the check polls the canary's token. That count grows with the backlog, so it is kept out of the 80-call budget. It is bounded: every few seconds in the first minute, then every 30 seconds. That gives at most 66 polls at the 30-minute limit.
- **Queue priority:** BOM uploads (priority 50) are analysed before DT's scheduled re-analysis (priority 0), so the canary measures what a new release sees.
- **Load:** `dt-health-verify` runs the check during a burst of 150 uploads and compares its calls with the baseline.
- **Alert volume:** one result per run, not one per project.

**API keys.**
- **The health key** needs `VIEW_PORTFOLIO`, `VIEW_VULNERABILITY`, `SYSTEM_CONFIGURATION_READ`, `BOM_UPLOAD` and `PROJECT_CREATION_UPLOAD`. No key is sent to the adapter or to Trivy, and redirects are never followed.
- **With portfolio ACL off (DT's default),** `BOM_UPLOAD` lets the key replace the components of any project, so treat it like a CI key. Prefer ACL on: create the canary project once, map the health team to it, and drop `PROJECT_CREATION_UPLOAD`. Under ACL the portfolio sample only sees mapped projects, so map a representative set or set `portfolio_analysis.enabled` to false.
- **`--test-extensions`** also needs `SYSTEM_CONFIGURATION_UPDATE`, because DT requires it for its test endpoint. That permission can rewrite every extension setting, so give it to a separate key in a trusted scheduler, not to CI. Without it, a revoked OSS Index token shows within 24 hours plus one run, through the canary.
- **OSS Index rate limits.** DT's OSS Index test counts HTTP 402 and 429 as authentication passed, but the analyzer fails on them. The canary catches that once the cache expires.

**One scheduler only.** Two overlapping runs replace each other's canary. A run that finds its canary replaced reports a warning ("another dt-health-check run replaced the canary") and doesn't judge the canary in that run. Use the CronJob or a CI schedule, not both.

**Exit codes.** `0` means healthy, with any warnings listed. `1` means problems were found; the report (`--report`) has every check. `2` means the check couldn't run (DT unreachable, key rejected, a redirect).

## Files

| File | Use |
|---|---|
| `sbom-release.sh` | The entry point: `sbom-release.sh cmake <src> <build> <binary> <out>` or `sbom-release.sh firmware <manifest> <fw-dir> <src-dir> <out>` |
| `../generators/sbom-gate.py` | The gate. It can also run on its own: `--sbom`, `--sbomqs`, `--link-txt` or `--rootfs`, `--cpe-exceptions`, `--own-supplier` |
| `dt-vex-upload.py` | Uploads a CycloneDX VEX to Dependency-Track and checks every statement (above). Standard library only; `DT_API_KEY` or `DT_BEARER` |
| `dt-health-check.py`, `health/dt-health.json`, `health/dt-health-canary.cdx.json` | The daily data health check, its configuration and the canary SBOM (above). Standard library only. `templates/dt-health.cronjob.yaml` (recommended) or `templates/dt-health.github-workflow.yml` schedules it |
| `../generators/openvex-to-cdx-vex.py` | OpenVEX (for example from Yocto's `sbom-cve-check`) to CycloneDX VEX, with the VEX policy checks |
| `install-sbomqs.sh` | Installs sbomqs 2.1.3 and checks it against the release checksum |
| `sign-sbom.sh`, `verify-sbom.sh` | Sign with SignPath, and check a signature with its timestamp |
| `github/action.yml` | GitHub composite action. Run it in the build job, right after the build. `templates/github-workflow-example.yml` shows a full workflow |
| `templates/sbom.gitlab-ci.yml` | GitLab include. Add `!reference [.sbom-release, script]` to the build job |
| `templates/SbomRelease.kt` | TeamCity Kotlin DSL template. Attach it to the build configuration |

## Settings

| Variable | Secret | Needed for |
|---|---|---|
| `ARTIFACT_BASE_URL` | no | The SBOM's download links (`<base>/<product>/<version>/<file>`). Upload the binaries to the same path |
| `SOURCE_URL` | no | The product's repository URL (CMake). Each template sets it from the CI system |
| `SIGN_SBOM` | no | `true` on release builds only |
| `SIGNPATH_ORGANIZATION_ID`, `SIGNPATH_PROJECT_SLUG`, `SIGNPATH_SIGNING_POLICY_SLUG` | no | Signing |
| `SIGNPATH_API_TOKEN` | **yes** | Signing (SignPath CI user) |
| `PKCS11_MODULE_PATH`, `SIGNING_CERT_PEM` | no | Signing. The agent needs OpenSSL 3 with libp11 and the SignPath Cryptoki provider |
| `TSA_URL` | no | The timestamp. With hash-based signing, timestamping is our job ([SignPath: Timestamps](https://docs.signpath.io/crypto-providers#timestamps)) |
| `DT_URL`, `DT_API_KEY` | key: **yes** | Uploading to Dependency-Track |
| `JF_TARGET` | no | Uploading to Artifactory with the JFrog CLI |
| `SBOM_CPE_EXCEPTIONS` | no | Path to the file of third-party components allowed without a CPE (optional) |
| `OPENVEX_FILE`, `VEX_FILE` | no | The release's VEX, as OpenVEX (converted first) or CycloneDX (optional) |
| `VEX_FAIL_ON_PENDING` | no | `true` to fail when a VEX statement can't be applied yet (optional) |

## Verify a signed SBOM

```
verify-sbom.sh sensorhub-fw-3.1.0.cdx.json signpath-ca-chain.pem tsa-ca-chain.pem
```

The SBOM manager should run this when an SBOM arrives, before importing it.

## Tested

- Both sample products pass the gate (BSI v2.1 required fields 10, NTIA 10).
- These cases fail it, as they should: the Syft SBOM with no components; the firmware SBOM with OpenSSL removed; the CMake SBOM with the SHA-512 hashes removed.
- Identifier check (gate 1.1), on the firmware SBOM: these fail, as they should: cJSON's CPE removed; zlib's CPE version changed to 1.2.13; OpenSSL's CPE version set to `*`; glibc's CPE in the old 2.2 form; an exception without a reason. These pass: a wildcard vendor (with a warning); distro version suffixes; cJSON without a CPE when the exceptions file lists it (with warnings for the used and the unused exception).
- VEX upload (`tests/test_vex_gap1.py`, 47 checks, against `tests/mock_dt.py`, a stand-in for the DT 5.2.1 API written from its source):
  - It reproduces the problem: a VEX sent right after the BOM is skipped and the upload still reports success.
  - With the tool, the found CVEs are `APPLIED`, a known CVE without a finding is `STORED`, and an unknown CVE is `PENDING_UNKNOWN_VULN`.
  - These fail the build: a statement DT didn't apply, an older analysis with the same state but other details, a component missing from the project (also when the project has no findings), and a VEX without statements.
  - DT's source fallback and findings open under an alias are detected. `--pending-from` re-applies only pending statements and leaves later triage alone.
  - Paging past 100 components works with DT's unstable default sort; without the `sortName` fix the test fails.
  - The converter handles `sbom-cve-check`'s product shape, subcomponents, the root, repeated statements and nested components, and its output validates as CycloneDX 1.6.
  - `sbom-release.sh firmware` was run end to end with `OPENVEX_FILE`: with DT, without DT (fails), with `VEX_FAIL_ON_PENDING` and with a policy breach.
  - An independent review found 3 blocking and 9 other issues; all are fixed and covered by these tests.
  - The real-DT check is `vex-verify.cmd` in the test repository.
- Data health (`tests/test_health_gap2.py`, 70 checks, against `tests/mock_dt.py`, which also copies DT 5.2.1's extensions, mirror runs, notification rules, projects, the reconciliation of analyzer results, and a `FAILED` token when every analyzer fails):
  - It detects:
    - a `FAILED`, stale, missing or stuck mirror run, including a `PENDING` one through `--state`;
    - a disabled required analyzer;
    - the NVD source switched back to NIST;
    - a failing Trivy or internal analyzer, and every analyzer failing;
    - a revoked OSS Index token (through the live test, while cached findings still look fine), and a test DT refuses;
    - an adapter that reports problems, answers without reasons, or doesn't answer;
    - enriched CVEs without CPEs in DT;
    - a portfolio whose re-analysis stopped;
    - an old Trivy database;
    - analysis falling behind;
    - a missing or disabled DT alert rule;
    - `ANALYZER` alerts sent to chat.
  - Without rotation, a failing analyzer is hidden by its old findings. This is why rotation is the default.
  - It runs with the 5-permission key and with `DT_BEARER`. A key that is rejected, lacks a permission, or is redirected never gives a pass.
  - API calls are the same for 5,000 and 10,000 projects, and stay within 80.
  - Mutation tests:
    - Two review rounds and our own runs removed or bent each check in turn, and the suite failed for each one.
    - That covers every check above, including: reading the total, skipping just-uploaded and collection projects, counting never-analysed projects, the stuck-run signature, the empty-sample warning, the candidates trend, the timeout branch, the poll counter, the concurrency warning and the alert filter.
    - One mutation is not covered by a test. If the adapter's `building` flag ignores the queue, nothing fails, because there is only a brief window to catch it in. The code reads the pass counters, so there is no such window.
  - The real-DT check is `dt-health-verify.cmd` in the test repository. It injects six real faults and restores each one, and checks DT's own alert end to end. It also runs the check during a burst of 150 uploads, which must all be accepted and analysed, with the call budget checked without the polls.
- Signing and verification were tested with a throwaway software key. A single changed character in the SBOM fails verification. The SignPath route itself (engine `pkcs11`) isn't tested here and needs a SignPath project and CI user.
- The GitHub workflows pass actionlint 1.7.7 (`dt-health` with its `dt-network` runner label declared). The CronJob template was only checked as YAML, not deployed. The GitLab template and the TeamCity DSL were only checked for syntax, not run in those systems.
