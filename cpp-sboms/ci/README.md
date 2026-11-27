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

## Files

| File | Use |
|---|---|
| `sbom-release.sh` | The entry point: `sbom-release.sh cmake <src> <build> <binary> <out>` or `sbom-release.sh firmware <manifest> <fw-dir> <src-dir> <out>` |
| `../generators/sbom-gate.py` | The gate. It can also run on its own: `--sbom`, `--sbomqs`, `--link-txt` or `--rootfs`, `--cpe-exceptions`, `--own-supplier` |
| `dt-vex-upload.py` | Uploads a CycloneDX VEX to Dependency-Track and checks every statement (above). Standard library only; `DT_API_KEY` or `DT_BEARER` |
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
- VEX upload (`tests/test_vex_gap1.py`, 42 checks, against `tests/mock_dt.py`, a stand-in for the DT 5.2.1 API written from its source):
  - It reproduces the problem: a VEX sent right after the BOM is skipped and the upload still reports success.
  - With the tool, the found CVEs are `APPLIED`, a known CVE without a finding is `STORED`, and an unknown CVE is `PENDING_UNKNOWN_VULN`.
  - These fail the build: a statement DT didn't apply, an older analysis with the same state but other details, a component missing from the project (also when the project has no findings), and a VEX without statements.
  - DT's source fallback and findings open under an alias are detected. `--pending-from` re-applies only pending statements and leaves later triage alone.
  - Paging past 100 components works with DT's unstable default sort; without the `sortName` fix the test fails.
  - The converter handles `sbom-cve-check`'s product shape, subcomponents, the root, repeated statements and nested components, and its output validates as CycloneDX 1.6.
  - `sbom-release.sh firmware` was run end to end with `OPENVEX_FILE`: with DT, without DT (fails), with `VEX_FAIL_ON_PENDING` and with a policy breach.
  - An independent review found 3 blocking and 9 other issues; all are fixed and covered by these tests.
  - The real-DT check is `vex-verify.cmd` in the test repository.
- Signing and verification were tested with a throwaway software key. A single changed character in the SBOM fails verification. The SignPath route itself (engine `pkcs11`) isn't tested here and needs a SignPath project and CI user.
- The GitHub workflow passes actionlint 1.7.7. The GitLab template and the TeamCity DSL were only checked for syntax, not run in those systems.
