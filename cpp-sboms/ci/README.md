# SBOM release gate for CI

The same four steps run in GitHub Actions, GitLab CI and TeamCity. Every CI system calls one script, `sbom-release.sh`, so the rules stay the same across the three systems.

| Step | What it does | Fails the build when |
|---|---|---|
| 1. Generate | `cmake-sbom.py` or `fw-sbom.py` builds the SBOM from what the build used | A FetchContent dependency has no identifier mapping, or a declared version doesn't match the source or the binary |
| 2. Gate | `sbom-gate.py` runs sbomqs v2.1.3 (pinned and checksum-checked) and a coverage check | Any required BSI TR-03183-2 v2.1 field scores below 10, the NTIA 2026 score is below 10, a library on the CMake link line is missing from the SBOM, or an ELF file in the firmware image isn't listed |
| 3. Sign (release builds) | `sign-sbom.sh` makes a detached CMS signature through the SignPath Cryptoki provider (hash-based), then an RFC 3161 timestamp | Signing or the timestamp fails |
| 4. Publish | Uploads the SBOM to Dependency-Track, and the SBOM, signature and gate report to Artifactory (`jf rt upload`) | An upload fails |

**Why there's a coverage check.** When OpenSSL was removed from the firmware SBOM, the SBOM still scored 10 out of 10 on both BSI and NTIA. Only the check that every ELF file in the image is listed caught it. A compliance score shows the fields are filled in. It doesn't show the list is complete.

## Files

| File | Use |
|---|---|
| `sbom-release.sh` | The entry point: `sbom-release.sh cmake <src> <build> <binary> <out>` or `sbom-release.sh firmware <manifest> <fw-dir> <src-dir> <out>` |
| `../generators/sbom-gate.py` | The gate. It can also run on its own: `--sbom`, `--sbomqs`, `--link-txt` or `--rootfs` |
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

## Verify a signed SBOM

```
verify-sbom.sh sensorhub-fw-3.1.0.cdx.json signpath-ca-chain.pem tsa-ca-chain.pem
```

The SBOM manager should run this when an SBOM arrives, before importing it.

## Tested

- Both sample products pass the gate (BSI v2.1 required fields 10, NTIA 10).
- These cases fail it, as they should: the Syft SBOM with no components; the firmware SBOM with OpenSSL removed; the CMake SBOM with the SHA-512 hashes removed.
- Signing and verification were tested with a throwaway software key. A single changed character in the SBOM fails verification. The SignPath route itself (engine `pkcs11`) isn't tested here and needs a SignPath project and CI user.
- The GitHub workflow passes actionlint 1.7.7. The GitLab template and the TeamCity DSL were only checked for syntax, not run in those systems.
