# C++ SBOM samples: CMake-only product and firmware image

This folder has two sample C++ products and eight SBOMs made from them. Each SBOM was made a different way. The goal is to show what each method finds, and how each SBOM scores against **BSI TR-03183-2 v2.1** and the **NTIA minimum elements (2026)**. Scores come from sbomqs v2.1.3.

The sample code uses old third-party versions on purpose. They have known CVEs, so you can use the SBOMs to test vulnerability matching in Dependency-Track.

## The two samples

| Sample | What it is | Third-party content (the ground truth) |
|---|---|---|
| **sensorhub-gateway 2.4.0** (`inputs/cmake-product`) | A C++17 application built with CMake only, with no Conan or vcpkg. Everything is statically linked. | Fetched with FetchContent: fmt 8.0.0, nlohmann/json 3.9.1, libexpat 2.4.1. Copied into `third_party/`: zlib 1.2.11, cJSON 1.7.10 |
| **sensorhub-fw 3.1.0** (`inputs/firmware/sensorhub-fw-3.1.0.bin`) | A 4 MiB image in a vendor format: a 64-byte `SNFW` header, then a squashfs rootfs, padded with 0xFF | busybox 1.33.1 (static), zlib 1.2.11 (.so), OpenSSL 1.1.1k (libcrypto, libssl), glibc 2.39, and the `sensord` 3.1.0 app, which links cJSON 1.7.10 and libexpat 2.4.1 statically. The opkg package database lists only busybox and zlib, as stripped vendor images often do |

## Results

| SBOM (`sboms/`) | How it was made | Components | Third-party found (version + CPE/PURL) | BSI v2.1 required | NTIA 2026 | sbomqs score |
|---|---|---|---|---|---|---|
| `cmake-build-derived` | `cmake-sbom.py`: FetchContent checkouts plus the declared `third_party/MANIFEST.json` | 5 | **5 / 5** | **10.0** | **10.0** | 9.4 (A) |
| `cmake-syft-source` | Syft 1.33.0 on the source tree | 0 | 0 / 5 | 3.75 | 4.38 | 3.0 (F) |
| `cmake-syft-binary` | Syft 1.33.0 on the built binary | 0 | 0 / 5 | 3.75 | 4.38 | 3.0 (F) |
| `cmake-cdxgen` | cdxgen on the source tree | 185 | 0 / 5 (header names without versions; the rest are build-host packages) | 2.09 | 3.01 | 4.7 (F) |
| `fw-build-manifest` | `fw-sbom.py`: the build manifest, checked against the built rootfs | 8 | **6 / 6** | **10.0** | **10.0** | 9.3 (A) |
| `fw-cvebintool` | cve-bin-tool 3.4 binary signature scan of the extracted rootfs | 5 | 4 / 6 (**misses OpenSSL** and cJSON; lists zlib twice under different vendors) | 4.32 | 5.29 | 5.6 (D) |
| `fw-syft-extracted` | Syft on the extracted rootfs | 6 | 2 / 6 (busybox and zlib, found only through the opkg database) | 2.89 | 4.31 | 4.8 (F) |
| `fw-syft-packed` | Syft on the packed image | 0 | 0 / 6 | 4.38 | 5.00 | 3.4 (F) |

The full sbomqs reports are in `scores/`. All eight files pass CycloneDX JSON schema validation.

> An empty SBOM still scores 3 to 5, because the document-level fields pass. A CI gate should therefore compare the component count with what the build linked, and not rely on the score alone.

## What this shows

1. **For a CMake-only C++ product, scanners have nothing to read.** There is no lockfile and no package-manager metadata. Static linking leaves no package metadata in the binary either. Only the build knows what went in. So the SBOM has to come from the build: from FetchContent and the vendored-code manifest, as here, or from Conan, which the plan already standardises on.
2. **For firmware, scanning finds only part of the content.** Syft can't read the packed image. After extraction, Syft finds only what the package database lists. Binary signature scanning (cve-bin-tool) finds more, but it missed OpenSSL, which carries the most CVEs in this image, and the vendored cJSON. Use binary scanning to cross-check the build SBOM, not to replace it.
3. **TR-03183-2 v2.1 needs fields that no generator adds by itself.** They were added in `tr03183.py`:
   - a SHA-512 of the deployable file, on the `distribution` reference;
   - an https URI for the deployable form, meaning your artifact repository (`file://` fails);
   - an explicit completeness statement (CycloneDX `compositions`);
   - a source-code URI, a source hash, the producer (`manufacturer`) and the tool version.
4. **The sbomqs version matters.** sbomqs v1.2.0 checks TR-03183-2 v1.1, which only accepts SHA-256. These SBOMs carry SHA-256 as well as SHA-512, so they pass both versions. Use sbomqs v2.1.3 or newer in CI.
5. **Some items can't be scored from a generator, or shouldn't be.**
   - The SBOM signature belongs in CI signing, which matches the "integrity enforced in CI" decision.
   - BOM links aren't scored.
   - Effective licence isn't scored, because sbomqs reads it only from SPDX 3.
   - security.txt is filled in only for your own components. It isn't made up for upstream projects.

## Using this in CI

`ci/` turns the generators into a release gate that runs the same way in GitHub Actions, GitLab CI and TeamCity. The steps are generate, then gate (sbomqs, a coverage check and a check that every third-party component has a usable CPE), then sign with SignPath on release builds, then publish. See `ci/README.md`.

The coverage check is there because of one result. When OpenSSL was removed from the firmware SBOM, the SBOM still scored 10 out of 10 on BSI and NTIA. Only the check that every ELF file in the image is listed caught it.

`ci/dt-health-check.py` watches the other half: that Dependency-Track's vulnerability data is still current and still reaches the findings. It checks the mirror runs, the NVD feed adapter's `/health`, and a canary project with one component per analyzer. See "Watch the data" in `ci/README.md`.

## Other converters

- `generators/vcpkg-spdx-to-cdx.py`: vcpkg's per-port SPDX files to one CycloneDX 1.6 SBOM, because Dependency-Track accepts only CycloneDX. It keeps one component per port, with `pkg:conan` identifier, CPE, licence and source SHA-512. Generic converters lose either the package URL or the hashes.
- `generators/openvex-to-cdx-vex.py`: OpenVEX (for example from Yocto's `sbom-cve-check --export-type openvex`) to a CycloneDX VEX for Dependency-Track's `PUT /api/v1/vex`. `vex/` has a worked example; its statuses are examples, not an assessment. Upload the result with `ci/dt-vex-upload.py`, which waits for DT's analysis and checks every statement (see `ci/README.md`); DT 5.2.1 silently drops a VEX that arrives before the analysis.

## Comparing SBOM managers

`compare/` has the ground truth for both samples (`expected-components.json`). Its script scores any tool's export against that list, and against the CVEs Dependency-Track finds: Manifest Cyber, Sonar, or Dependency-Track itself. See `compare/README.md`. `cpp-sboms-dt-test.cmd`, in the folder above, loads all eight SBOMs into the local Dependency-Track test stack.

## Dependency-Track results (26 Nov 2026)

`cpp-sboms-dt-test.cmd`, in the folder above, loaded the SBOMs into Dependency-Track 5.2.1. Three analyzers were on: NVD with the VulnCheck NVD++ adapter, OSS Index and Trivy. The results are in `../cpp-sboms-dt-results.json`, and the CycloneDX that Dependency-Track exports again is in `dt-exports/`.

| SBOM | CVEs found | Missed compared with the complete SBOM |
|---|---|---|
| `fw-build-manifest` (complete) | 160: OpenSSL 49, expat 56, glibc 31, busybox 19, zlib 4, cJSON 1 | — |
| `fw-build-manifest` with ConanCenter identifiers (`dt-variants/`) | 180 (OSS Index adds 20: OpenSSL 14, zlib 3, expat 3) | — |
| `fw-cvebintool` | 110 | 50: all of OpenSSL and cJSON |
| `fw-syft-extracted` | 23 | 137 |
| `fw-syft-packed` | 0 | all |
| `cmake-build-derived` (complete) | 61: expat 56, zlib 4, cJSON 1 | — |
| `cmake-build-derived` with ConanCenter identifiers | 67 (OSS Index adds 6) | — |
| `cmake-syft-*`, `cmake-cdxgen` | 0 | all |

What the results show:

- **Matching for C++ runs on CPEs.** Every NVD match came through the CPE in the SBOM. With `pkg:github` and `pkg:generic` identifiers, OSS Index and Trivy found nothing. With `pkg:conan` identifiers, OSS Index added 6 to 20 CVEs.
- **One CPE per component isn't always enough.** NVD files cJSON under two vendor names: `davegamble:cjson` for CVE-2019-11834 and CVE-2019-11835, and `cjson_project:cjson` for CVE-2023-53154. Dependency-Track matches one CPE per component, so it misses the 2019 CVEs. OSS Index didn't add them either. One fix would be to map vendor aliases in the NVD feed adapter.
- **glibc is overstated.** The sample uses Ubuntu's patched glibc 2.39, and NVD ranges don't know about distribution patches. Real firmware needs the build's patch status, for example Yocto `cve-check` output or a VEX file, so that fixed CVEs are closed.
- **Dependency-Track is not a faithful archive.** Its export is CycloneDX 1.5. It drops the SHA-512 on the download links, the declared and concluded licence pair, `compositions`, the lifecycle and the manufacturer. The BSI v2.1 required score falls from 10 to 7.4–7.6. So the original signed SBOM is the record, kept in Artifactory, and Dependency-Track is for analysis.
- **Results changed between runs, now fixed.** CVEs that matched in the first run were gone in the second, 13 minutes later, after the NVD adapter restarted. NIST's yearly feed had overwritten their VulnCheck CPEs. Adapter version 2 fixes this and is verified on the test stack (`../nvdpp-v2-verify-results.json`). Three were real losses, and the two that can be named, CVE-2024-8176 and CVE-2026-107496, are back. The fourth, CVE-2026-76844, was a false zlib match, since corrected upstream. With version 2 and its cJSON alias, the complete firmware SBOM shows 181 CVEs and the CMake one 73.

## Placeholders to replace before real use

- `https://artifacts.example.com/artifactory/releases/...`: set `ARTIFACT_BASE_URL` to your JFrog repository. The URL is built as `<base>/<product>/<version>/<file>`.
- Replace `git.example.com`, `https://example.com/.well-known/security.txt`, `psirt@example.com`, "Example Product Team" and "Example Device Team". For the CMake product, set `SOURCE_URL` to its repository URL.
- The **source hash** is a SHA-512 over the checked-out source tree (sorted paths and contents, with `.git` left out). Choose one method for the whole organisation, either this one or the hash of the released source archive, and write it down.
- The sample rootfs uses glibc from the Ubuntu build host (2.39-0ubuntu8.9). The SBOM records it as upstream glibc 2.39.
- `compositions` says `complete`. That is true here only because each generator fails when the build and the manifest disagree. The CMake SBOM leaves out the C/C++ runtime (libstdc++, glibc) because the target OS provides it, and the SBOM says so in a `scope-note` property.

## How to make these again

**CMake product.** The copied zlib and cJSON sources aren't included. Clone `madler/zlib` at tag `v1.2.11` into `third_party/zlib`, and `DaveGamble/cJSON` at tag `v1.7.10` into `third_party/cjson`. Then run:

```
cmake -S cmake-product -B cmake-product/build -DCMAKE_BUILD_TYPE=Release
cmake --build cmake-product/build && cmake --install cmake-product/build --prefix cmake-product/install
python3 generators/cmake-sbom.py cmake-product cmake-product/build cmake-product/install/bin/sensorhub-gateway out/cmake-build-derived.cdx.json
```

The script exits with code 1 in two cases: a FetchContent dependency has no identifier mapping (the `KNOWN` table), or a manifest version doesn't match the version in the vendored header. Either way the CI job fails.

**Firmware.** `fw-sbom.py` needs a folder that holds `rootfs/`, `rootfs.squashfs`, `app/` and the image:

```
python3 -c "import struct;d=open('sensorhub-fw-3.1.0.bin','rb').read();n=struct.unpack_from('<I',d,8)[0];open('rootfs.squashfs','wb').write(d[64:64+n])"
unsquashfs -o 64 -d rootfs sensorhub-fw-3.1.0.bin
python3 generators/fw-sbom.py build-manifest.json <fw-folder> <third-party-source-folder> out/fw-build-manifest.cdx.json
```

The script fails if a manifest entry points at a file that isn't in the rootfs, or if the binary doesn't contain the declared version string. `generators/mkfw-image.py` packs a squashfs into the sample image format, and it reproduces the included image byte for byte.

**Scoring.** Use sbomqs v2.1.3 (`sbomqs_2.1.3_Linux_x86_64.tar.gz` from the GitHub release, checked against its `checksums.txt`):

```
python3 generators/score.py ./sbomqs sboms scores.json
```

The script prints the BSI v2.1 and NTIA 2026 scores for every SBOM, and lists each required field that fails.
