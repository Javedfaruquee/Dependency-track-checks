# Comparing SBOM managers on the same samples

Use the eight SBOMs in `../sboms` to compare Dependency-Track, Manifest Cyber and Sonar on the same inputs. `expected-components.json` lists what is really inside each sample. `compare-findings.py` scores any tool's export against that list, and against the CVEs Dependency-Track found on the complete SBOM.

1. **Load the SBOMs.** Upload at least `cmake-build-derived` and `fw-build-manifest`, plus one scanner-made SBOM (for example `fw-cvebintool`), so you can see how each tool handles an incomplete input.
   - **Manifest Cyber:** upload through the UI or the API.
   - **Sonar:** use the imported-SBOM analysis (beta in December 2025).
2. **Export the results** as CycloneDX with vulnerabilities (VEX or VDR), or as CSV with a component column, a version column and a CVE column.
3. **Score them:**

```
python3 compare-findings.py --expected expected-components.json \
  --product "sensorhub-fw 3.1.0 (firmware)" --findings manifest-fw-export.json \
  --reference ../../cpp-sboms-dt-results.json --reference-project cpp-sbom-fw-build-manifest
```

The table shows, for each component: whether the tool listed it, whether the version matches, how many CVEs it reported, and which CVEs Dependency-Track found that this tool didn't.

Also check whether each tool keeps the BSI TR-03183-2 fields when it exports the SBOM again (SHA-512 hashes, links, licences, supplier). For Dependency-Track this is in `../dt-exports`.
