# NVD feed adapter (version 2)

The adapter sits between Dependency-Track and NIST. Dependency-Track's NVD source downloads NVD JSON 2.0 feed files from a URL you configure (`http://nvdpp:8080/feeds`). The adapter serves every feed file (2002 to the current year, plus `modified`), rebuilt from NIST's files with two changes:

1. **VulnCheck CPEs.** If NIST left a CVE without CPE configurations and VulnCheck NVD++ has them, the record gets VulnCheck's configurations. VulnCheck's community terms require attribution.
2. **CPE vendor aliases.** If NVD files one product under several vendor names, every CPE match is copied to the other names (see [Vendor aliases](#vendor-aliases)).

## Why version 2

Dependency-Track 5.2.1 (`vuln-data-source/nvd`) reads the feeds like this:

- It keeps **one watermark**: the newest `lastModified` it has ingested.
- It keeps **one sha256 per feed file**.
- It **skips a feed file** if its sha256 hasn't changed, or if the `.meta` `lastModifiedDate` isn't later than the watermark.
- Inside a file, it **skips any CVE** whose `lastModified` isn't later than the watermark.
- It reads the **yearly files newest first, and `modified` last**.

Version 1 rewrote only `modified` and passed the yearly files through from NIST. That caused two failures:

| Problem in version 1 | What happened | Version 2 |
|---|---|---|
| **Lost CPEs** | NIST updated an enriched CVE. The yearly file (NIST's record, without CPEs) overwrote Dependency-Track's copy. After a restart the old `modified` file was skipped because its sha256 hadn't changed. The re-enriched record then had the same `lastModified`, at or below the watermark, so it never came back. In the test on 26 Nov 2026, four recent CVEs disappeared this way. | Every feed that contains a CVE carries the same rewritten record. |
| **Re-delivery storm** | The record of what had been delivered lived in memory. After a restart, all 56,106 enriched CVEs got new timestamps and were ingested again. | Each rewritten CVE gets a stable `lastModified`, stored in `/cache/assigned.json`. It changes only when NIST changes the CVE or the rewrite changes (new VulnCheck data, a new alias). |
| `.meta` rounded to whole seconds | A change within the same second as the watermark could be skipped | Milliseconds are written; Dependency-Track parses them with `Instant.parse` |

New timestamps sit just above NIST's newest change and above every value handed out before, including version 1's. So Dependency-Track's watermark never runs ahead of NIST.

`tests/test_adapter.py` reproduces both failures with a fake NIST server and a client that follows Dependency-Track's rules:

```
python3 tests/test_adapter.py adapter.py --v1 <old adapter.py>
```

Version 1 loses CVE-2026-1000 during the restart window and never gets it back. Version 2 keeps it, re-ingests nothing when nothing has changed, and re-delivers exactly one CVE when an alias group is added.

## Upgrading from version 1

1. Replace `adapter.py` and add `cpe-aliases.json`. No compose change is needed, because `./nvdpp` is mounted at `/app`.
2. Run `docker compose up -d`. On first start the adapter downloads and rewrites every NIST yearly file, which takes about 10–30 minutes. Until a file is ready, the adapter answers 503 for it, rather than handing out unenriched NIST data. Dependency-Track retries on its next mirror run.
3. Values that version 1 delivered are carried over (`migrated_from_v1` in `/stats`), so there's no re-delivery storm. Only CVEs that NIST changed since then, and CVEs that gain an alias, are delivered again.
4. `nvdpp-v2-verify.cmd` runs this on the test stack and reports the result.

## Vendor aliases

**Why they're needed.** Dependency-Track's internal analyzer compares a component's CPE vendor and product exactly with each CVE's CPE matches (`CpeFilterCondition` in `vuln-analysis/internal`). NVD isn't consistent. cJSON is `davegamble:cjson` in CVE-2019-11834 and CVE-2019-11835, but `cjson_project:cjson` in CVE-2023-53154. A component with one of these CPEs misses the CVEs filed under the other. In the test, cJSON 1.7.10 showed 1 CVE instead of 3.

**What the adapter does.** `cpe-aliases.json` lists groups of `vendor:product` names that are the same software. In every record it serves, the adapter copies each CPE match on one name to the other names in its group, with the same version range. The rest of the record stays as it is. Changed CVEs get a new stable `lastModified`, so Dependency-Track ingests them once.

```json
{
  "aliases": [
    {"same": ["cjson_project:cjson", "davegamble:cjson"],
     "note": "cJSON. 2019 CVEs use davegamble, later ones cjson_project."}
  ]
}
```

**How to add an alias**

1. Find candidates. Open `http://localhost:8090/aliases/suggest`. It lists C/C++ products from the adapter's list that NVD files under more than one vendor and that the file doesn't cover yet. You can also add any `vendor:product` pair you've seen in the NVD CPE dictionary.
2. Check each candidate before adding it. Look up a CVE of each name in NVD and confirm it's the same project. A product name can belong to different software; `json`, for example, is used by several unrelated vendors.
3. Add a group to `cpe-aliases.json`, with a `note` that says why and gives an example CVE. The names are lower case, `vendor:product` only.
4. Open `http://localhost:8090/rebuild` or restart the adapter. Only the feeds that contain affected CVEs change. Then run Dependency-Track's NVD mirror, or wait for its schedule.
5. Check the result. `http://localhost:8090/aliases` shows the loaded groups, and `/stats` shows `aliased_cves` per feed. In Dependency-Track, the component should now list the CVEs from both names.

**Quick alternative without the adapter.** A component CPE with a wildcard vendor, such as `cpe:2.3:a:*:cjson:1.7.10:*:*:*:*:*:*:*`, matches every vendor, because Dependency-Track treats target `ANY` as a superset. Use this only for distinctive product names. For generic names (`json`, `parser`, `client`) it produces false positives.

## Endpoints

| Path | What it returns |
|---|---|
| `/feeds/json/cve/2.0/nvdcve-2.0-<year\|modified>.meta` and `.json.gz` | The rebuilt feeds, for Dependency-Track |
| `/stats` | Build state, per-feed counts (`enriched`, `aliased_cves`), and `assigned_new`, `assigned_kept`, `migrated_from_v1` |
| `/rebuild`, `/rebuild?wait=1`, `/rebuild?all=1`, `/rebuild?vc=1` | Rebuild changed feeds; wait for it; rebuild everything; also reload VulnCheck |
| `/aliases`, `/aliases/suggest` | Loaded alias groups; alias candidates |
| `/examples`, `/candidate-ids`, `/healthz` | As in version 1 |

## Settings (environment)

| Variable | Default | Meaning |
|---|---|---|
| `VULNCHECK_TOKEN` | — | VulnCheck community token. Without it, only aliases are applied |
| `CPE_ALIASES_FILE` | `cpe-aliases.json` next to `adapter.py` | Alias groups |
| `FEED_MAX_AGE_MIN` | 60 | Minutes between rebuild checks |
| `VC_MAX_AGE_HOURS` | 24 | When to reload VulnCheck data |
| `FIRST_YEAR` | 2002 | First yearly feed |
| `CACHE_DIR` | `/cache` | Feeds, `assigned.json` and VulnCheck data. Keep this volume |
| `NIST_FEEDS_URL` | `https://nvd.nist.gov/feeds` | Source feeds |

Disk: the cache holds a rewritten copy of every NVD feed, roughly the size of NIST's compressed feeds, plus the VulnCheck digest.
