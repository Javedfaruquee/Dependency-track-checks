# NVD feed adapter (version 2.2)

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
- **Dependency-Track 5.2.2 only:** while the watermark is less than 6 days old, it **skips the yearly files** and reads only `modified` (see [Version 2.2](#version-22-for-dependency-track-522)).

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

## Version 2.2: for Dependency-Track 5.2.2

Dependency-Track 5.2.2 (released 18 Nov 2026) reads only `modified` on its daily mirrors: while its watermark is less than 6 days old it skips every yearly file (`MODIFIED_FEED_COVERAGE` in `NvdVulnDataSource`). NIST's `modified` file covers the last 8 days of NIST's changes.

That broke one case in version 2.1. When VulnCheck adds CPEs to an older CVE that NIST hasn't touched recently, or an alias group changes, the CVE gets a new `lastModified`, but it is in no NIST `modified` file. Version 2.1 put the rewritten record only into the CVE's yearly file, which 5.2.2 no longer reads, so the new CPEs never reached Dependency-Track. The health check's VulnCheck sample would have reported it, but only some time later.

Version 2.2 also puts every rewritten CVE whose `lastModified` is less than `MODIFIED_EXTRA_DAYS` (8) days older than NIST's newest change into `modified`. It copies the record from its own yearly file, so nothing extra is downloaded, and the record is identical in both files. `/stats` shows how many records were copied (`recent_rewrites`). Dependency-Track 5.2.1 reads both copies, as it already did for CVEs that are in NIST's yearly and `modified` files.

Upgrading from 2.1 rebuilds only `modified` (its cache key now includes the copied CVEs). The yearly files and the VulnCheck backup are kept.

**Upgrade the adapter first.** Start 2.2 and wait until `/stats` shows `recent_rewrites` for `modified` (it is then built by 2.2). Only then start Dependency-Track 5.2.2. If DT 5.2.2 mirrors while 2.1 still serves the feeds, its watermark moves past any rewrite 2.1 made of an older CVE, and 2.2 cannot bring it back. For the same reason, never roll the adapter back to 2.1 while DT runs 5.2.2. Adapter 2.2 works with DT 5.2.1, so you can keep it on a DT rollback. `dt-health-verify.ps1` follows this order.

**If the order went wrong:** stop the adapter, move `assigned.json` and `delivered.json` (in the cache volume) aside, keep `issued.json`, and start it again. Every rewritten CVE then gets a new `lastModified` above everything served before. This is a one-time re-delivery of all of them (56,106 on the test stack), all within the window, so they are copied into `modified` too.

Version 2.2 also fixes two older ways a rewrite could arrive below DT's watermark:
- **A drop-guarded feed accepted later.** The guard stops a yearly file after its rewrites were given new values, and those values were kept for the accepted rebuild, by then below DT's watermark. Now a value that was issued but never served (its feed was not written) is replaced by a fresh one. `served` counts a value only if the record went out with exactly that `lastModified`.
- **A stale `.meta` from NIST.** New values were floored by NIST's `.meta` and by the values handed out before. Now they are also floored by the newest `lastModified` in any feed served (empty feeds aside).

`assigned.json` now also records the yearly file each rewritten CVE is in, so `modified` copies it from there. Older entries fall back to the CVE's ID year, which is where NVD files them. `/stats` shows `recent_not_copied` for `modified`: the recently rewritten CVEs that could not be copied, for example while their yearly file is held back by the drop guard.

`tests/test_adapter.py` has a client for 5.2.2's rules: version 2.1 fails its 5.2.2 scenario (CVE-2021-3000 never gets VulnCheck's zlib CPE), and version 2.2 passes it.

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
| `GET /rebuild`, `GET /rebuild?wait=1` | Queue a refresh of changed feeds; wait for it. Requests made while a build runs are queued for the next one (version 2.1), never dropped |
| `POST /rebuild?all=1`, `?vc=1`, `?vc=1&accept_vc_drop=1`, `?accept_feed_drop=1`, plus `&wait=1` | Rebuild everything; reload VulnCheck; accept data the drop guard stopped. **Version 2.1:** these need POST with the header `X-NVDPP-Rebuild: 1`, so a web page can't trigger them through `localhost` |
| `/aliases`, `/aliases/suggest` | Loaded alias groups; alias candidates |
| `/health` | **Version 2.1.** 200 when the served data is fresh, 503 with the reasons when it isn't (see [Health](#health-version-21)) |
| `/candidates/sample?served_before=<epoch ms>&n=20` | **Version 2.1.** Enriched CVEs the adapter first published before that time (wall clock, kept in `assigned.json`, set when a feed carrying the record is written), for `ci/dt-health-check.py` to confirm in Dependency-Track |
| `/examples`, `/candidate-ids` | As in version 1 |
| `/healthz` | Liveness only: "ok" while the process runs, whatever the data. Use `/health` for monitoring |

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
| `NIST_MAX_AGE_HOURS` | 6 | `/health`: the last good refresh from NIST may be this old |
| `NIST_QUIET_HOURS` | 48 | `/health`: NIST's newest CVE change may be this old (NIST stalled) |
| `VC_STALE_HOURS` | 48 | `/health`: the VulnCheck data may be this old |
| `VULNCHECK_REQUIRED` | 1 | `/health`: a missing `VULNCHECK_TOKEN` is a problem (0: only a warning) |
| `VC_DROP_PCT`, `FEED_DROP_PCT` | 1, 1 | Drop guards: a VulnCheck backup with this % fewer records or CVEs with CPEs, or a NIST yearly file with this % fewer CVEs, is not used |
| `VC_CANDIDATE_DROP_PCT` | 10 | Drop guard on enriched CVEs (NIST enriches some every day, so the limit is wider) |
| `FEED_STALE_HOURS` | 72 | `/health`: a feed that could not be checked against NIST for this long is a problem (its CVEs stop getting VulnCheck and alias updates) |
| `MODIFIED_EXTRA_DAYS` | 8 | Version 2.2: rewritten CVEs whose `lastModified` is less than this many days older than NIST's newest change also go into `modified` (Dependency-Track 5.2.2 reads only that file while its watermark is under 6 days old) |
| `REBUILD_HOSTS` | `localhost,127.0.0.1,::1,nvdpp` | Host names `POST /rebuild` accepts (against DNS rebinding). Add the adapter's service name if it differs |

Disk: the cache holds a rewritten copy of every NVD feed, roughly the size of NIST's compressed feeds, plus the VulnCheck digest.

## Health (version 2.1)

Version 2 answered `/healthz` with "ok" whatever happened. If NIST or VulnCheck failed, it kept serving the last data, and Dependency-Track's NVD mirror still reported `COMPLETED`, so nobody noticed. Version 2.1 adds `/health`. It answers **200** when the data is fresh. Otherwise it answers **503** and lists the problems:

| Problem | Reported |
|---|---|
| Feed files missing (cold cache); Dependency-Track's mirror fails on them | at once |
| NIST refresh failing with HTTP 4xx (URL removed), except 403 (NIST's CDN rate-limiting) | at once |
| NIST refresh failing with a network error, 403 or 5xx | as a warning, and as a problem once the last good refresh is older than `NIST_MAX_AGE_HOURS` |
| One yearly file failing | at once for 4xx, otherwise after `FEED_STALE_HOURS`; the other feeds, and `modified` above all, are still refreshed |
| NIST's newest CVE change older than `NIST_QUIET_HOURS` | at once |
| VulnCheck token rejected (401/403), or `VULNCHECK_TOKEN` unset | at once: every refresh (hourly, and at start) checks the token |
| VulnCheck data with no enriched CVEs at all (a format change) | at once |
| VulnCheck unreachable | as a warning, and as a problem once the data is older than `VC_STALE_HOURS` |
| Drop guard stopped new data | at once, until accepted |

The adapter keeps this state in `/cache/health.json`, so a restart doesn't hide a failure. Every refresh checks the token with VulnCheck's small metadata call; it doesn't download the backup again while the data is fresh. A fixed token clears the problem within the hour, or at once with `/rebuild`.

**Drop guards.** NIST's yearly files only grow, because rejected CVEs stay in them. VulnCheck's record count also only grows. A much smaller file therefore means a broken download or a broken source. Serving it would remove CPEs from Dependency-Track. The adapter keeps the previous data instead and reports the stop. The same applies when the number of enriched CVEs falls by more than 10%, for example after a format change. To accept the new data after checking it:

- VulnCheck: `curl -X POST -H 'X-NVDPP-Rebuild: 1' 'http://localhost:8090/rebuild?vc=1&accept_vc_drop=1&wait=1'`. The downloaded backup and its checksum are kept for this, so nothing is downloaded or hashed again.
- NIST yearly file: the same with `accept_feed_drop=1`.

**Year change.** From 1 January, Dependency-Track asks for the new year's file. Until NIST publishes it and the adapter has built it, `/health` reports it missing and DT's NVD mirror fails on it. That is expected for the first hours of the year.

`tests/test_health.py` (42 checks) injects each fault against a fake NIST and a fake VulnCheck API, including a restart with a rejected token, a forced reload requested during a running build, a cold cache and a failing yearly file. It checks that `/health` turns 503 with the right reason, that the feeds Dependency-Track gets stay as they were, and that `/health` returns to 200 once the fault is gone:

```
python3 tests/test_health.py adapter.py
```

Dependency-Track's side (mirror runs, analyzers, whether the CPEs reach the findings) is checked by `cpp-sboms/ci/dt-health-check.py`, which also reads `/health`.

