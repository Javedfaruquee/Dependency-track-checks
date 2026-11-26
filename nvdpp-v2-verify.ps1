# NVD feed adapter v2 on the real stack: start it, wait until every feed is rebuilt (VulnCheck CPEs and
# cpe-aliases.json applied), run Dependency-Track's NVD mirror, re-analyse the cpp-sbom-* projects and
# collect the findings. Shows whether cJSON's 2019 CVEs and the CVEs lost under v1 now match, and how
# many CVEs DT re-ingested. Results: nvdpp-v2-verify-results.json. Containers are stopped at the end.

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$Dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Log = Join-Path $Dir 'nvdpp-v2-verify-log.txt'
$Api = 'http://localhost:8081'
$Adapter = 'http://localhost:8090'
$NewPw = 'DtTest-2026!'

function Log([string]$m) { $l = "$(Get-Date -Format 'HH:mm:ss') $m"; Write-Host $l; Add-Content -Path $Log -Value $l -Encoding UTF8 }
function Status([string]$s) { @{ stage = $s; time = (Get-Date).ToString('s') } | ConvertTo-Json | Set-Content -Path (Join-Path $Dir 'nvdpp-v2-verify-status.json') -Encoding UTF8 }
function ErrText($e) { $t = $e.Exception.Message; if ($e.ErrorDetails -and $e.ErrorDetails.Message) { $t += ' | ' + $e.ErrorDetails.Message }; return $t }
function J($o) { return ($o | ConvertTo-Json -Depth 10 -Compress) }
function Items($x) { $o = New-Object System.Collections.ArrayList; foreach ($i in @($x)) { if ($i -is [System.Array]) { foreach ($j in $i) { [void]$o.Add($j) } } elseif ($null -ne $i) { [void]$o.Add($i) } }; return ,$o.ToArray() }

Set-Content -Path $Log -Value "NVD adapter v2 verification started $(Get-Date -Format s)" -Encoding UTF8
Status 'starting'
docker compose -f (Join-Path $Dir 'compose.yaml') up -d 2>&1 | ForEach-Object { Log "compose: $_" }
$up = $false
for ($i = 0; $i -lt 60; $i++) { try { $ver = Invoke-RestMethod -Uri "$Api/api/version" -TimeoutSec 5; $up = $true; break } catch { Start-Sleep 5 } }
if (-not $up) { Log 'FAILED: API server did not come up'; Status 'failed-api'; exit 1 }

# ---------- 1. wait for the adapter to rebuild every feed ----------
Status 'adapter-build'
$t0 = Get-Date; $last = ''; $ready = $false
while (((Get-Date) - $t0).TotalMinutes -lt 90) {
    try { $s = Invoke-RestMethod -Uri "$Adapter/stats" -TimeoutSec 20
          $line = "phase=$($s.phase) feeds=$(@($s.feeds.PSObject.Properties).Count) vulncheck=$($s.vulncheck.status) build=$($s.modified_feed.built_at)"
          if ($line -ne $last) { Log "adapter: $line"; $last = $line }
          if ($s.phase -eq 'ready' -and $s.modified_feed.built_at -and @($s.feeds.PSObject.Properties).Count -ge 26) { $ready = $true; break } }
    catch { Log "adapter stats: $(ErrText $_)" }
    Start-Sleep 30
}
if (-not $ready) { Log 'FAILED: adapter did not finish building the feeds in 90 minutes'; Status 'failed-adapter'; exit 1 }
$adapterStats = Invoke-RestMethod -Uri "$Adapter/stats" -TimeoutSec 20
Log "adapter build: $(J $adapterStats.modified_feed)"
try { $al = Invoke-RestMethod -Uri "$Adapter/aliases" -TimeoutSec 20; Log "aliases: $(J $al.map)" } catch { }
try { $sug = Invoke-RestMethod -Uri "$Adapter/aliases/suggest" -TimeoutSec 60; $sug | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $Dir 'nvdpp-alias-suggestions.json') -Encoding UTF8; Log "alias suggestions saved: $(@($sug.products.PSObject.Properties).Count) products" } catch { Log "aliases/suggest: $(ErrText $_)" }

# ---------- 2. log in ----------
Status 'login'
$tok = $null
foreach ($p in @($NewPw, 'admin')) { try { $tok = Invoke-RestMethod -Method Post -Uri "$Api/api/v1/user/login" -ContentType 'application/x-www-form-urlencoded' -Body @{ username = 'admin'; password = $p }; if ($tok) { break } } catch { } }
if (-not $tok) { Log 'FAILED: could not log in'; Status 'failed-login'; exit 1 }
$script:H = @{ Authorization = "Bearer $tok" }
function Api([string]$method, [string]$path, $body = $null) {
    $req = @{ Method = $method; Uri = "$Api$path"; Headers = $script:H; TimeoutSec = 120 }
    if ($null -ne $body) { $req.Body = [Text.Encoding]::UTF8.GetBytes((J $body)); $req.ContentType = 'application/json' }
    return Invoke-RestMethod @req
}
function Paged([string]$path) {
    $all = New-Object System.Collections.ArrayList; $seen = @{}; $sep = '?'; if ($path.Contains('?')) { $sep = '&' }
    for ($pg = 1; $pg -le 200; $pg++) {
        $r = Items (Api 'GET' "$path$($sep)pageSize=100&pageNumber=$pg"); $new = 0
        foreach ($x in $r) { $k = J $x; if (-not $seen.ContainsKey($k)) { $seen[$k] = 1; [void]$all.Add($x); $new++ } }
        if ($r.Count -lt 100 -or $new -eq 0) { break }
    }
    return ,$all.ToArray()
}

# ---------- 3. NVD mirror through the adapter ----------
Status 'mirror-nvd'
$since = Get-Date
$prev = $null; try { $prev = (Api 'GET' '/api/v2/vuln-data-sources/nvd/mirror-runs/latest').started_at } catch { }
try { Api 'POST' '/api/v2/vuln-data-sources/nvd/mirror-runs' | Out-Null; Log 'NVD mirror triggered' } catch { Log "NVD trigger: $(ErrText $_)" }
$run = $null; $deadline = (Get-Date).AddMinutes(120); $lastS = ''
while ((Get-Date) -lt $deadline) {
    Start-Sleep 20
    try { $run = Api 'GET' '/api/v2/vuln-data-sources/nvd/mirror-runs/latest'; $s = J $run
          if ($s -ne $lastS) { Log "nvd mirror: $s"; $lastS = $s }
          if ("$($run.started_at)" -ne "$prev" -and "$($run.status)" -match '(?i)complet|fail|error|cancel') { break } } catch { Log "mirror status: $(ErrText $_)" }
}
$mins = [int][Math]::Ceiling(((Get-Date) - $since).TotalMinutes) + 1
$feedLines = @(docker logs --since "$($mins)m" dt5-test-apiserver-1 2>&1 | Where-Object { "$_" -match 'Finished nvd|Skipping nvd|Skipping .*Digest|Skipping .*watermark|consumed .* CVE' } | ForEach-Object { "$_".Trim() })
$feedLines | Select-Object -Last 40 | ForEach-Object { Log "apiserver: $_" }

# ---------- 4. re-analyse and collect ----------
Status 'analyse'
$projects = @((Paged '/api/v1/project') | Where-Object { $_.name -like 'cpp-sbom-*' })
foreach ($p in $projects) { try { Api 'POST' "/api/v1/finding/project/$($p.uuid)/analyze" | Out-Null } catch { Log "analyze $($p.name): $(ErrText $_)" } }
Log 'waiting 180 s for re-analysis'; Start-Sleep 180
$results = [ordered]@{ run = (Get-Date).ToString('s'); mirror = $run; adapter = $adapterStats.modified_feed; feedLog = $feedLines; projects = [ordered]@{} }
foreach ($p in ($projects | Sort-Object name)) {
    try { $f = Paged "/api/v1/finding/project/$($p.uuid)?suppressed=true"
          $results.projects[$p.name] = [ordered]@{ findings = $f.Count
              findingList = @($f | ForEach-Object { [ordered]@{ component = "$($_.component.name)@$($_.component.version)"; id = $_.vulnerability.vulnId; source = $_.vulnerability.source; analyzer = $_.attribution.analyzerIdentity } }) }
          Log "$($p.name): findings=$($f.Count)" } catch { Log "collect $($p.name): $(ErrText $_)" }
}
$results | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $Dir 'nvdpp-v2-verify-results.json') -Encoding UTF8
docker compose -f (Join-Path $Dir 'compose.yaml') stop 2>&1 | ForEach-Object { Log "compose: $_" }
Log 'DONE - containers stopped; images and data volumes kept.'
Status 'done'
