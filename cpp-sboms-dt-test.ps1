# Dependency-Track v5: load the eight C++ / firmware SBOMs from cpp-sboms\sboms as separate projects,
# run every configured analyzer (NVD + VulnCheck CPEs, OSS Index, Trivy, OSV), and save:
#   cpp-sboms-dt-results.json   components, identifiers, hashes and findings per project (with analyzer)
#   cpp-sboms\dt-exports\*.json the CycloneDX that DT gives back (shows which SBOM fields DT keeps)
# Starts the stack from this folder (also recreates the NVD adapter after the folder move),
# then stops the containers. Images and data volumes are kept. Safe to re-run.

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$Dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Log = Join-Path $Dir 'cpp-sboms-dt-log.txt'
$Api = 'http://localhost:8081'
$NewPw = 'DtTest-2026!'
$SbomDir = Join-Path $Dir 'cpp-sboms\sboms'
$VariantDir = Join-Path $Dir 'cpp-sboms\dt-variants'
$ExportDir = Join-Path $Dir 'cpp-sboms\dt-exports'
New-Item -ItemType Directory -Force -Path $ExportDir | Out-Null

function Log([string]$m) { $l = "$(Get-Date -Format 'HH:mm:ss') $m"; Write-Host $l; Add-Content -Path $Log -Value $l -Encoding UTF8 }
function Status([string]$s) { @{ stage = $s; time = (Get-Date).ToString('s') } | ConvertTo-Json | Set-Content -Path (Join-Path $Dir 'cpp-sboms-dt-status.json') -Encoding UTF8 }
function ErrText($e) { $t = $e.Exception.Message; if ($e.ErrorDetails -and $e.ErrorDetails.Message) { $t += ' | ' + $e.ErrorDetails.Message }; return $t }
function J($o) { return ($o | ConvertTo-Json -Depth 10 -Compress) }
function Items($x) { $o = New-Object System.Collections.ArrayList; foreach ($i in @($x)) { if ($i -is [System.Array]) { foreach ($j in $i) { [void]$o.Add($j) } } elseif ($null -ne $i) { [void]$o.Add($i) } }; return ,$o.ToArray() }

Set-Content -Path $Log -Value "cpp-sboms DT run started $(Get-Date -Format s)" -Encoding UTF8
Status 'starting'

# ---------- start containers ----------
docker compose -f (Join-Path $Dir 'compose.yaml') up -d 2>&1 | ForEach-Object { Log "compose: $_" }
$up = $false
for ($i = 0; $i -lt 60; $i++) { try { $ver = Invoke-RestMethod -Uri "$Api/api/version" -TimeoutSec 5; $up = $true; break } catch { Start-Sleep 5 } }
if (-not $up) { Log 'FAILED: API server did not come up'; Status 'failed-api'; exit 1 }
Log "DT version: $(J $ver)"
try { $s = Invoke-RestMethod -Uri 'http://localhost:8090/stats' -TimeoutSec 10; Log "nvdpp adapter: $(J $s)" } catch { Log "nvdpp adapter stats: $(ErrText $_)" }

# ---------- log in ----------
Status 'login'
$tok = $null
foreach ($p in @($NewPw, 'admin')) {
    try { $tok = Invoke-RestMethod -Method Post -Uri "$Api/api/v1/user/login" -ContentType 'application/x-www-form-urlencoded' -Body @{ username = 'admin'; password = $p }; if ($tok) { Log 'login ok'; break } }
    catch { Log "login attempt failed: $(ErrText $_)" }
}
if (-not $tok) { Log 'FAILED: could not log in'; Status 'failed-login'; exit 1 }
$script:H = @{ Authorization = "Bearer $tok" }
function Relogin {
    try { $t = Invoke-RestMethod -Method Post -Uri "$Api/api/v1/user/login" -ContentType 'application/x-www-form-urlencoded' -Body @{ username = 'admin'; password = $NewPw }
          if ($t) { $script:H = @{ Authorization = "Bearer $t" }; Log 're-login ok'; return $true } } catch { Log "re-login failed: $(ErrText $_)" }
    return $false
}
function Api([string]$method, [string]$path, $body = $null) {
    for ($attempt = 0; $attempt -lt 2; $attempt++) {
        $req = @{ Method = $method; Uri = "$Api$path"; Headers = $script:H; TimeoutSec = 120 }
        if ($null -ne $body) { $req.Body = [Text.Encoding]::UTF8.GetBytes((J $body)); $req.ContentType = 'application/json' }
        try { return Invoke-RestMethod @req }
        catch {
            $code = 0; if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
            if ($code -eq 401 -and $attempt -eq 0) { if (Relogin) { continue } }
            throw
        }
    }
}
try {
    $teams = Items (Api 'GET' '/api/v1/team')   # assign first: piping Items() directly passes the whole array as one object
    $adm = $teams | Where-Object { $_.name -eq 'Administrators' } | Select-Object -First 1
    if ($adm) { $k = Api 'PUT' "/api/v1/team/$($adm.uuid)/key"; $key = $k.key; if (-not $key) { $key = $k.secret }
                if ($key) { $script:H = @{ 'X-Api-Key' = $key }; Log 'using Administrators team API key' } }
} catch { Log "API key creation failed, staying on session token: $(ErrText $_)" }

# ---------- analyzer settings (for the record) ----------
$analyzers = [ordered]@{}
foreach ($pt in @('vuln-analyzer', 'vuln-data-source')) {
    try { $ex = Api 'GET' "/api/v2/extension-points/$pt/extensions"
          foreach ($e in (Items $ex.items)) { $n = $e.name
              try { $c = Api 'GET' "/api/v2/extension-points/$pt/extensions/$n/config"; $cfg = $c; if ($c.config) { $cfg = $c.config }
                    $analyzers["$pt/$n"] = [ordered]@{ enabled = $cfg.enabled; ecosystems = $cfg.ecosystems } } catch { $analyzers["$pt/$n"] = 'config not readable' } } }
    catch { Log "$pt : $(ErrText $_)" }
}
Log "analyzers: $(J $analyzers)"

# ---------- paging: DT 5 returns at most 100 items per page ----------
function Paged([string]$path) {
    $all = New-Object System.Collections.ArrayList; $seen = @{}
    $sep = '?'; if ($path.Contains('?')) { $sep = '&' }
    for ($pg = 1; $pg -le 200; $pg++) {
        $r = Items (Api 'GET' "$path$($sep)pageSize=100&pageNumber=$pg")
        $new = 0
        foreach ($x in $r) { $k = J $x; if (-not $seen.ContainsKey($k)) { $seen[$k] = 1; [void]$all.Add($x); $new++ } }
        if ($r.Count -lt 100 -or $new -eq 0) { break }
    }
    return ,$all.ToArray()
}

# ---------- wait helper: DT event / workflow token ----------
function Wait-Token([string]$t, [int]$maxSec = 600) {
    if (-not $t) { Start-Sleep 90; return 'no token (slept 90 s)' }
    $deadline = (Get-Date).AddSeconds($maxSec); $seen = ''
    while ((Get-Date) -lt $deadline) {
        Start-Sleep 10
        try { $r = Api 'GET' "/api/v1/event/token/$t"; if ($r.processing -eq $false) { return 'done (event token)' }; $seen = 'event' ; continue } catch { }
        try { $w = Items (Api 'GET' "/api/v1/workflow/token/$t/status")
              $open = @($w | Where-Object { "$($_.status)" -match '(?i)pending|processing|^$' })
              if ($w.Count -gt 0 -and $open.Count -eq 0) { return "done (workflow: $(@($w | ForEach-Object { "$($_.step)=$($_.status)" }) -join ', '))" }
              $seen = 'workflow'; continue } catch { }
    }
    return "timeout after $maxSec s (last seen: $seen)"
}

# ---------- upload ----------
Status 'upload'
$files = @(Get-ChildItem -Path $SbomDir -Filter '*.cdx.json') + @(Get-ChildItem -Path $VariantDir -Filter '*.cdx.json' -ErrorAction SilentlyContinue) | Sort-Object Name
$proj = [ordered]@{}
foreach ($f in $files) {
    $name = 'cpp-sbom-' + ($f.Name -replace '\.cdx\.json$', '')
    $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($f.FullName))
    try { $r = Api 'PUT' '/api/v1/bom' @{ projectName = $name; projectVersion = '1'; autoCreate = $true; bom = $b64 }
          $proj[$name] = "$($r.token)"; Log "uploaded $name" }
    catch { Log "upload $name FAILED: $(ErrText $_)"; $proj[$name] = $null }
}
foreach ($n in $proj.Keys) { if ($null -ne $proj[$n]) { Log "$n processing: $(Wait-Token $proj[$n] 600)" } }

# ---------- analyse ----------
Status 'analyse'
$allProjects = Paged '/api/v1/project'
$projects = @($allProjects | Where-Object { $_.name -like 'cpp-sbom-*' })
Log "projects to analyse: $(@($projects | ForEach-Object { $_.name }) -join ', ')"
$atok = [ordered]@{}
foreach ($p in $projects) { try { $r = Api 'POST' "/api/v1/finding/project/$($p.uuid)/analyze"; $atok[$p.name] = "$($r.token)" } catch { Log "analyze $($p.name): $(ErrText $_)" } }
foreach ($n in $atok.Keys) { Log "$n analysis: $(Wait-Token $atok[$n] 900)" }
Start-Sleep 30

# ---------- collect ----------
Status 'collect'
$results = [ordered]@{ run = (Get-Date).ToString('s'); dtVersion = $ver; analyzers = $analyzers; projects = [ordered]@{} }
foreach ($p in ($projects | Sort-Object name)) {
    $e = [ordered]@{}
    try { $comps = Paged "/api/v1/component/project/$($p.uuid)"
          $e.components = $comps.Count
          $e.componentList = @($comps | ForEach-Object { [ordered]@{ name = $_.name; version = $_.version; group = $_.group; purl = $_.purl; cpe = $_.cpe;
                sha512 = [bool]$_.sha512; sha256 = [bool]$_.sha256; supplier = $_.supplier.name; license = "$($_.resolvedLicense.licenseId)$($_.license)";
                externalReferences = @($_.externalReferences).Count } }) } catch { $e.componentsError = ErrText $_ }
    try { $f = Paged "/api/v1/finding/project/$($p.uuid)?suppressed=true"
          $e.findings = $f.Count
          $e.findingList = @($f | ForEach-Object { [ordered]@{ component = "$($_.component.name)@$($_.component.version)"; id = $_.vulnerability.vulnId;
                source = $_.vulnerability.source; severity = $_.vulnerability.severity; analyzer = $_.attribution.analyzerIdentity;
                aliases = @($_.vulnerability.aliases | ForEach-Object { @($_.cveId, $_.ghsaId, $_.osvId, $_.sonatypeId, $_.snykId) | Where-Object { $_ } }) } }) } catch { $e.findingsError = ErrText $_ }
    foreach ($v in @('inventory', 'withVulnerabilities')) {
        try { $r = Invoke-WebRequest -UseBasicParsing -Uri "$Api/api/v1/bom/cyclonedx/project/$($p.uuid)?format=JSON&variant=$v" -Headers $script:H -TimeoutSec 120
              $txt = $r.Content; if ($txt -is [byte[]]) { $txt = [Text.Encoding]::UTF8.GetString($txt) }
              [IO.File]::WriteAllText((Join-Path $ExportDir "$($p.name).$v.cdx.json"), $txt) } catch { Log "export $($p.name) $v : $(ErrText $_)" }
    }
    $results.projects[$p.name] = $e
    Log "$($p.name): components=$($e.components) findings=$($e.findings)"
}
$results | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $Dir 'cpp-sboms-dt-results.json') -Encoding UTF8

# ---------- stop ----------
Status 'stopping'
docker compose -f (Join-Path $Dir 'compose.yaml') stop 2>&1 | ForEach-Object { Log "compose: $_" }
Log 'DONE - containers stopped; images and data volumes kept.'
Status 'done'
