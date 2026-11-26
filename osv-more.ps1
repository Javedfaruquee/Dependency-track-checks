# Dependency-Track v5: adds OSV ecosystems PyPI, npm, NuGet, Maven; uploads npm/NuGet/Maven control SBOMs;
# saves the analyzer and KEV settings schemas (dt5-extensions.json) so API keys can be configured; collects results;
# then stops the containers (images and data volumes kept).
# Images and data volumes are kept, so a re-run reuses the mirrored NVD data.

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$Dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Log = Join-Path $Dir 'osv-more-log.txt'
$Api = 'http://localhost:8081'
$NewPw = 'DtTest-2026!'

function Log([string]$m) { $l = "$(Get-Date -Format 'HH:mm:ss') $m"; Write-Host $l; Add-Content -Path $Log -Value $l -Encoding UTF8 }
function Status([string]$s) { @{ stage = $s; time = (Get-Date).ToString('s') } | ConvertTo-Json | Set-Content -Path (Join-Path $Dir 'osv-more-status.json') -Encoding UTF8 }
function ErrText($e) { $t = $e.Exception.Message; if ($e.ErrorDetails -and $e.ErrorDetails.Message) { $t += ' | ' + $e.ErrorDetails.Message }; return $t }
function J($o) { return ($o | ConvertTo-Json -Depth 10 -Compress) }
# Windows PowerShell 5.1 returns JSON arrays from Invoke-RestMethod as ONE object; flatten to real items
function Items($x) { $o = New-Object System.Collections.ArrayList; foreach ($i in @($x)) { if ($i -is [System.Array]) { foreach ($j in $i) { [void]$o.Add($j) } } elseif ($null -ne $i) { [void]$o.Add($i) } }; return ,$o.ToArray() }

Set-Content -Path $Log -Value "dt5 OSV more-ecosystems run started $(Get-Date -Format s)" -Encoding UTF8
Status 'starting'

# ---------- start containers if needed ----------
docker compose -f (Join-Path $Dir 'compose.yaml') up -d 2>&1 | ForEach-Object { Log "compose: $_" }
$up = $false
for ($i = 0; $i -lt 60; $i++) { try { $ver = Invoke-RestMethod -Uri "$Api/api/version" -TimeoutSec 5; $up = $true; break } catch { Start-Sleep 5 } }
if (-not $up) { Log 'FAILED: API server did not come up'; Status 'failed-api'; exit 1 }
$uploadResult = 'see log.txt of the main run'
# ---------- log in ----------
Status 'login'
try { Invoke-RestMethod -Method Post -Uri "$Api/api/v1/user/forceChangePassword" -ContentType 'application/x-www-form-urlencoded' -Body @{ username = 'admin'; password = 'admin'; newPassword = $NewPw; confirmPassword = $NewPw } | Out-Null; Log 'initial admin password changed' }
catch { Log "forceChangePassword (fine on re-runs): $(ErrText $_)" }
$tok = $null
foreach ($p in @($NewPw, 'admin')) {
    try { $tok = Invoke-RestMethod -Method Post -Uri "$Api/api/v1/user/login" -ContentType 'application/x-www-form-urlencoded' -Body @{ username = 'admin'; password = $p }; if ($tok) { Log 'login ok'; break } }
    catch { Log "login attempt failed: $(ErrText $_)" }
}
if (-not $tok) { Log 'FAILED: could not log in'; Status 'failed-login'; exit 1 }
$script:H = @{ Authorization = "Bearer $tok" }
function Diag([string]$why) {
    Log "DIAG ($why): apiserver state $((docker inspect --format '{{.RestartCount}} restarts, started {{.State.StartedAt}}, status {{.State.Status}}, OOMKilled {{.State.OOMKilled}}' dt5-test-apiserver-1 2>&1 | Out-String).Trim())"
    docker logs --tail 60 dt5-test-apiserver-1 2>&1 | ForEach-Object { Log "apiserver-log: $_" }
}
function Relogin {
    try { $t = Invoke-RestMethod -Method Post -Uri "$Api/api/v1/user/login" -ContentType 'application/x-www-form-urlencoded' -Body @{ username = 'admin'; password = $NewPw }
          if ($t) { $script:H = @{ Authorization = "Bearer $t" }; Log 're-login ok'; return $true } } catch { Log "re-login failed: $(ErrText $_)" }
    return $false
}
$script:diagDone = $false
function Api([string]$method, [string]$path, $body = $null) {
    for ($attempt = 0; $attempt -lt 2; $attempt++) {
        $req = @{ Method = $method; Uri = "$Api$path"; Headers = $script:H; TimeoutSec = 120 }
        if ($null -ne $body) { $req.Body = [Text.Encoding]::UTF8.GetBytes((J $body)); $req.ContentType = 'application/json' }
        try { return Invoke-RestMethod @req }
        catch {
            $code = 0; if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
            if ($code -eq 401 -and $attempt -eq 0) {
                if (-not $script:diagDone) { Diag "401 on $method $path"; $script:diagDone = $true }
                if (Relogin) { continue }
            }
            throw
        }
    }
}
# Prefer a team API key (more robust than the session token for long runs)
try {
    $teams = Items (Api 'GET' '/api/v1/team')
    $adm = $teams | Where-Object { $_.name -eq 'Administrators' } | Select-Object -First 1
    if ($adm) {
        $k = Api 'PUT' "/api/v1/team/$($adm.uuid)/key"
        $key = $k.key; if (-not $key) { $key = $k.secret }
        if ($key) { $script:H = @{ 'X-Api-Key' = $key }; Log "using Administrators team API key ($($key.Substring(0,8))...)" }
        else { Log "API key response without key field: $(J $k)" }
    } else { Log "Administrators team not found: $(J $teams)" }
} catch { Log "API key creation failed, staying on session token: $(ErrText $_)" }
Diag 'after login'

# ---------- OSV helpers ----------
$ep = 'vuln-data-source'
function Set-OsvEcosystems($ecos) {
    $cfg = $null
    try { $cur = Api 'GET' "/api/v2/extension-points/$ep/extensions/osv/config"; if ($cur.config) { $cfg = $cur.config } else { $cfg = $cur } } catch { Log "osv get config: $(ErrText $_)" }
    $h = @{}
    if ($cfg) { $cfg.PSObject.Properties | ForEach-Object { $h[$_.Name] = $_.Value } }
    $h['enabled'] = $true
    $h['ecosystems'] = @($ecos)
    try { Api 'PUT' "/api/v2/extension-points/$ep/extensions/osv/config" @{ config = $h } | Out-Null } catch { Log "osv set config: $(ErrText $_)" }
    try { $cur = Api 'GET' "/api/v2/extension-points/$ep/extensions/osv/config"; Log "osv config now: $(J $cur)" } catch { Log "osv get config after: $(ErrText $_)" }
}
function Mirror-Osv([int]$Minutes = 20) {
    $prev = $null; try { $prev = (Api 'GET' "/api/v2/vuln-data-sources/osv/mirror-runs/latest").started_at } catch { }
    try { Api 'POST' "/api/v2/vuln-data-sources/osv/mirror-runs" | Out-Null; Log 'osv mirror triggered' } catch { Log "osv trigger: $(ErrText $_)" }
    $deadline = (Get-Date).AddMinutes($Minutes); $last = ''; $run = $null
    while ((Get-Date) -lt $deadline) {
        Start-Sleep 15
        try { $run = Api 'GET' "/api/v2/vuln-data-sources/osv/mirror-runs/latest"; $s = J $run
              if ($s -ne $last) { Log "osv mirror: $s"; $last = $s; Status "mirror-osv $($run.status)" }
              if ("$($run.started_at)" -ne "$prev" -and "$($run.status)" -match '(?i)complet|fail|error|cancel') { break } } catch { Log "osv mirror status: $(ErrText $_)" }
    }
    return "$($run.status)"
}

# ---------- discovery: analyzers, KEV sources, secrets, OpenAPI ----------
Status 'discovery'
$disc = [ordered]@{}
try { $disc.extensionPoints = Api 'GET' '/api/v2/extension-points' } catch { $disc.extensionPointsError = ErrText $_ }
foreach ($pt in @('kev-data-source', 'vuln-analyzer', 'vuln-data-source')) {
    try {
        $ex = Api 'GET' "/api/v2/extension-points/$pt/extensions"
        $entry = [ordered]@{ list = $ex; configs = [ordered]@{} }
        foreach ($e in (Items $ex.items)) {
            $n = $e.name; $cfgEntry = [ordered]@{}
            try { $cfgEntry.schema = Api 'GET' "/api/v2/extension-points/$pt/extensions/$n/config-schema" } catch { $cfgEntry.schemaError = ErrText $_ }
            try { $cfgEntry.config = Api 'GET' "/api/v2/extension-points/$pt/extensions/$n/config" } catch { $cfgEntry.configError = ErrText $_ }
            $entry.configs[$n] = $cfgEntry
        }
        $disc[$pt] = $entry
        Log "$pt extensions: $(@((Items $ex.items) | ForEach-Object { $_.name }) -join ', ')"
    } catch { $disc["$pt-error"] = ErrText $_; Log "$pt : $(ErrText $_)" }
}
$disc | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $Dir 'dt5-extensions.json') -Encoding UTF8
foreach ($pth in @('/api/v2/secrets', '/api/v2/openapi.yaml', '/api/v2/openapi.json', '/api/openapi.json')) {
    try { $r = Invoke-WebRequest -UseBasicParsing -Uri "$Api$pth" -Headers $script:H -TimeoutSec 60
          $txt = $r.Content; if ($txt -is [byte[]]) { $txt = [Text.Encoding]::UTF8.GetString($txt) }
          $fn = 'dt5-' + (($pth.Trim('/')) -replace '/', '-')
          [IO.File]::WriteAllText((Join-Path $Dir $fn), $txt)
          Log "saved $pth -> $fn ($($txt.Length) chars)" } catch { Log "GET $pth : $(ErrText $_)" }
}

# ---------- OSV: PyPI, npm, NuGet, Maven ----------
$t0 = Get-Date
$ecos = @('PyPI', 'npm', 'NuGet', 'Maven')
$ecosUsed = $ecos
Status 'mirror-osv'
Set-OsvEcosystems $ecos
$st = Mirror-Osv 90
if ($st -notmatch '(?i)complet') {
    $why = ''; try { $why = "$((Api 'GET' '/api/v2/vuln-data-sources/osv/mirror-runs/latest').failure_reason)" } catch { }
    Log "OSV mirror did not complete ($st): $why"
    $bad = $ecos | Where-Object { $why -match "ecosystem $_\b" }
    if ($bad) { $ecosUsed = @($ecos | Where-Object { $bad -notcontains $_ }); Log "dropping $($bad -join ', ') and retrying" }
    else { $ecosUsed = @('PyPI'); Log 'reverting to PyPI only' }
    Set-OsvEcosystems $ecosUsed
    $st = Mirror-Osv 90
    Log "retry mirror: $st"
}
$mins = [int][Math]::Ceiling(((Get-Date) - $t0).TotalMinutes) + 1
docker logs --since "$($mins)m" dt5-test-apiserver-1 2>&1 | Where-Object { "$_" -match '(?i)Finished ecosystem|Completed mirror|Failed to download|ecosystem' } | Select-Object -Last 30 | ForEach-Object { Log "apiserver-log: $_" }
$h = @{ ecosystems = $ecosUsed }

# ---------- upload npm / NuGet / Maven control SBOMs ----------
Status 'upload'
$sbomDir = Join-Path $Dir 'sboms'
$uploads = [ordered]@{ 'npm-control' = 'npm-control.cdx.json'; 'nuget-control' = 'nuget-control.cdx.json'; 'maven-control' = 'maven-control.cdx.json' }
foreach ($name in $uploads.Keys) {
    $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $sbomDir $uploads[$name])))
    try { $r = Api 'PUT' '/api/v1/bom' @{ projectName = $name; projectVersion = '1'; autoCreate = $true; bom = $b64 }; Log "uploaded $name : $(J $r)" }
    catch { Log "upload $name FAILED: $(ErrText $_)" }
}
Log 'waiting 90 s for BOM processing'
Start-Sleep 90

# ---------- re-analyse and collect ----------
Status 'collect'
$projects = @()
try { $projects = Items (Api 'GET' '/api/v1/project?pageSize=100') } catch { Log "projects: $(ErrText $_)" }
foreach ($p in $projects) { try { Api 'POST' "/api/v1/finding/project/$($p.uuid)/analyze" | Out-Null } catch { Log "analyze $($p.name): $(ErrText $_)" } }
Log 'waiting 120 s for re-analysis'
Start-Sleep 120
$results = [ordered]@{ dtVersion = $ver; osvEcosystems = $h['ecosystems']; projects = [ordered]@{} }
foreach ($p in ($projects | Sort-Object name)) {
    $entry = [ordered]@{}
    try { $comps = Items (Api 'GET' "/api/v1/component/project/$($p.uuid)?pageSize=500")
          $entry.components = $comps.Count
          $entry.componentList = @($comps | Select-Object -First 15 | ForEach-Object { "$($_.name)@$($_.version) purl=$($_.purl) cpe=$($_.cpe)" }) } catch { $entry.componentsError = ErrText $_ }
    try { $f = Items (Api 'GET' "/api/v1/finding/project/$($p.uuid)?suppressed=true&pageSize=2000")
          $entry.findings = $f.Count
          $by = [ordered]@{}
          foreach ($x in $f) { $k = "$($x.component.name)@$($x.component.version)"; if (-not $by.Contains($k)) { $by[$k] = @() }; $by[$k] += "$($x.vulnerability.source):$($x.vulnerability.vulnId)" }
          $entry.byComponent = $by
          $entry.sources = @($f | ForEach-Object { $_.vulnerability.source } | Sort-Object -Unique) } catch { $entry.findingsError = ErrText $_ }
    $results.projects[$p.name] = $entry
    Log "$($p.name): components=$($entry.components) findings=$($entry.findings) sources=$(@($entry.sources) -join ',')"
}
$results | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $Dir 'osv-more-results.json') -Encoding UTF8

# ---------- stop ----------
Status 'stopping'
docker compose -f (Join-Path $Dir 'compose.yaml') stop 2>&1 | ForEach-Object { Log "compose: $_" }
Log 'DONE - containers stopped; images and data volumes kept.'
Status 'done'

