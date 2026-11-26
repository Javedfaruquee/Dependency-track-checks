# Dependency-Track v5: removes ConanCenter from OSV (OSV publishes no ConanCenter data) and tests the OSV vcpkg ecosystem
# If vcpkg also fails, falls back to PyPI only. Re-analyses the C++ projects, writes osv-vcpkg-results.json,
# then stops the containers (images and data volumes kept).
# Images and data volumes are kept, so a re-run reuses the mirrored NVD data.

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$Dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Log = Join-Path $Dir 'osv-vcpkg-log.txt'
$Api = 'http://localhost:8081'
$NewPw = 'DtTest-2026!'

function Log([string]$m) { $l = "$(Get-Date -Format 'HH:mm:ss') $m"; Write-Host $l; Add-Content -Path $Log -Value $l -Encoding UTF8 }
function Status([string]$s) { @{ stage = $s; time = (Get-Date).ToString('s') } | ConvertTo-Json | Set-Content -Path (Join-Path $Dir 'osv-vcpkg-status.json') -Encoding UTF8 }
function ErrText($e) { $t = $e.Exception.Message; if ($e.ErrorDetails -and $e.ErrorDetails.Message) { $t += ' | ' + $e.ErrorDetails.Message }; return $t }
function J($o) { return ($o | ConvertTo-Json -Depth 10 -Compress) }
# Windows PowerShell 5.1 returns JSON arrays from Invoke-RestMethod as ONE object; flatten to real items
function Items($x) { $o = New-Object System.Collections.ArrayList; foreach ($i in @($x)) { if ($i -is [System.Array]) { foreach ($j in $i) { [void]$o.Add($j) } } elseif ($null -ne $i) { [void]$o.Add($i) } }; return ,$o.ToArray() }

Set-Content -Path $Log -Value "dt5 OSV vcpkg test started $(Get-Date -Format s)" -Encoding UTF8
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

# ---------- OSV: PyPI + vcpkg, fall back to PyPI only ----------
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
function Mirror-Osv {
    $prev = $null; try { $prev = (Api 'GET' "/api/v2/vuln-data-sources/osv/mirror-runs/latest").started_at } catch { }
    try { Api 'POST' "/api/v2/vuln-data-sources/osv/mirror-runs" | Out-Null; Log 'osv mirror triggered' } catch { Log "osv trigger: $(ErrText $_)" }
    $deadline = (Get-Date).AddMinutes(20); $last = ''; $run = $null
    while ((Get-Date) -lt $deadline) {
        Start-Sleep 15
        try { $run = Api 'GET' "/api/v2/vuln-data-sources/osv/mirror-runs/latest"; $s = J $run
              if ($s -ne $last) { Log "osv mirror: $s"; $last = $s }
              if ("$($run.started_at)" -ne "$prev" -and "$($run.status)" -match '(?i)complet|fail|error|cancel') { break } } catch { Log "osv mirror status: $(ErrText $_)" }
    }
    return "$($run.status)"
}
Status 'mirror-osv-vcpkg'
$t0 = Get-Date
Set-OsvEcosystems @('PyPI', 'vcpkg')
$st = Mirror-Osv
$ecosUsed = @('PyPI', 'vcpkg')
if ($st -notmatch '(?i)complet') {
    Log "vcpkg mirror did not complete ($st); reverting OSV to PyPI only"
    Status 'mirror-osv-pypi'
    Set-OsvEcosystems @('PyPI')
    $st2 = Mirror-Osv
    Log "PyPI-only mirror: $st2"
    $ecosUsed = @('PyPI')
}
$mins = [int][Math]::Ceiling(((Get-Date) - $t0).TotalMinutes) + 1
docker logs --since "$($mins)m" dt5-test-apiserver-1 2>&1 | Where-Object { "$_" -match '(?i)OsvVulnDataSource|vcpkg|MirrorVulnDataSourceActivity' } | Select-Object -Last 30 | ForEach-Object { Log "apiserver-log: $_" }
$h = @{ ecosystems = $ecosUsed }

# ---------- re-analyse and collect ----------
Status 'collect'
$projects = @()
try { $projects = Items (Api 'GET' '/api/v1/project?pageSize=100') } catch { Log "projects: $(ErrText $_)" }
$projects = @($projects | Where-Object { $_.name -match '^(conan|vcpkg|vendored)' })
foreach ($p in $projects) { try { Api 'POST' "/api/v1/finding/project/$($p.uuid)/analyze" | Out-Null } catch { Log "analyze $($p.name): $(ErrText $_)" } }
Log 'waiting 120 s for re-analysis'
Start-Sleep 120
$results = [ordered]@{ dtVersion = $ver; osvEcosystems = $h['ecosystems']; projects = [ordered]@{} }
foreach ($p in ($projects | Sort-Object name)) {
    $entry = [ordered]@{}
    try { $comps = Items (Api 'GET' "/api/v1/component/project/$($p.uuid)?pageSize=500")
          $entry.components = $comps.Count
          $entry.componentList = @($comps | Select-Object -First 12 | ForEach-Object { "$($_.name)@$($_.version) purl=$($_.purl) cpe=$($_.cpe)" }) } catch { $entry.componentsError = ErrText $_ }
    try { $f = Items (Api 'GET' "/api/v1/finding/project/$($p.uuid)?suppressed=true&pageSize=2000")
          $entry.findings = $f.Count
          $by = [ordered]@{}
          foreach ($x in $f) { $k = "$($x.component.name)@$($x.component.version)"; if (-not $by.Contains($k)) { $by[$k] = @() }; $by[$k] += "$($x.vulnerability.source):$($x.vulnerability.vulnId)" }
          $entry.byComponent = $by
          $entry.sources = @($f | ForEach-Object { $_.vulnerability.source } | Sort-Object -Unique) } catch { $entry.findingsError = ErrText $_ }
    $results.projects[$p.name] = $entry
    Log "$($p.name): components=$($entry.components) findings=$($entry.findings) sources=$(@($entry.sources) -join ',')"
}
$results | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $Dir 'osv-vcpkg-results.json') -Encoding UTF8

# ---------- stop ----------
Status 'stopping'
docker compose -f (Join-Path $Dir 'compose.yaml') stop 2>&1 | ForEach-Object { Log "compose: $_" }
Log 'DONE - containers stopped; images and data volumes kept.'
Status 'done'

