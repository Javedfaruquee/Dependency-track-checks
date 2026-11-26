# Dependency-Track v5: adds a Trivy server (v0.76.2) to the stack, connects DT's Trivy analyzer to it,
# re-analyses all projects and writes trivy-results.json with findings per analyzer (internal / OSS Index / Trivy),
# then stops the containers (images and data volumes, including the Trivy database cache, are kept).
# Images and data volumes are kept, so a re-run reuses the mirrored NVD data.

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$Dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Log = Join-Path $Dir 'trivy-log.txt'
$Api = 'http://localhost:8081'
$NewPw = 'DtTest-2026!'

function Log([string]$m) { $l = "$(Get-Date -Format 'HH:mm:ss') $m"; Write-Host $l; Add-Content -Path $Log -Value $l -Encoding UTF8 }
function Status([string]$s) { @{ stage = $s; time = (Get-Date).ToString('s') } | ConvertTo-Json | Set-Content -Path (Join-Path $Dir 'set-api-keys-status.json') -Encoding UTF8 }
function ErrText($e) { $t = $e.Exception.Message; if ($e.ErrorDetails -and $e.ErrorDetails.Message) { $t += ' | ' + $e.ErrorDetails.Message }; return $t }
function J($o) { return ($o | ConvertTo-Json -Depth 10 -Compress) }
# Windows PowerShell 5.1 returns JSON arrays from Invoke-RestMethod as ONE object; flatten to real items
function Items($x) { $o = New-Object System.Collections.ArrayList; foreach ($i in @($x)) { if ($i -is [System.Array]) { foreach ($j in $i) { [void]$o.Add($j) } } elseif ($null -ne $i) { [void]$o.Add($i) } }; return ,$o.ToArray() }

Set-Content -Path $Log -Value "dt5 Trivy setup started $(Get-Date -Format s)" -Encoding UTF8
Status 'starting'


# ---------- Trivy token in .env (used by compose.yaml) ----------
$envFile = Join-Path $Dir '.env'
$trivyToken = $null
if (Test-Path $envFile) { foreach ($l in (Get-Content $envFile)) { if ($l -match '^TRIVY_TOKEN=(.+)$') { $trivyToken = $Matches[1].Trim() } } }
if (-not $trivyToken) {
    $bytes = New-Object byte[] 24; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $trivyToken = ($bytes | ForEach-Object { $_.ToString('x2') }) -join ''
    Add-Content -Path $envFile -Value "TRIVY_TOKEN=$trivyToken" -Encoding ASCII
    Log 'generated a Trivy server token in .env'
} else { Log 'using the Trivy token from .env' }

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


# ---------- wait for the Trivy server (first start downloads its vulnerability database) ----------
Status 'trivy-start'
$dig = (docker image inspect ghcr.io/aquasecurity/trivy:0.76.2 --format '{{index .RepoDigests 0}}' 2>&1 | Out-String).Trim()
Log "trivy image: $dig"
$trivyUp = $false
for ($i = 0; $i -lt 90; $i++) {
    try { $r = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:4954/healthz' -TimeoutSec 5; if ($r.StatusCode -eq 200) { $trivyUp = $true; break } } catch { }
    Start-Sleep 10
}
docker logs --tail 15 dt5-test-trivy-1 2>&1 | ForEach-Object { Log "trivy-log: $_" }
if (-not $trivyUp) { Log 'WARNING: Trivy server did not report healthy within 15 minutes; continuing anyway' } else { Log 'Trivy server healthy' }

function Put-Secret([string]$name, [string]$value, [string]$desc) {
    try { Api 'POST' '/api/v2/secrets' @{ name = $name; value = $value; description = $desc } | Out-Null; Log "secret $name created" }
    catch {
        $code = 0; if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        if ($code -eq 409) { try { Api 'PATCH' "/api/v2/secrets/$name" @{ value = $value; description = $desc } | Out-Null; Log "secret $name updated" } catch { Log "secret $name update failed: $(ErrText $_)" } }
        else { Log "secret $name create failed: $(ErrText $_)" }
    }
}
function Set-ExtConfig([string]$pt, [string]$name, [hashtable]$changes) {
    $h = @{}
    try { $cur = Api 'GET' "/api/v2/extension-points/$pt/extensions/$name/config"; $cfg = $cur.config; if (-not $cfg) { $cfg = $cur }
          if ($cfg) { $cfg.PSObject.Properties | ForEach-Object { $h[$_.Name] = $_.Value } } } catch { Log "$pt/$name get config: $(ErrText $_)" }
    foreach ($k in $changes.Keys) { $h[$k] = $changes[$k] }
    try { Api 'PUT' "/api/v2/extension-points/$pt/extensions/$name/config" @{ config = $h } | Out-Null; Log "$pt/$name config set" } catch { Log "$pt/$name set config: $(ErrText $_)" }
    try { $cur = Api 'GET' "/api/v2/extension-points/$pt/extensions/$name/config"; Log "$pt/$name config now: $(J $cur)" } catch { }
}


# ---------- connect DT's Trivy analyzer ----------
Status 'configure'
Put-Secret 'TRIVY_API_TOKEN' $trivyToken 'Token of the local Trivy server (see .env)'
Set-ExtConfig 'vuln-analyzer' 'trivy' @{ enabled = $true; apiUrl = 'http://trivy:4954'; apiToken = 'TRIVY_API_TOKEN'; scanLibrary = $true; scanOs = $true; ignoreUnfixed = $false }
foreach ($n in @('internal', 'oss-index')) { try { $c = Api 'GET' "/api/v2/extension-points/vuln-analyzer/extensions/$n/config"; Log "analyzer $n : enabled=$($c.config.enabled)" } catch { } }
try { $c = Api 'GET' '/api/v2/extension-points/kev-data-source/extensions/vulncheck/config'; Log "kev vulncheck : enabled=$($c.config.enabled)" } catch { }

# ---------- re-analyse and collect (all pages) ----------
Status 'collect'
$projects = @()
try { $projects = Items (Api 'GET' '/api/v1/project?pageSize=100') } catch { Log "projects: $(ErrText $_)" }
$t0 = Get-Date
foreach ($p in $projects) { try { Api 'POST' "/api/v1/finding/project/$($p.uuid)/analyze" | Out-Null } catch { Log "analyze $($p.name): $(ErrText $_)" } }
Log 'waiting 240 s for re-analysis (OSS Index and Trivy are queried)'
Start-Sleep 240
function All-Findings($uuid) {
    $all = New-Object System.Collections.ArrayList
    for ($pg = 1; $pg -le 30; $pg++) {
        $f = Items (Api 'GET' "/api/v1/finding/project/$($uuid)?suppressed=true&pageSize=100&pageNumber=$pg")
        foreach ($x in $f) { [void]$all.Add($x) }
        if ($f.Count -lt 100) { break }
    }
    return ,$all.ToArray()
}
$results = [ordered]@{ dtVersion = $ver; trivyImage = $dig; projects = [ordered]@{} }
foreach ($p in ($projects | Sort-Object name)) {
    $entry = [ordered]@{}
    try { $f = All-Findings $p.uuid
          $entry.findings = $f.Count
          $byA = [ordered]@{}; $by = [ordered]@{}
          foreach ($x in $f) {
              $a = "$($x.attribution.analyzerIdentity)"; if (-not $a) { $a = 'unknown' }
              if (-not $byA.Contains($a)) { $byA[$a] = 0 }; $byA[$a]++
              $k = "$($x.component.name)@$($x.component.version)"; if (-not $by.Contains($k)) { $by[$k] = @() }
              $by[$k] += "$($x.vulnerability.source):$($x.vulnerability.vulnId) [$a]"
          }
          $entry.byAnalyzer = $byA; $entry.byComponent = $by
          $entry.sources = @($f | ForEach-Object { $_.vulnerability.source } | Sort-Object -Unique)
          if ($f.Count -gt 0) { $entry.sampleFinding = $f[0] } } catch { $entry.findingsError = ErrText $_ }
    $results.projects[$p.name] = $entry
    Log "$($p.name): findings=$($entry.findings) byAnalyzer=$(J $entry.byAnalyzer)"
}
$results | ConvertTo-Json -Depth 12 | Set-Content -Path (Join-Path $Dir 'trivy-results.json') -Encoding UTF8
$mins = [int][Math]::Ceiling(((Get-Date) - $t0).TotalMinutes) + 1
docker logs --since "$($mins)m" dt5-test-apiserver-1 2>&1 | Where-Object { "$_" -match '(?i)trivy|ossindex|oss-index' } | Select-Object -Last 25 | ForEach-Object { Log "apiserver-log: $_" }
docker logs --since "$($mins)m" dt5-test-trivy-1 2>&1 | Select-Object -Last 15 | ForEach-Object { Log "trivy-log: $_" }

# ---------- stop ----------
Status 'stopping'
docker compose -f (Join-Path $Dir 'compose.yaml') stop 2>&1 | ForEach-Object { Log "compose: $_" }
Log 'DONE - containers stopped; images and data volumes (incl. Trivy DB cache) kept.'
Status 'done'
