# Dependency-Track v5 C++ SBOM test (Windows PowerShell 5.1 compatible)
# Starts DT v5 in Docker Desktop, mirrors live NVD + OSV data, uploads the test SBOMs,
# writes results.json / log.txt next to this script, then stops the containers.
# Images and data volumes are kept, so a re-run reuses the mirrored NVD data.

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$Dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Log = Join-Path $Dir 'log.txt'
$Api = 'http://localhost:8081'
$NewPw = 'DtTest-2026!'

function Log([string]$m) { $l = "$(Get-Date -Format 'HH:mm:ss') $m"; Write-Host $l; Add-Content -Path $Log -Value $l -Encoding UTF8 }
function Status([string]$s) { @{ stage = $s; time = (Get-Date).ToString('s') } | ConvertTo-Json | Set-Content -Path (Join-Path $Dir 'status.json') -Encoding UTF8 }
function ErrText($e) { $t = $e.Exception.Message; if ($e.ErrorDetails -and $e.ErrorDetails.Message) { $t += ' | ' + $e.ErrorDetails.Message }; return $t }
function J($o) { return ($o | ConvertTo-Json -Depth 10 -Compress) }
# Windows PowerShell 5.1 returns JSON arrays from Invoke-RestMethod as ONE object; flatten to real items
function Items($x) { $o = New-Object System.Collections.ArrayList; foreach ($i in @($x)) { if ($i -is [System.Array]) { foreach ($j in $i) { [void]$o.Add($j) } } elseif ($null -ne $i) { [void]$o.Add($i) } }; return ,$o.ToArray() }

Set-Content -Path $Log -Value "dt5 test started $(Get-Date -Format s)" -Encoding UTF8
Status 'starting'

# ---------- 1. Docker Desktop ----------
Status 'docker-check'
$ok = $false
for ($i = 0; $i -lt 2; $i++) {
    $v = (docker version --format '{{.Server.Version}}' 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -eq 0) { Log "Docker engine $v"; $ok = $true; break }
    if ($i -eq 0) {
        $dd = Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
        if (Test-Path $dd) { Log 'Docker engine not running - starting Docker Desktop'; Start-Process $dd } else { Log 'Docker Desktop.exe not found' }
        for ($w = 0; $w -lt 36; $w++) { Start-Sleep 5; docker info *> $null; if ($LASTEXITCODE -eq 0) { break } }
    }
}
if (-not $ok) { Log 'FAILED: Docker engine not reachable'; Status 'failed-docker'; exit 1 }

# ---------- 2. Network check from this laptop ----------
foreach ($u in @('https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.meta',
                 'https://osv-vulnerabilities.storage.googleapis.com/PyPI/modified_id.csv',
                 'https://ghcr.io/v2/')) {
    try { $r = Invoke-WebRequest -Uri $u -Method Head -UseBasicParsing -TimeoutSec 30; Log "net ok   $($r.StatusCode) $u" }
    catch { Log "net FAIL $u :: $(ErrText $_)" }
}

# ---------- 3. Start the stack ----------
Status 'compose-up'
docker compose -f (Join-Path $Dir 'compose.yaml') up -d 2>&1 | ForEach-Object { Log "compose: $_" }
docker compose -f (Join-Path $Dir 'compose.yaml') ps 2>&1 | ForEach-Object { Log "ps: $_" }
$up = $false
for ($i = 0; $i -lt 120; $i++) {
    try { $ver = Invoke-RestMethod -Uri "$Api/api/version" -TimeoutSec 5; Log "API up: $(J $ver)"; $up = $true; break } catch { Start-Sleep 5 }
}
if (-not $up) {
    docker compose -f (Join-Path $Dir 'compose.yaml') logs --tail 80 apiserver 2>&1 | ForEach-Object { Log "apiserver-log: $_" }
    Log 'FAILED: API server did not come up'; Status 'failed-api'; exit 1
}

# ---------- 4. Log in ----------
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

# ---------- 5. Configure NVD and OSV (live feeds) ----------
Status 'configure'
$ep = $null
try { $eps = Api 'GET' '/api/v2/extension-points'; Log "extension points: $(J $eps)"
      $names = @(); foreach ($x in @($eps.items) + @($eps)) { if ($x.name) { $names += $x.name } }
      $ep = $names | Where-Object { $_ -match 'vuln' -and $_ -match 'source' } | Select-Object -First 1 }
catch { Log "extension-points: $(ErrText $_)" }
if (-not $ep) { $ep = 'vuln.data.source'; Log "falling back to extension point name $ep" } else { Log "vuln data source extension point: $ep" }
try { $ex = Api 'GET' "/api/v2/extension-points/$ep/extensions"; Log "extensions: $(J $ex)" } catch { Log "extensions: $(ErrText $_)" }

foreach ($src in @('nvd', 'osv')) {
    $cfg = $null
    try { $schema = Api 'GET' "/api/v2/extension-points/$ep/extensions/$src/config-schema"; Log "$src schema: $(J $schema)" } catch { Log "$src schema: $(ErrText $_)" }
    try { $cur = Api 'GET' "/api/v2/extension-points/$ep/extensions/$src/config"; Log "$src current config: $(J $cur)"; if ($cur.config) { $cfg = $cur.config } else { $cfg = $cur } } catch { Log "$src get config: $(ErrText $_)" }
    $h = @{}
    if ($cfg) { $cfg.PSObject.Properties | ForEach-Object { $h[$_.Name] = $_.Value } }
    $h['enabled'] = $true
    if ($src -eq 'osv') { $h['ecosystems'] = @('PyPI') }
    $needPut = $true; if ($cfg -and $cfg.enabled -eq $true -and ($src -ne 'osv' -or ((@($cfg.ecosystems) -join ',') -eq 'PyPI'))) { $needPut = $false; Log "$src already configured" }
    if ($needPut) { try { $res = Api 'PUT' "/api/v2/extension-points/$ep/extensions/$src/config" @{ config = $h }; Log "$src config set: $(J $res)" }
    catch { Log "$src set config: $(ErrText $_)" } }
}

# ---------- 6. Mirror vulnerability data ----------
foreach ($src in @('osv', 'nvd')) {
    Status "mirror-$src"
    try { $r = Api 'POST' "/api/v2/vuln-data-sources/$src/mirror-runs"; Log "$src mirror triggered: $(J $r)" } catch { Log "$src trigger (may already be running): $(ErrText $_)" }
    $deadline = (Get-Date).AddMinutes($(if ($src -eq 'nvd') { 150 } else { 30 }))
    $last = ''
    while ((Get-Date) -lt $deadline) {
        Start-Sleep 30
        try {
            $run = Api 'GET' "/api/v2/vuln-data-sources/$src/mirror-runs/latest"; $s = J $run
            if ($s -ne $last) { Log "$src mirror: $s"; $last = $s }
            $st = "$($run.status)$($run.state)"
            if ($st -match '(?i)complet|succe|fail|error|cancel|abort') { break }
            if ($run.completed_at -or $run.completedAt -or $run.finished_at -or $run.finishedAt -or $run.ended_at) { break }
        } catch { Log "$src mirror status: $(ErrText $_)" }
    }
}

# ---------- 7. Upload SBOMs ----------
Status 'upload'
$sbomDir = Join-Path $Dir 'sboms'
$uploads = [ordered]@{
    'python-control'         = 'python-control.cdx.json'
    'conan-native'           = 'cpp-conan-native.cdx.json'
    'conan-normalised'       = 'cpp-conan-normalised.cdx.json'
    'vcpkg-spdx-zlib-direct' = 'vcpkg-zlib.spdx.json'
    'vcpkg-native'           = 'cpp-vcpkg-native.cdx.json'
    'vcpkg-normalised'       = 'cpp-vcpkg-normalised.cdx.json'
    'vendored-syft'          = 'cpp-vendored-syft.cdx.json'
    'vendored-declared'      = 'cpp-vendored-declared.cdx.json'
}
$uploadResult = [ordered]@{}
foreach ($name in $uploads.Keys) {
    $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $sbomDir $uploads[$name])))
    try { $r = Api 'PUT' '/api/v1/bom' @{ projectName = $name; projectVersion = '1'; autoCreate = $true; bom = $b64 }; Log "uploaded $name : $(J $r)"; $uploadResult[$name] = 'accepted' }
    catch { $t = ErrText $_; Log "upload $name FAILED: $t"; $uploadResult[$name] = "rejected: $t" }
}
Log 'waiting 120 s for BOM processing and analysis'
Start-Sleep 120

# ---------- 8. Re-analyse and collect findings ----------
Status 'collect'
$projects = @()
try { $projects = Items (Api 'GET' '/api/v1/project?pageSize=100') } catch { Log "projects: $(ErrText $_)" }
foreach ($p in $projects) { try { Api 'POST' "/api/v1/finding/project/$($p.uuid)/analyze" | Out-Null } catch { Log "analyze $($p.name): $(ErrText $_)" } }
Log 'waiting 120 s for re-analysis'
Start-Sleep 120
$results = [ordered]@{ dtVersion = $ver; uploads = $uploadResult; projects = [ordered]@{} }
foreach ($p in ($projects | Sort-Object name)) {
    $entry = [ordered]@{}
    try { $comps = Items (Api 'GET' "/api/v1/component/project/$($p.uuid)?pageSize=500")
          $entry.components = $comps.Count
          $entry.componentList = @($comps | ForEach-Object { "$($_.name)@$($_.version) purl=$($_.purl) cpe=$($_.cpe)" }) } catch { $entry.componentsError = ErrText $_ }
    try { $f = Items (Api 'GET' "/api/v1/finding/project/$($p.uuid)?suppressed=true")
          $entry.findings = $f.Count
          $by = [ordered]@{}
          foreach ($x in $f) { $k = "$($x.component.name)@$($x.component.version)"; if (-not $by.Contains($k)) { $by[$k] = @() }; $by[$k] += $x.vulnerability.vulnId }
          $entry.byComponent = $by
          $entry.sources = @($f | ForEach-Object { $_.vulnerability.source } | Sort-Object -Unique) } catch { $entry.findingsError = ErrText $_ }
    try { $vex = Api 'GET' "/api/v1/vex/cyclonedx/project/$($p.uuid)"; $entry.vexExport = "ok, specVersion $($vex.specVersion)" } catch { $entry.vexExport = ErrText $_ }
    $results.projects[$p.name] = $entry
    Log "$($p.name): components=$($entry.components) findings=$($entry.findings)"
}
$results | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $Dir 'results.json') -Encoding UTF8

# ---------- 9. Stop containers, keep images and volumes ----------
Status 'stopping'
docker compose -f (Join-Path $Dir 'compose.yaml') stop 2>&1 | ForEach-Object { Log "compose: $_" }
Log 'DONE - containers stopped; images and data volumes kept. Restart later with: docker compose up -d (in this folder)'
Status 'done'
