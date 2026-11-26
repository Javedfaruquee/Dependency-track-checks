# Dependency-Track v5: adds the NVD feed adapter (NIST feeds + VulnCheck NVD++ CPEs for CVEs NIST left without CPEs),
# proves the effect with a C++ "gap" SBOM before/after, points DT's NVD source at the adapter, writes nvdpp-results.json,
# then stops the containers (images and data volumes kept). The VulnCheck token is typed here and kept in .env.
# Images and data volumes are kept, so a re-run reuses the mirrored NVD data.

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$Dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Log = Join-Path $Dir 'nvdpp-log.txt'
$Api = 'http://localhost:8081'
$NewPw = 'DtTest-2026!'

function Log([string]$m) { $l = "$(Get-Date -Format 'HH:mm:ss') $m"; Write-Host $l; Add-Content -Path $Log -Value $l -Encoding UTF8 }
function Status([string]$s) { @{ stage = $s; time = (Get-Date).ToString('s') } | ConvertTo-Json | Set-Content -Path (Join-Path $Dir 'nvdpp-status.json') -Encoding UTF8 }
function ErrText($e) { $t = $e.Exception.Message; if ($e.ErrorDetails -and $e.ErrorDetails.Message) { $t += ' | ' + $e.ErrorDetails.Message }; return $t }
function J($o) { return ($o | ConvertTo-Json -Depth 10 -Compress) }
# Windows PowerShell 5.1 returns JSON arrays from Invoke-RestMethod as ONE object; flatten to real items
function Items($x) { $o = New-Object System.Collections.ArrayList; foreach ($i in @($x)) { if ($i -is [System.Array]) { foreach ($j in $i) { [void]$o.Add($j) } } elseif ($null -ne $i) { [void]$o.Add($i) } }; return ,$o.ToArray() }

Set-Content -Path $Log -Value "dt5 NVD feed adapter setup started $(Get-Date -Format s)" -Encoding UTF8
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


# ---------- VulnCheck token for the adapter (.env) ----------
$envLines = @(); if (Test-Path $envFile) { $envLines = @(Get-Content $envFile | Where-Object { $_ -notmatch '^VULNCHECK_TOKEN=' }) }
$hasVc = $false; if (Test-Path $envFile) { $hasVc = [bool](Get-Content $envFile | Where-Object { $_ -match '^VULNCHECK_TOKEN=.+' }) }
$ask = $true
if ($hasVc) { $ans = Read-Host 'A VulnCheck token is already stored in .env. Press Enter to keep it, or type N to enter a new one'; if ($ans -notmatch '^[Nn]') { $ask = $false } }
if ($ask) {
    $ss = Read-Host 'VulnCheck API token (input hidden)' -AsSecureString
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
    try { $vt = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
    if (-not $vt) { Log 'FAILED: no VulnCheck token entered'; Status 'failed-no-token'; exit 1 }
    $envLines += "VULNCHECK_TOKEN=$vt"; $vt = $null
    Set-Content -Path $envFile -Value $envLines -Encoding ASCII
    Log 'VulnCheck token stored in .env (not logged)'
} else { Log 'keeping the VulnCheck token from .env' }

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



# ---------- wait for the adapter to digest VulnCheck data and build the modified feed ----------
Status 'adapter'
$st = $null; $lastP = ''
$deadline = (Get-Date).AddMinutes(75)
while ((Get-Date) -lt $deadline) {
    try { $st = Invoke-RestMethod -Uri 'http://127.0.0.1:8090/stats' -TimeoutSec 10
          $p = "$($st.phase) | $(J $st.progress)"
          if ($p -ne $lastP) { Log "adapter: $p"; $lastP = $p; Status "adapter $($st.phase)" }
          if ($st.phase -eq 'ready' -or $st.phase -eq 'error') { break } } catch { }
    Start-Sleep 15
}
docker logs --tail 25 dt5-test-nvdpp-1 2>&1 | ForEach-Object { Log "nvdpp-log: $_" }
if (-not $st -or $st.phase -ne 'ready') { Log 'FAILED: adapter not ready'; Status 'failed-adapter'; docker compose -f (Join-Path $Dir 'compose.yaml') stop 2>&1 | Out-Null; exit 1 }
Log "VulnCheck: $(J $st.vulncheck)"
Log "modified feed: $(J $st.modified_feed)"
if ($st.vulncheck.status -ne 'loaded') {
    Log 'VulnCheck data not loaded - DT stays on nvd.nist.gov. See the error above.'
    Status 'failed-vulncheck'; docker compose -f (Join-Path $Dir 'compose.yaml') stop 2>&1 | Out-Null; exit 1
}

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



function All-Findings($uuid) {
    $all = New-Object System.Collections.ArrayList
    for ($pg = 1; $pg -le 30; $pg++) {
        $f = Items (Api 'GET' "/api/v1/finding/project/$($uuid)?suppressed=true&pageSize=100&pageNumber=$pg")
        foreach ($x in $f) { [void]$all.Add($x) }
        if ($f.Count -lt 100) { break }
    }
    return ,$all.ToArray()
}
function Collect($proj) {
    $entry = [ordered]@{}
    $f = All-Findings $proj.uuid
    $entry.findings = $f.Count
    $byA = [ordered]@{}; $ids = @()
    foreach ($x in $f) { $a = "$($x.attribution.analyzerIdentity)"; if (-not $byA.Contains($a)) { $byA[$a] = 0 }; $byA[$a]++; $ids += "$($x.component.name)@$($x.component.version) $($x.vulnerability.vulnId)" }
    $entry.byAnalyzer = $byA; $entry.items = $ids
    return $entry
}

# ---------- gap test SBOM: C/C++ components affected by CVEs that NIST left without CPEs ----------
Status 'gap-sbom'
$ex = @(Items $st.vulncheck.cpp_examples)
Log "C/C++ examples from VulnCheck: $(J $ex)"
$gapProj = $null; $before = $null
if ($ex.Count -gt 0) {
    $comps = @(); $seen = @{}
    foreach ($e in $ex) { $k = "$($e.product)@$($e.version)"; if ($seen[$k]) { continue }; $seen[$k] = 1
        $comps += [ordered]@{ type = 'library'; 'bom-ref' = $k; group = $e.vendor; name = $e.product; version = $e.version; cpe = $e.cpe } }
    $bom = [ordered]@{ bomFormat = 'CycloneDX'; specVersion = '1.6'; serialNumber = "urn:uuid:$([guid]::NewGuid())"; version = 1
        metadata = [ordered]@{ component = [ordered]@{ type = 'application'; name = 'cpp-nvd-gap'; version = '1' } }; components = $comps }
    $json = $bom | ConvertTo-Json -Depth 10
    [IO.File]::WriteAllText((Join-Path $Dir 'sboms\cpp-nvd-gap.cdx.json'), $json)
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
    try { $r = Api 'PUT' '/api/v1/bom' @{ projectName = 'cpp-nvd-gap'; projectVersion = '1'; autoCreate = $true; bom = $b64 }; Log "uploaded cpp-nvd-gap ($($comps.Count) components, CPE only): $(J $r)" } catch { Log "upload cpp-nvd-gap FAILED: $(ErrText $_)" }
    Start-Sleep 60
    $gapProj = Items (Api 'GET' '/api/v1/project?name=cpp-nvd-gap&pageSize=10') | Where-Object { $_.name -eq 'cpp-nvd-gap' } | Select-Object -First 1
    if ($gapProj) { try { Api 'POST' "/api/v1/finding/project/$($gapProj.uuid)/analyze" | Out-Null } catch { }; Start-Sleep 60; $before = Collect $gapProj; Log "BEFORE (NIST data only): cpp-nvd-gap findings=$($before.findings) $(J $before.items)" }
} else { Log 'no C/C++ examples among the CVEs VulnCheck fills in; skipping the gap SBOM' }

# ---------- point DT's NVD source at the adapter and mirror ----------
Status 'switch-nvd'
Set-ExtConfig 'vuln-data-source' 'nvd' @{ enabled = $true; cveFeedsUrl = 'http://nvdpp:8080/feeds' }
$prev = $null; try { $prev = (Api 'GET' '/api/v2/vuln-data-sources/nvd/mirror-runs/latest').started_at } catch { }
try { Api 'POST' '/api/v2/vuln-data-sources/nvd/mirror-runs' | Out-Null; Log 'nvd mirror triggered' } catch { Log "nvd trigger: $(ErrText $_)" }
$t0 = Get-Date; $run = $null; $last = ''
while (((Get-Date) - $t0).TotalMinutes -lt 45) {
    Start-Sleep 15
    try { $run = Api 'GET' '/api/v2/vuln-data-sources/nvd/mirror-runs/latest'; $s = J $run
          if ($s -ne $last) { Log "nvd mirror: $s"; $last = $s; Status "nvd-mirror $($run.status)" }
          if ("$($run.started_at)" -ne "$prev" -and "$($run.status)" -match '(?i)complet|fail|error|cancel') { break } } catch { Log "nvd mirror status: $(ErrText $_)" }
}
$mins = [int][Math]::Ceiling(((Get-Date) - $t0).TotalMinutes) + 1
docker logs --since "$($mins)m" dt5-test-apiserver-1 2>&1 | Where-Object { "$_" -match '(?i)NvdVulnDataSource|vulnDataSourceName=nvd' } | Select-Object -Last 20 | ForEach-Object { Log "apiserver-log: $_" }
docker logs --since "$($mins)m" dt5-test-nvdpp-1 2>&1 | Select-Object -Last 15 | ForEach-Object { Log "nvdpp-log: $_" }

# ---------- re-analyse everything and collect ----------
Status 'collect'
$projects = @(); try { $projects = Items (Api 'GET' '/api/v1/project?pageSize=100') } catch { }
foreach ($p in $projects) { try { Api 'POST' "/api/v1/finding/project/$($p.uuid)/analyze" | Out-Null } catch { } }
Log 'waiting 240 s for re-analysis'
Start-Sleep 240
$results = [ordered]@{ adapter = $st; nvdMirror = $run; gapBefore = $before; projects = [ordered]@{} }
foreach ($p in ($projects | Sort-Object name)) {
    try { $e = Collect $p; $results.projects[$p.name] = $e; Log "$($p.name): findings=$($e.findings) byAnalyzer=$(J $e.byAnalyzer)" } catch { Log "collect $($p.name): $(ErrText $_)" }
}
if ($results.projects.Contains('cpp-nvd-gap')) { Log "AFTER (NIST + VulnCheck CPEs): cpp-nvd-gap $(J $results.projects['cpp-nvd-gap'].items)" }
$results | ConvertTo-Json -Depth 12 | Set-Content -Path (Join-Path $Dir 'nvdpp-results.json') -Encoding UTF8

# ---------- stop ----------
Status 'stopping'
docker compose -f (Join-Path $Dir 'compose.yaml') stop 2>&1 | ForEach-Object { Log "compose: $_" }
Log 'DONE - containers stopped; images and data volumes kept. DT now reads NVD through the adapter (http://nvdpp:8080/feeds).'
Status 'done'
