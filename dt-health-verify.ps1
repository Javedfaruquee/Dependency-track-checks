# Gap 2 check on the real Dependency-Track 5.2.2 stack: vulnerability data must not stop silently.
#  0. Upgrades the test stack to DT 5.2.2 (compose.yaml pins it; data volumes are kept), the NVD feed adapter
#     first (DT 5.2.2 must not mirror against adapter 2.1), and points DT's ENISA
#     EU KEV source at the feed's new address (ENISA moved it on 2026-11-16; DT keeps the URL it stored at
#     first start, so the upgrade alone does not fix it).
#  1. Loads the NVD feed adapter 2.2 (restart; caches and volumes are kept), runs every enabled mirror once,
#     and creates two health keys: a read-only one (5 permissions) and one that may also run DT's live
#     extension tests (SYSTEM_CONFIGURATION_UPDATE).
#     It also sets up DT's own alert for failed mirrors (a webhook rule) with a small receiver container.
#  2. Baseline: cpp-sboms/ci/dt-health-check.py must PASS with both keys (canary included).
#  3. Injects one real fault at a time, checks that the health check reports it, and restores it:
#       stale threshold, OSS Index token revoked, Trivy analyzer disabled, Trivy server stopped,
#       NVD feed adapter stopped (DT's own alert must arrive too), VulnCheck token rejected by VulnCheck.
#     Each fault is also confirmed from another source where one exists (DT's admin API, docker, the logs).
#  4. Load: uploads 150 test projects at once (a release-day burst), runs the check during the backlog,
#     compares its API calls with the baseline, then deletes the test projects.
#  5. Final run must PASS again. Only then commits the gap 2 files and pushes them to GitHub.
# Everything changed is put back in 'finally', also after a failure, and again at the next start if the
# window was closed (restore files in dt-health-verify/, leftover health-* teams). Tokens are never printed.
# The admin password below is the local test stack's (bound to localhost); never point this at a shared DT.
# Results: dt-health-verify-results.json and dt-health-verify-log.txt.

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$Dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Log = Join-Path $Dir 'dt-health-verify-log.txt'
$ResultsFile = Join-Path $Dir 'dt-health-verify-results.json'
$Api = 'http://localhost:8081'
$Adapter = 'http://localhost:8090'
$NewPw = 'DtTest-2026!'
$Work = Join-Path $Dir 'dt-health-verify'
$Compose = Join-Path $Dir 'compose.yaml'
$FaultYaml = Join-Path $Work 'fault-vulncheck.yaml'
$Py = 'python:3.13-slim'
$ReadPerms = @('VIEW_PORTFOLIO', 'VIEW_VULNERABILITY', 'SYSTEM_CONFIGURATION_READ', 'BOM_UPLOAD', 'PROJECT_CREATION_UPLOAD')
$TestPerms = $ReadPerms + @('SYSTEM_CONFIGURATION_UPDATE')
$RevokedSecret = 'DT_HEALTH_VERIFY_REVOKED'
$Receiver = 'dt-health-receiver'
$LoadProjects = 150
$LoadComponents = 60
$DtVersion = '5.2.2'
$EnisaOldUrl = 'https://raw.githubusercontent.com/enisaeu/CNW/main/advisories/eukev/eukev.json'
$EnisaNewUrl = 'https://raw.githubusercontent.com/enisaeu/CNW/main/eukev/eukev.json'
New-Item -ItemType Directory -Force -Path $Work | Out-Null
Remove-Item -Force -ErrorAction SilentlyContinue $ResultsFile, (Join-Path $Work 'baseline*.json'), (Join-Path $Work 'fault-*.json'), (Join-Path $Work 'final*.json'), (Join-Path $Work 'load*.json'), (Join-Path $Work 'state*.json'), (Join-Path $Work 'received.jsonl')

function Log([string]$m) { $l = "$(Get-Date -Format 'HH:mm:ss') $m"; Write-Host $l; Add-Content -Path $Log -Value $l -Encoding UTF8 }
function Status([string]$s) { @{ stage = $s; time = (Get-Date).ToString('s') } | ConvertTo-Json | Set-Content -Path (Join-Path $Dir 'dt-health-verify-status.json') -Encoding UTF8 }
function ErrText($e) { $t = $e.Exception.Message; if ($e.ErrorDetails -and $e.ErrorDetails.Message) { $t += ' | ' + $e.ErrorDetails.Message }; return $t }
function J($o) { return (ConvertTo-Json -InputObject $o -Depth 10 -Compress) }   # -InputObject: a one-item array stays an array
function Items($x) { $o = New-Object System.Collections.ArrayList; foreach ($i in @($x)) { if ($i -is [System.Array]) { foreach ($j in $i) { [void]$o.Add($j) } } elseif ($null -ne $i) { [void]$o.Add($i) } }; return ,$o.ToArray() }
function Canon($o) { if ($null -eq $o) { return '' }; return (($o.PSObject.Properties | Sort-Object Name | ForEach-Object { "$($_.Name)=$(J $_.Value)" }) -join ';') }
function Call([hashtable]$headers, [string]$method, [string]$path, $body = $null, [int]$timeout = 120) {
    $req = @{ Method = $method; Uri = "$Api$path"; Headers = $headers; TimeoutSec = $timeout }
    if ($null -ne $body) { $req.Body = [Text.Encoding]::UTF8.GetBytes((J $body)); $req.ContentType = 'application/json' }
    elseif ($method -eq 'POST' -or $method -eq 'PUT') { $req.ContentType = 'application/json' }   # DT @Consumes(JSON) answers 415 without it
    return Invoke-RestMethod @req
}
function Code($e) { if ($e.Exception.Response) { return [int]$e.Exception.Response.StatusCode }; return 0 }
function Paged([hashtable]$headers, [string]$path) {
    $all = New-Object System.Collections.ArrayList; $seen = @{}; $sep = '?'; if ($path.Contains('?')) { $sep = '&' }
    for ($pg = 1; $pg -le 200; $pg++) {
        $r = Items (Call $headers 'GET' "$path$($sep)pageSize=100&pageNumber=$pg"); $new = 0
        foreach ($x in $r) { $k = J $x; if (-not $seen.ContainsKey($k)) { $seen[$k] = 1; [void]$all.Add($x); $new++ } }
        if ($r.Count -lt 100 -or $new -eq 0) { break }
    }
    return ,$all.ToArray()
}
function Py([string[]]$a) {
    $net = ((docker inspect dt5-test-apiserver-1 -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>$null | Select-Object -First 1) -split ' ')[0]
    $out = docker run --rm --network $net -e DT_API_KEY -v "${Dir}:/w" -w /w $Py python -I @a 2>&1
    $code = $LASTEXITCODE
    $out | ForEach-Object { Log "  py: $_" }
    return $code
}
function GitStep([string[]]$a) {   # not 'Git': PowerShell names are case-insensitive, it would call itself
    $out = git -C $Dir @a 2>&1
    $code = $LASTEXITCODE
    $out | ForEach-Object { Log "  git: $_" }
    return $code
}
function AdapterHealth {
    try { $r = Invoke-WebRequest -UseBasicParsing -Uri "$Adapter/health" -TimeoutSec 30; return @{ code = [int]$r.StatusCode; body = ($r.Content | ConvertFrom-Json) } }
    catch {
        $code = Code $_; $body = $null
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { try { $body = $_.ErrorDetails.Message | ConvertFrom-Json } catch { } }
        if (-not $body -and $_.Exception.Response) { try { $sr = New-Object IO.StreamReader($_.Exception.Response.GetResponseStream()); $body = $sr.ReadToEnd() | ConvertFrom-Json } catch { } }
        return @{ code = $code; body = $body }
    }
}
function Wait-AdapterAlive([int]$maxSec = 300) {
    $deadline = (Get-Date).AddSeconds($maxSec)
    while ((Get-Date) -lt $deadline) { try { Invoke-WebRequest -UseBasicParsing -Uri "$Adapter/healthz" -TimeoutSec 5 | Out-Null; return $true } catch { Start-Sleep 3 } }
    return $false
}
function Wait-AdapterHealthy([int]$maxSec = 2700) {
    $deadline = (Get-Date).AddSeconds($maxSec); $last = $null; $n = 0
    while ((Get-Date) -lt $deadline) {
        $h = AdapterHealth; $last = $h
        if ($h.code -eq 200 -and $h.body -and -not $h.body.building) { return $h }
        if (($n % 8) -eq 0) { $p = ''; if ($h.body) { $p = (Items $h.body.problems) -join ' | '; if ($h.body.phase) { $p = "phase $($h.body.phase); $p" } }; Log "  adapter /health $($h.code): $p" }
        $n++; Start-Sleep 15
    }
    return $last
}
function Mirror([string]$ep, [string]$name, [int]$maxSec = 2700) {
    # not a variable named api: PowerShell names are case-insensitive, it would hide the DT URL from Call
    $src = 'vuln-data-sources'; if ($ep -eq 'kev-data-source') { $src = 'kev-data-sources' }
    # compare with the run before, not with this computer's clock (Docker Desktop's VM clock can drift)
    $before = $null; try { $before = Call $adminH 'GET' "/api/v2/$src/$name/mirror-runs/latest" } catch { }
    $prev = ''; if ($before) { $prev = "$($before.started_at)|$($before.status)" }
    $fresh = $true
    try { Call $adminH 'POST' "/api/v2/$src/$name/mirror-runs" | Out-Null }
    catch { if ((Code $_) -eq 409) { $fresh = $false; Log "  $ep/$name already mirroring; waiting for that run" } else { Log "  $ep/$name trigger failed: $(ErrText $_)"; return $null } }
    $deadline = (Get-Date).AddSeconds($maxSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Call $adminH 'GET' "/api/v2/$src/$name/mirror-runs/latest"
            $now = "$($r.started_at)|$($r.status)"
            if (($r.status -eq 'COMPLETED' -or $r.status -eq 'FAILED') -and ((-not $fresh) -or ($now -ne $prev -and "$($r.started_at)" -ne "$($before.started_at)"))) { return $r }
        } catch { }
        Start-Sleep 10
    }
    return $null
}
function GetCfg([string]$ep, [string]$name) { return (Call $adminH 'GET' "/api/v2/extension-points/$ep/extensions/$name/config").config }
function SaveRestore([string]$ep, [string]$name, $cfg) { $cfg | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $Work "restore-$ep-$name.json") -Encoding UTF8 }
function DropRestore([string]$ep, [string]$name) { Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $Work "restore-$ep-$name.json") }
function AdapterRebuild([string]$query) {   # forcing or accepting needs POST with this header (adapter 2.1 and later)
    return Invoke-RestMethod -Method Post -Uri "$Adapter/rebuild?$query" -Headers @{ 'X-NVDPP-Rebuild' = '1' } -ContentType 'text/plain' -Body '' -TimeoutSec 3600
}
function Wait-AdapterIdle([int]$maxSec = 2700) {
    $deadline = (Get-Date).AddSeconds($maxSec)
    while ((Get-Date) -lt $deadline) { $h = AdapterHealth; if ($h.body -and -not $h.body.building) { return $h }; Start-Sleep 5 }
    return AdapterHealth
}
function PutCfg([string]$ep, [string]$name, $cfg) {
    $h = [ordered]@{}; $cfg.PSObject.Properties | ForEach-Object { $h[$_.Name] = $_.Value }
    try { Call $adminH 'PUT' "/api/v2/extension-points/$ep/extensions/$name/config" @{ config = $h } | Out-Null } catch { if ((Code $_) -ne 304) { throw } }
}
function WithChange($cfg, [string]$key, $value) { $c = $cfg | ConvertTo-Json -Depth 10 | ConvertFrom-Json; $c | Add-Member -NotePropertyName $key -NotePropertyValue $value -Force; return $c }

$checks = New-Object System.Collections.ArrayList
$runs = [ordered]@{}
function Check([string]$name, [bool]$ok, $expected, $got) {
    [void]$checks.Add([ordered]@{ check = $name; expected = "$expected"; got = "$got"; ok = $ok })
    Log ("{0} {1}: expected {2}, got {3}" -f $(if ($ok) { 'ok  ' } else { 'FAIL' }), $name, $expected, $got)
}
function Health([string]$label, [string]$key, [string[]]$extra) {
    $env:DT_API_KEY = $key   # passed to the container by name only (docker run -e DT_API_KEY)
    $rpt = "dt-health-verify/$label.json"
    $stf = 'dt-health-verify/state.json'; if ($label -like 'fault-*' -or $label -like 'load*') { $stf = 'dt-health-verify/state-faults.json' }
    $a = @('cpp-sboms/ci/dt-health-check.py', '--url', 'http://apiserver:8080', '--allow-http', '--config', 'cpp-sboms/ci/health/dt-health.json',
           '--report', $rpt, '--state', $stf) + $extra
    Log "health check '$label' $($extra -join ' ')"
    $t = Get-Date
    $code = Py $a
    $rep = $null; try { $rep = Get-Content (Join-Path $Dir $rpt) -Raw | ConvertFrom-Json } catch { }
    $runs[$label] = [ordered]@{ exit = $code; result = $(if ($rep) { $rep.result } else { 'no report' }); seconds = [int]((Get-Date) - $t).TotalSeconds
                               apiCalls = $(if ($rep) { $rep.apiCalls } else { $null })
                               problems = @(Problems $rep '' '' '' | ForEach-Object { "$($_.area)/$($_.name): $($_.detail)" }); canary = $(if ($rep) { $rep.canary } else { $null }) }
    return @{ code = $code; rep = $rep }
}
function Problems($rep, [string]$area, [string]$name, [string]$pattern) {
    if (-not $rep) { return @() }
    return @((Items $rep.checks) | Where-Object { $_.status -eq 'problem' -and ($area -eq '' -or $_.area -eq $area) -and ($name -eq '' -or $_.name -eq $name) -and ($pattern -eq '' -or "$($_.detail)" -match $pattern) })
}
function Summ($h) {
    if (-not $h.rep) { return "exit $($h.code), no report" }
    $p = @(Problems $h.rep '' '' '' | ForEach-Object { "$($_.area)/$($_.name): $($_.detail)" })
    return "exit $($h.code), $($h.rep.result)" + $(if ($p.Count) { '; ' + ($p -join ' | ') } else { '' })
}
function CanaryOk($rep) { if (-not $rep) { return 0 }; return @((Items $rep.checks) | Where-Object { $_.area -eq 'canary' -and $_.name -ne 'analysis-latency' -and $_.status -eq 'ok' }).Count }
function NewTeam([string]$name, [string[]]$perms) {
    $t = Call $adminH 'PUT' '/api/v1/team' @{ name = $name }
    $script:teams += $t
    foreach ($perm in $perms) { Call $adminH 'POST' "/api/v1/permission/$perm/team/$($t.uuid)" | Out-Null }
    $k = Call $adminH 'PUT' "/api/v1/team/$($t.uuid)/key"
    $key = $k.key; if (-not $key) { $key = $k.secret }
    $kid = $k.publicId; if (-not $kid) { $kid = $key }
    if (-not $key) { throw "no API key for team $name" }
    $script:keyIds += $kid
    Log "team $name with $($perms -join ', ')"
    return $key
}

Set-Content -Path $Log -Value "Gap 2 (vulnerability data health) check started $(Get-Date -Format s)" -Encoding UTF8
Status 'starting'
$adminH = $null; $teams = @(); $keyIds = @(); $result = 'FAIL'; $pushed = $false
$ossOrig = $null; $trivyOrig = $null; $secretMade = $false; $trivyStopped = $false; $nvdppStopped = $false; $nvdppFault = $false
$ruleUuid = $null; $receiverUp = $false; $loadUuids = @()
try {
    # ---------- the adapter 2.2 first: DT 5.2.2 reads only "modified" on its daily mirrors, and a rewrite it misses
    # while an older adapter serves the feeds does not come back. So DT starts only once 2.2 has built "modified". ----------
    Status 'adapter'
    docker compose -f $Compose up -d nvdpp 2>&1 | ForEach-Object { Log "compose: $_" }
    docker compose -f $Compose restart nvdpp 2>&1 | ForEach-Object { Log "compose: $_" }   # loads the mounted code; caches stay
    if (-not (Wait-AdapterAlive)) { throw 'the NVD feed adapter did not start' }
    Log 'adapter restarted; waiting until /health reports fresh data (the first start after the upgrade rebuilds the modified feed)'
    $ah = Wait-AdapterHealthy
    $ahProblems = ''; if ($ah.body) { $ahProblems = (Items $ah.body.problems) -join ' | ' }
    $mod = $null; try { $mod = (Invoke-RestMethod -Uri "$Adapter/stats" -TimeoutSec 30).feeds.modified } catch { }
    $mod22 = [bool]($mod -and ($mod.PSObject.Properties.Name -contains 'recent_rewrites'))
    Check 'adapter 2.2 /health after the upgrade' ($ah.code -eq 200 -and "$($ah.body.version)" -eq '2.2') '200, version 2.2' "$($ah.code), version $($ah.body.version) $ahProblems"
    Check 'adapter 2.2 built the modified feed before DT 5.2.2 starts' $mod22 'built by 2.2' "$(if ($mod22) { "recent_rewrites $($mod.recent_rewrites)" } else { 'not yet' })"
    if ($ah.code -ne 200 -or "$($ah.body.version)" -ne '2.2' -or -not $mod22) { throw "adapter 2.2 not ready, so DT was not started: $ahProblems" }

    # ---------- then DT 5.2.2 (compose.yaml pins it) ----------
    Status 'dt'
    docker compose -f $Compose up -d 2>&1 | ForEach-Object { Log "compose: $_" }
    $up = $false
    for ($i = 0; $i -lt 60; $i++) { try { $ver = Invoke-RestMethod -Uri "$Api/api/version" -TimeoutSec 5; $up = $true; break } catch { Start-Sleep 5 } }
    if (-not $up) { throw 'API server did not come up' }
    Log "DT version: $($ver.version)"
    Check "DT runs $DtVersion (compose.yaml)" ("$($ver.version)" -eq $DtVersion) $DtVersion "$($ver.version)"
    if ("$($ver.version)" -ne $DtVersion) { throw "DT $($ver.version) is running, expected $DtVersion" }

    # ---------- admin session (setup, faults and the independent checks only) ----------
    Status 'setup'
    $tok = $null
    foreach ($p in @($NewPw, 'admin')) {
        try { $tok = Invoke-RestMethod -Method Post -Uri "$Api/api/v1/user/login" -ContentType 'application/x-www-form-urlencoded' -Body @{ username = 'admin'; password = $p }; if ($tok) { break } } catch { }
    }
    if (-not $tok) { throw 'could not log in as admin' }
    $adminH = @{ Authorization = "Bearer $tok" }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    # ---------- leftovers of a run whose window was closed (finally did not run) ----------
    foreach ($f in @(Get-ChildItem -Path $Work -Filter 'restore-*.json' -ErrorAction SilentlyContinue)) {
        $m = [regex]::Match($f.Name, '^restore-(vuln-analyzer|vuln-data-source|kev-data-source)-(.+)\.json$')
        if ($m.Success) { try { PutCfg $m.Groups[1].Value $m.Groups[2].Value (Get-Content $f.FullName -Raw | ConvertFrom-Json); Log "restored $($m.Groups[1].Value)/$($m.Groups[2].Value) from an aborted run"; Remove-Item -Force $f.FullName } catch { Log "could not restore $($f.Name): $(ErrText $_)" } }
    }
    $o = GetCfg 'vuln-analyzer' 'oss-index'
    if ($o.apiToken -eq $RevokedSecret) { Log 'repairing an OSS Index token left from an aborted run'; PutCfg 'vuln-analyzer' 'oss-index' (WithChange $o 'apiToken' 'OSSINDEX_API_TOKEN') }
    try { Call $adminH 'DELETE' "/api/v2/secrets/$RevokedSecret" | Out-Null; Log 'removed a test secret left from an aborted run' } catch { }
    try {
        foreach ($t in (Paged $adminH '/api/v1/team')) {
            if ("$($t.name)" -notmatch '^health-(read|test)-\d{8}-\d{6}$') { continue }
            foreach ($k in (Items $t.apiKeys)) { $kid = $k.publicId; if ($kid) { try { Call $adminH 'DELETE' "/api/v1/team/key/$kid" | Out-Null } catch { } } }
            try { Call $adminH 'DELETE' '/api/v1/team' @{ uuid = $t.uuid } | Out-Null; Log "removed team $($t.name) left from an aborted run" } catch { }
        }
    } catch { Log "could not list teams: $(ErrText $_)" }
    try { foreach ($r in (Paged $adminH '/api/v1/notification/rule')) { if ("$($r.name)" -like 'dt-health-verify*') { Call $adminH 'DELETE' '/api/v1/notification/rule' @{ uuid = $r.uuid } | Out-Null; Log 'removed a test notification rule left from an aborted run' } } } catch { }
    try {
        # (Paged ...) in parentheses: Paged returns its list as one object, and piped as it is, Where-Object would
        # get the whole list as one item and select every project whenever the first one was a load-test project
        $all = Paged $adminH '/api/v1/project'
        $old = @($all | Where-Object { $_ -isnot [System.Array] -and "$($_.name)" -match '^dt-health-load-\d+$' -and "$($_.version)" -eq '1' })
        $ids = @($old | ForEach-Object { "$($_.uuid)" } | Where-Object { $_ -match '^[0-9a-f-]{36}$' })
        if ($old.Count -gt $LoadProjects -or $ids.Count -ne $old.Count -or ($old.Count -gt 0 -and $old.Count -ge $all.Count)) {
            Log "NOT deleting: $($old.Count) of $($all.Count) projects look like load-test leftovers, which is more than this script creates; check them in the UI"
        } elseif ($ids.Count) {
            Call $adminH 'POST' '/api/v1/project/batchDelete' $ids | Out-Null; Log "removed $($ids.Count) load-test projects left from an aborted run"
        }
    } catch { Log "could not clean up old load-test projects: $(ErrText $_)" }
    docker rm -f $Receiver 2>$null | Out-Null
    $readKey = NewTeam "health-read-$stamp" $ReadPerms
    $testKey = NewTeam "health-test-$stamp" $TestPerms

    # ---------- DT's own alert for failed mirrors: a webhook rule to a small receiver ----------
    Set-Content -Path (Join-Path $Work 'receiver.py') -Encoding ASCII -Value @(
        'import http.server, json, time',
        'class H(http.server.BaseHTTPRequestHandler):',
        '    def log_message(self, *a): pass',
        '    def do_POST(self):',
        '        n = int(self.headers.get("Content-Length") or 0); body = self.rfile.read(n).decode("utf-8", "replace")',
        '        open("/w/dt-health-verify/received.jsonl", "a").write(json.dumps({"at": time.time(), "body": body}) + "\n")',
        '        self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers()',
        'http.server.ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()')
    $net = ((docker inspect dt5-test-apiserver-1 -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>$null | Select-Object -First 1) -split ' ')[0]
    docker run -d --rm --name $Receiver --network $net -v "${Dir}:/w" $Py python -u -I /w/dt-health-verify/receiver.py 2>&1 | ForEach-Object { Log "receiver: $_" }
    $receiverUp = $true
    $pub = @((Items (Call $adminH 'GET' '/api/v1/notification/publisher')) | Where-Object { "$($_.extensionName)" -eq 'webhook' -or "$($_.name)" -match 'Webhook' }) | Select-Object -First 1
    if (-not $pub) { throw 'DT has no webhook notification publisher' }
    $rule = Call $adminH 'PUT' '/api/v1/notification/rule' @{ name = "dt-health-verify mirrors $stamp"; scope = 'SYSTEM'; level = 'ERROR'; publisher = @{ uuid = $pub.uuid } }
    $ruleUuid = $rule.uuid
    Call $adminH 'POST' '/api/v1/notification/rule' @{ uuid = $ruleUuid; name = "dt-health-verify mirrors $stamp"; enabled = $true; notifyChildren = $false
        logSuccessfulPublish = $true; scope = 'SYSTEM'; level = 'ERROR'; notifyOn = @('DATASOURCE_MIRRORING')
        publisherConfig = (J @{ destinationUrl = "http://${Receiver}:8080/hook" }) } | Out-Null
    Log "notification rule for failed mirrors -> $Receiver (publisher $($pub.name))"

    # ---------- DT 5.2.2: the ENISA EU KEV feed moved; DT keeps the URL it stored at first start ----------
    $en = $null; try { $en = GetCfg 'kev-data-source' 'enisa' } catch { Log "could not read the ENISA config: $(ErrText $_)" }
    if ($en -and "$($en.feedUrl)" -eq $EnisaOldUrl) {
        PutCfg 'kev-data-source' 'enisa' (WithChange $en 'feedUrl' $EnisaNewUrl)
        Log "ENISA EU KEV feed URL changed to the new address (the old one was retired; this is the upgrade, not restored)"
        $en = GetCfg 'kev-data-source' 'enisa'
    }
    if ($en -and $en.enabled) { Check 'ENISA EU KEV source uses the current feed URL' ("$($en.feedUrl)" -eq $EnisaNewUrl) $EnisaNewUrl "$($en.feedUrl)" }

    # ---------- every enabled mirror once, so the baseline is current ----------
    Status 'mirrors'
    foreach ($ep in @('vuln-data-source', 'kev-data-source')) {
        foreach ($x in (Items (Call $adminH 'GET' "/api/v2/extension-points/$ep/extensions").items)) {
            $c = $null; try { $c = GetCfg $ep $x.name } catch { }
            if (-not ($c -and $c.enabled)) { continue }
            $r = Mirror $ep $x.name
            Log "mirror $ep/$($x.name): $(if ($r) { "$($r.status) $($r.failure_reason)" } else { 'no result' })"
        }
    }

    # ---------- the test stack was off: let DT's portfolio re-analysis catch up (it runs every minute) ----------
    Status 'portfolio'
    $deadline = (Get-Date).AddMinutes(30); $staleN = -1
    while ((Get-Date) -lt $deadline) {
        $nowMs = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $pr = Paged $adminH '/api/v1/project?excludeInactive=true'   # no @(): Paged already returns one list
        $staleN = @($pr | Where-Object { $_.lastBomImport -and $_.metrics.components -ne 0 -and (-not $_.lastVulnerabilityAnalysis -or ($nowMs - [int64]$_.lastVulnerabilityAnalysis) -gt 30 * 3600 * 1000) }).Count
        if ($staleN -eq 0) { break }
        Log "  $staleN of $($pr.Count) projects not re-analysed yet"; Start-Sleep 30
    }
    Log "portfolio re-analysis: $staleN projects older than 30 h left"

    # ---------- with portfolio ACL on, both health teams must see an existing canary before the first run ----------
    $canary = $null; try { $canary = Call $adminH 'GET' '/api/v1/project/lookup?name=dt-health-canary&version=1' } catch { }
    if ($canary) { foreach ($t in $teams) { try { Call $adminH 'PUT' '/api/v1/acl/mapping' @{ team = $t.uuid; project = $canary.uuid } | Out-Null } catch { if ((Code $_) -ne 409) { Log "ACL mapping for $($t.name): $(ErrText $_)" } } } }

    # ---------- baseline ----------
    Status 'baseline'
    $b = Health 'baseline' $testKey @('--test-extensions')
    Check 'baseline (test key, --test-extensions, canary): PASS' ($b.code -eq 0) 'exit 0' (Summ $b)
    Check 'baseline: all 5 canary expectations hold on the real stack' ((CanaryOk $b.rep) -eq 5) 5 (CanaryOk $b.rep)
    if ($b.rep.canary.project) {   # with portfolio ACL on, only the creating team could see the canary
        foreach ($t in $teams) { try { Call $adminH 'PUT' '/api/v1/acl/mapping' @{ team = $t.uuid; project = $b.rep.canary.project } | Out-Null } catch { if ((Code $_) -ne 409) { Log "ACL mapping for $($t.name): $(ErrText $_)" } } }
    }
    $bl = Health 'baseline-read-key' $readKey @()
    Check 'baseline with the read-only key (5 permissions): PASS' ($bl.code -eq 0) 'exit 0' (Summ $bl)
    $g1 = $b.rep.canary.group; $g2 = $bl.rep.canary.group
    Check 'canary components re-created in the other group on the next run' ($g1 -and $g2 -and $g1 -ne $g2) 'groups differ' "$g1 -> $g2"
    if ($bl.rep.canary.project) {
        $cc = Paged $adminH "/api/v1/component/project/$($bl.rep.canary.project)?sortName=name&sortOrder=asc"
        $grp = @($cc | ForEach-Object { $_.group } | Sort-Object -Unique)
        Check 'independent: the canary project has 4 components, all in the new group' ($cc.Count -eq 4 -and $grp.Count -eq 1 -and $grp[0] -eq $g2) "4 in $g2" "$($cc.Count) in $($grp -join ',')"
    }

    # ---------- fault: stale threshold ----------
    Status 'fault-stale'
    $f = Health 'fault-stale' $readKey @('--no-canary', '--max-age-hours', '0.001')
    Check 'stale: mirror runs older than the limit are problems' ($f.code -eq 1 -and @(Problems $f.rep 'mirror' 'vuln-data-source/nvd' 'limit 0.001 h').Count -eq 1) 'exit 1, NVD mirror too old' (Summ $f)

    # ---------- fault: OSS Index token revoked (findings still come from DT's 24 h cache) ----------
    Status 'fault-ossindex'
    $ossOrig = GetCfg 'vuln-analyzer' 'oss-index'; SaveRestore 'vuln-analyzer' 'oss-index' $ossOrig
    try { Call $adminH 'POST' '/api/v2/secrets' @{ name = $RevokedSecret; value = "sonatype_pat_dt-health-verify-revoked-$stamp"; description = 'dt-health-verify: a revoked OSS Index token (deleted after the test)' } | Out-Null; $secretMade = $true }
    catch { if ((Code $_) -eq 409) { $secretMade = $true } else { throw } }
    PutCfg 'vuln-analyzer' 'oss-index' (WithChange $ossOrig 'apiToken' $RevokedSecret)
    Check 'independent: OSS Index now uses the revoked token' ((GetCfg 'vuln-analyzer' 'oss-index').apiToken -eq $RevokedSecret) $RevokedSecret ((GetCfg 'vuln-analyzer' 'oss-index').apiToken)
    $f = Health 'fault-ossindex' $testKey @('--no-canary', '--test-extensions')
    Check 'OSS Index token revoked: the live test reports it' ($f.code -eq 1 -and @(Problems $f.rep 'test' 'vuln-analyzer/oss-index' 'authentication FAILED').Count -eq 1) 'exit 1, authentication FAILED' (Summ $f)
    PutCfg 'vuln-analyzer' 'oss-index' $ossOrig
    Call $adminH 'DELETE' "/api/v2/secrets/$RevokedSecret" | Out-Null; $secretMade = $false
    Check 'restored: OSS Index configuration as before' ((Canon (GetCfg 'vuln-analyzer' 'oss-index')) -eq (Canon $ossOrig)) 'unchanged' 'compared'
    $ossOrig = $null; DropRestore 'vuln-analyzer' 'oss-index'

    # ---------- fault: Trivy analyzer disabled ----------
    Status 'fault-trivy-disabled'
    $trivyOrig = GetCfg 'vuln-analyzer' 'trivy'; SaveRestore 'vuln-analyzer' 'trivy' $trivyOrig
    PutCfg 'vuln-analyzer' 'trivy' (WithChange $trivyOrig 'enabled' $false)
    Check 'independent: DT has Trivy disabled now' (-not (GetCfg 'vuln-analyzer' 'trivy').enabled) 'enabled false' ((GetCfg 'vuln-analyzer' 'trivy').enabled)
    $f = Health 'fault-trivy-disabled' $readKey @('--no-canary')
    Check 'Trivy analyzer disabled: reported as a required analyzer that is off' ($f.code -eq 1 -and @(Problems $f.rep 'config' 'vuln-analyzer/trivy' 'required, but disabled').Count -eq 1) 'exit 1' (Summ $f)
    PutCfg 'vuln-analyzer' 'trivy' $trivyOrig
    Check 'restored: Trivy configuration as before' ((Canon (GetCfg 'vuln-analyzer' 'trivy')) -eq (Canon $trivyOrig)) 'unchanged' 'compared'
    $trivyOrig = $null; DropRestore 'vuln-analyzer' 'trivy'

    # ---------- fault: Trivy server down (the analyzer fails; DT keeps old Trivy findings elsewhere) ----------
    Status 'fault-trivy-down'
    docker compose -f $Compose stop trivy 2>&1 | ForEach-Object { Log "compose: $_" }; $trivyStopped = $true
    $running = (docker inspect -f '{{.State.Running}}' dt5-test-trivy-1 2>$null | Select-Object -First 1)
    Check 'independent: the Trivy container is stopped' ("$running" -eq 'false') 'false' "$running"
    $f = Health 'fault-trivy-down' $readKey @()
    $others = @((Items $f.rep.checks) | Where-Object { $_.area -eq 'canary' -and $_.name -ne 'trivy' -and $_.name -ne 'analysis-latency' -and $_.status -eq 'ok' }).Count
    Check 'Trivy server down: the canary trivy expectation fails, the other 4 hold' ($f.code -eq 1 -and @(Problems $f.rep 'canary' 'trivy' '').Count -eq 1 -and $others -eq 4) 'exit 1, trivy only' "$(Summ $f); other canary ok: $others"
    docker compose -f $Compose start trivy 2>&1 | ForEach-Object { Log "compose: $_" }
    $tu = $false; for ($i = 0; $i -lt 90; $i++) { try { $r = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:4954/healthz' -TimeoutSec 5; if ($r.StatusCode -eq 200) { $tu = $true; break } } catch { Start-Sleep 5 } }
    Check 'restored: Trivy server answers' $tu 'healthz 200' $tu
    $trivyStopped = -not $tu

    # ---------- fault: NVD feed adapter stopped ----------
    Status 'fault-adapter-down'
    docker compose -f $Compose stop nvdpp 2>&1 | ForEach-Object { Log "compose: $_" }; $nvdppStopped = $true
    $r = Mirror 'vuln-data-source' 'nvd' 1200
    Check 'independent: DT NVD mirror with the adapter down' ($r -and $r.status -eq 'FAILED') 'FAILED' "$(if ($r) { "$($r.status) $($r.failure_reason)" } else { 'no result' })"
    $f = Health 'fault-adapter-down' $testKey @('--no-canary', '--test-extensions')
    Check 'adapter down: reported (adapter does not answer)' (@(Problems $f.rep 'adapter' 'health' 'does not answer').Count -eq 1) 'problem' (Summ $f)
    Check 'adapter down: the failed NVD mirror run is reported' (@(Problems $f.rep 'mirror' 'vuln-data-source/nvd' 'FAILED').Count -eq 1) 'problem' 'see above'
    Check 'adapter down: DT live NVD test fails' (@(Problems $f.rep 'test' 'vuln-data-source/nvd' 'FAILED').Count -eq 1) 'problem' 'see above'
    $got = $null
    for ($i = 0; $i -lt 60 -and -not $got; $i++) {
        $rf = Join-Path $Work 'received.jsonl'
        if (Test-Path $rf) { $got = @(Get-Content $rf | Where-Object { $_ -match 'DATASOURCE_MIRRORING' -and $_ -match '(?i)fail' -and $_ -match 'NVD' }) | Select-Object -First 1 }
        if (-not $got) { Start-Sleep 5 }
    }
    Check "DT's own alert: the failed NVD mirror notification reached the webhook receiver" ([bool]$got) 'received' $(if ($got) { 'received' } else { 'nothing within 5 min' })
    docker compose -f $Compose start nvdpp 2>&1 | ForEach-Object { Log "compose: $_" }; $nvdppStopped = $false
    if (-not (Wait-AdapterAlive)) { throw 'the adapter did not come back' }
    $ah = Wait-AdapterHealthy 1800
    Check 'restored: adapter /health 200' ($ah.code -eq 200) 200 $ah.code
    $r = Mirror 'vuln-data-source' 'nvd'
    Check 'restored: NVD mirror COMPLETED' ($r -and $r.status -eq 'COMPLETED') 'COMPLETED' "$(if ($r) { $r.status } else { 'no result' })"

    # ---------- fault: VulnCheck rejects the token (the adapter keeps serving the old CPEs) ----------
    Status 'fault-vulncheck'
    Set-Content -Path $FaultYaml -Encoding ASCII -Value @('services:', '  nvdpp:', '    environment:', "      VULNCHECK_TOKEN: `"dt-health-verify-invalid-$stamp`"")
    $prior = AdapterHealth; $priorAttempt = ''; if ($prior.body) { $priorAttempt = "$($prior.body.vulncheck.last_attempt_at)" }
    docker compose -f $Compose -f $FaultYaml up -d nvdpp 2>&1 | ForEach-Object { Log "compose: $_" }; $nvdppFault = $true
    if (-not (Wait-AdapterAlive)) { throw 'the adapter did not start with the test token' }
    Wait-AdapterIdle | Out-Null   # the startup refresh checks the token by itself (adapter 2.1 and later)
    try { AdapterRebuild 'vc=1&wait=1' | Out-Null } catch { Log "rebuild: $(ErrText $_)" }
    $ah = AdapterHealth
    $ap = ''; $att = ''; if ($ah.body) { $ap = (Items $ah.body.problems) -join ' | '; $att = "$($ah.body.vulncheck.last_attempt_at)" }
    Check 'adapter /health 503 naming VulnCheck, after a new VulnCheck attempt' ($ah.code -eq 503 -and $ap -match 'VulnCheck' -and $att -and $att -ne $priorAttempt) '503 VulnCheck, new attempt' "$($ah.code) $ap (attempt $priorAttempt -> $att)"
    $lg = @(docker logs --since 30m dt5-test-nvdpp-1 2>&1 | Where-Object { "$_" -match 'VulnCheck load failed' -and "$_" -match '40[13]' })
    Check 'independent: the adapter log shows VulnCheck refusing the token' ($lg.Count -ge 1) 'a 401 or 403' "$($lg.Count) log lines"
    $f = Health 'fault-vulncheck' $readKey @('--no-canary')
    Check 'VulnCheck token rejected: reported through the adapter' ($f.code -eq 1 -and @(Problems $f.rep 'adapter' 'health' 'VulnCheck').Count -ge 1) 'exit 1' (Summ $f)
    docker compose -f $Compose up -d nvdpp 2>&1 | ForEach-Object { Log "compose: $_" }; $nvdppFault = $false
    if (-not (Wait-AdapterAlive)) { throw 'the adapter did not come back with the real token' }
    $ah = Wait-AdapterHealthy 2700
    Check 'restored: adapter /health 200 with the real token' ($ah.code -eq 200) 200 $ah.code

    # ---------- load: a release-day burst of uploads ahead of the canary ----------
    Status 'load'
    $pool = @('zlib:zlib:1.2.11', 'openssl:openssl:1.1.1k', 'libexpat_project:libexpat:2.4.1', 'busybox:busybox:1.33.1', 'gnu:glibc:2.39',
              'cjson_project:cjson:1.7.10', 'libpng:libpng:1.6.34', 'haxx:curl:7.64.0', 'sqlite:sqlite:3.31.0', 'xmlsoft:libxml2:2.9.10')
    $env:DT_API_KEY = $null
    $readH = @{ 'X-Api-Key' = $readKey }
    $tokens = New-Object System.Collections.ArrayList
    $t0 = Get-Date
    for ($pn = 0; $pn -lt $LoadProjects; $pn++) {
        $comps = New-Object System.Collections.ArrayList
        for ($j = 0; $j -lt $LoadComponents; $j++) {   # CPE only: the internal analyzer works, nothing calls OSS Index
            $v = $pool[$j % $pool.Count].Split(':')
            [void]$comps.Add([ordered]@{ type = 'library'; 'bom-ref' = "c$j"; name = "load-$($v[1])-$j"; version = $v[2]; cpe = "cpe:2.3:a:$($v[0]):$($v[1]):$($v[2]):*:*:*:*:*:*:*" })
        }
        $bom = [ordered]@{ bomFormat = 'CycloneDX'; specVersion = '1.6'; version = 1; metadata = [ordered]@{ component = [ordered]@{ type = 'application'; name = "dt-health-load-$pn"; version = '1' } }; components = $comps }
        $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((J $bom)))
        try { $u = Call $readH 'PUT' '/api/v1/bom' @{ projectName = "dt-health-load-$pn"; projectVersion = '1'; autoCreate = $true; bom = $b64 }; [void]$tokens.Add($u.token); if ($u.projectUuid) { $script:loadUuids += $u.projectUuid } }
        catch { Log "load upload $pn failed: $(ErrText $_)" }
    }
    Log "load: $($tokens.Count) projects with $LoadComponents components uploaded in $([int]((Get-Date) - $t0).TotalSeconds) s; health check while DT works through them"
    $ld = Health 'load' $readKey @()
    $lat = @((Items $ld.rep.checks) | Where-Object { $_.area -eq 'canary' -and $_.name -eq 'analysis-latency' }) | Select-Object -First 1
    $other = @(Problems $ld.rep '' '' '' | Where-Object { -not ($_.area -eq 'canary' -and $_.name -eq 'analysis-latency') })
    Check 'load: no false alarm during the backlog (only analysis latency may be reported)' ($other.Count -eq 0 -and $ld.rep) 'no other problem' "$(Summ $ld); latency: $($lat.detail)"
    Check 'load: all test uploads accepted' ($tokens.Count -eq $LoadProjects) $LoadProjects $tokens.Count
    $budget = [int]$bl.rep.apiCallsExcludingPolls + 5   # the portfolio sample may read up to 5 more pages; token polls are counted apart
    Check 'load: API calls (token polls apart) no more than at baseline plus the sample pages' ($ld.rep.apiCallsExcludingPolls -and [int]$ld.rep.apiCallsExcludingPolls -le $budget) "at most $budget" "$($ld.rep.apiCallsExcludingPolls) (and $($ld.rep.tokenPolls) token polls)"
    $maxPolls = [int](6 + 30 * 60 / 30 + 1)
    Check 'load: token polls bounded' ($ld.rep.tokenPolls -ne $null -and [int]$ld.rep.tokenPolls -le $maxPolls) "at most $maxPolls" $ld.rep.tokenPolls
    $pending = 0; $deadline = (Get-Date).AddMinutes(60)
    foreach ($tk in $tokens) { while ((Get-Date) -lt $deadline) { try { $st = Call $readH 'GET' "/api/v1/event/token/$tk"; if (-not $st.processing) { break } } catch { break }; Start-Sleep 5 }; if ((Get-Date) -ge $deadline) { $pending++ } }
    $drain = [int]((Get-Date) - $t0).TotalSeconds
    Log "load: DT finished $($tokens.Count - $pending) of $($tokens.Count) analyses in $drain s"
    Check 'load: DT worked through the whole backlog' ($pending -eq 0 -and $tokens.Count -gt 0) 'all analysed' "$($tokens.Count - $pending) of $($tokens.Count) in $drain s"
    $runs['load'].canarySecondsBaseline = $bl.rep.metrics.'canary/analysis_seconds'; $runs['load'].canarySecondsUnderLoad = $ld.rep.metrics.'canary/analysis_seconds'
    $runs['load'].drainSeconds = $drain; $runs['load'].projects = $tokens.Count; $runs['load'].componentsEach = $LoadComponents
    if ($loadUuids.Count) { try { Call $adminH 'POST' '/api/v1/project/batchDelete' @($loadUuids) | Out-Null; Log "load: $($loadUuids.Count) test projects deleted"; $script:loadUuids = @() } catch { Log "load: could not delete the test projects: $(ErrText $_)" } }
    Check 'load: test projects deleted' ($loadUuids.Count -eq 0) 0 $loadUuids.Count

    # ---------- final ----------
    Status 'final'
    $fin = Health 'final' $testKey @('--test-extensions')
    Check 'final (test key, --test-extensions, canary): PASS' ($fin.code -eq 0) 'exit 0' (Summ $fin)
    Check 'final: all 5 canary expectations hold' ((CanaryOk $fin.rep) -eq 5) 5 (CanaryOk $fin.rep)
    $finr = Health 'final-read-key' $readKey @()
    Check 'final with the read-only key: PASS' ($finr.code -eq 0) 'exit 0' (Summ $finr)

    $pass = @($checks | Where-Object { -not $_.ok }).Count -eq 0
    if ($pass) { $result = 'PASS' }
    $results = [ordered]@{ run = (Get-Date).ToString('s'); dt = $ver.version; result = $result; readKeyPermissions = $ReadPerms; testKeyPermissions = $TestPerms
        checks = $checks; runs = $runs; adapterHealth = $ah.body }
    $results | ConvertTo-Json -Depth 12 | Set-Content -Path $ResultsFile -Encoding UTF8
    Log "RESULT: $result"

    # ---------- commit and push only when the check passed ----------
    if ($pass) {
        Status 'push'
        $msg = @'
Gap 2: vulnerability data can no longer stop silently (DT 5.2.2)

In Dependency-Track 5.2 a failed mirror leaves the old data in place, the
NVD feed adapter kept serving its last build while answering "ok", and a
failed analyzer keeps the findings it reported before. Nothing alerted.
The first real run found such a failure: ENISA moved its EU KEV feed on
2026-11-16 and every ENISA mirror on DT 5.2.1 failed with HTTP 404.
Verified on DT 5.2.2 with real faults and a burst of 150 uploads
(dt-health-verify).

- Test stack upgraded to DT 5.2.2 (compose.yaml): reads ENISA's new
  format, plus security fixes. DT keeps the ENISA URL it stored at first
  start, so dt-health-verify sets the new one. 5.2.2 has no database
  migrations: rolling back is changing the tags back.
- nvdpp/adapter.py 2.2: DT 5.2.2 reads only the modified feed while its
  watermark is under 6 days old, so rewritten CVEs (new VulnCheck CPEs,
  aliases) whose lastModified is recent are copied into "modified" too;
  2.1 put them only into their yearly feed, which 5.2.2 skips. The adapter
  must be upgraded before DT (dt-health-verify starts it first). Also: a
  value issued for a drop-guarded feed is no longer reused after the
  accept (it came back below DT's watermark), and new values are floored
  by the newest lastModified served.
- nvdpp/adapter.py 2.1: /health (200, or 503 with the reasons): NIST
  refresh age and NIST going quiet, VulnCheck age, a rejected or missing
  token (checked on every refresh), no enriched CVEs; state kept across
  restarts. Drop guards keep the previous data when a VulnCheck backup or
  a NIST yearly feed is much smaller. One build worker queues requests
  instead of dropping them; forcing and accepting need POST plus a header.
  A failing feed no longer stops the others. /candidates/sample.
- ci/dt-health-check.py: mirror runs (stuck runs through --state), required
  sources and analyzers, the NVD feed URL, DT's own alert rules, live
  extension tests (opt-in), the adapter's /health, VulnCheck CPEs in DT,
  portfolio re-analysis (sampled), Trivy DB age, analysis latency, and a
  canary whose components are re-created each run, one per analyzer.
  API calls do not grow with the portfolio (tested at 10,000 projects).
- templates: Kubernetes CronJob next to DT, or a GitHub schedule.
- tests: nvdpp/tests/test_health.py (42 checks), nvdpp/tests/
  test_adapter.py (DT 5.2.1 and 5.2.2 reading rules: upgrade, window,
  drop guard), cpp-sboms/tests/test_health_gap2.py (70 checks, mock_dt.py
  with DT's reconciliation and its project list fields). Three
  independent reviews, the last on the 5.2.2 changes.
- dt-health-verify: the leftover clean-up selected every project when the
  first one listed was a load-test project (a PowerShell list passed whole
  into a pipeline); it now checks each project and refuses more than the
  script creates. It did not trigger on the test stack; a dry run with
  leftovers listed first showed it.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Gtp89CuUSYYsi5XMxfwRvd
'@
        $msgFile = Join-Path $Dir 'gap2-msg.tmp'
        [IO.File]::WriteAllText($msgFile, $msg.Replace("`r`n", "`n"))
        $files = @('compose.yaml', 'nvdpp/adapter.py', 'nvdpp/README.md', 'nvdpp/tests/test_health.py', 'nvdpp/tests/test_adapter.py',
                   'cpp-sboms/ci/dt-health-check.py', 'cpp-sboms/ci/health/dt-health.json', 'cpp-sboms/ci/health/dt-health-canary.cdx.json',
                   'cpp-sboms/ci/templates/dt-health.github-workflow.yml', 'cpp-sboms/ci/templates/dt-health.cronjob.yaml',
                   'cpp-sboms/ci/README.md', 'cpp-sboms/README.md',
                   'cpp-sboms/tests/mock_dt.py', 'cpp-sboms/tests/test_health_gap2.py',
                   'dt-health-verify.ps1', 'dt-health-verify.cmd', 'dt-health-verify-results.json', 'README.md', '.gitignore')
        $missing = @($files | Where-Object { -not (Test-Path (Join-Path $Dir $_)) })
        if ($missing.Count -gt 0) { throw "not pushed: missing files $($missing -join ', ')" }
        # before committing: this folder and GitHub must be at the same commit (nothing to pull, nothing unpushed)
        if ((GitStep @('fetch', 'origin', 'main')) -ne 0) { throw 'not pushed: git fetch failed (nothing committed)' }
        $behind = (git -C $Dir rev-list --count HEAD..origin/main 2>&1 | Select-Object -First 1)
        $aheadBefore = (git -C $Dir rev-list --count origin/main..HEAD 2>&1 | Select-Object -First 1)
        if ("$behind" -ne '0' -or "$aheadBefore" -ne '0') { throw "not pushed: this folder is $aheadBefore commits ahead of and $behind behind GitHub (nothing committed; check git status and git log)" }
        if ((GitStep (@('add', '--') + $files)) -ne 0) { throw 'not pushed: git add failed' }
        git -C $Dir diff --cached --quiet; if ($LASTEXITCODE -eq 0) { throw 'not pushed: nothing staged' }
        $cc = GitStep (@('commit', '-F', $msgFile, '--') + $files)   # only these files, whatever else is staged
        Remove-Item -Force -ErrorAction SilentlyContinue $msgFile
        if ($cc -ne 0) { throw 'not pushed: git commit failed' }
        GitStep @('fetch', 'origin', 'main') | Out-Null
        $ahead = (git -C $Dir rev-list --count origin/main..HEAD 2>&1 | Select-Object -First 1)
        if ("$ahead" -ne '1') { throw "not pushed: $ahead local commits would go to GitHub, expected only this one (the commit is local; check git log origin/main..HEAD)" }
        if ((GitStep @('push', 'origin', 'main')) -ne 0) { throw 'not pushed: git push failed (the commit is local; run git push later)' }
        GitStep @('log', '--oneline', '-1') | Out-Null
        $pushed = $true
        Log 'Pushed to GitHub.'
    } else {
        Log 'Not pushed: the check did not pass.'
    }
} catch {
    Log "FAILED: $($_.Exception.Message)"
    if (-not (Test-Path $ResultsFile)) {
        [ordered]@{ run = (Get-Date).ToString('s'); result = 'FAIL'; error = $_.Exception.Message; checks = $checks; runs = $runs } | ConvertTo-Json -Depth 12 | Set-Content -Path $ResultsFile -Encoding UTF8
    }
} finally {
    # put back whatever a fault changed
    if ($adminH -and $ossOrig) { try { PutCfg 'vuln-analyzer' 'oss-index' $ossOrig; Log 'OSS Index configuration restored'; DropRestore 'vuln-analyzer' 'oss-index' } catch { Log "could not restore the OSS Index configuration (kept in dt-health-verify/ for the next run): $(ErrText $_)" } }
    if ($adminH -and $secretMade) { try { Call $adminH 'DELETE' "/api/v2/secrets/$RevokedSecret" | Out-Null; Log 'test secret deleted' } catch { Log "could not delete the test secret: $(ErrText $_)" } }
    if ($adminH -and $trivyOrig) { try { PutCfg 'vuln-analyzer' 'trivy' $trivyOrig; Log 'Trivy configuration restored'; DropRestore 'vuln-analyzer' 'trivy' } catch { Log "could not restore the Trivy configuration (kept in dt-health-verify/ for the next run): $(ErrText $_)" } }
    if ($trivyStopped) { docker compose -f $Compose start trivy 2>&1 | ForEach-Object { Log "compose: $_" } }
    if ($nvdppFault -or $nvdppStopped) {
        docker compose -f $Compose up -d nvdpp 2>&1 | ForEach-Object { Log "compose: $_" }
        if ($adminH -and (Wait-AdapterAlive)) { $r = Mirror 'vuln-data-source' 'nvd' 1200; Log "NVD mirror after restoring the adapter: $(if ($r) { $r.status } else { 'no result' })" }
    }
    Remove-Item -Force -ErrorAction SilentlyContinue $FaultYaml
    if ($adminH -and $loadUuids.Count) { try { Call $adminH 'POST' '/api/v1/project/batchDelete' @($loadUuids) | Out-Null; Log 'load-test projects deleted' } catch { Log "could not delete the load-test projects: $(ErrText $_)" } }
    if ($adminH -and $ruleUuid) { try { Call $adminH 'DELETE' '/api/v1/notification/rule' @{ uuid = $ruleUuid } | Out-Null; Log 'test notification rule deleted' } catch { Log "could not delete the test notification rule: $(ErrText $_)" } }
    if ($receiverUp) { docker rm -f $Receiver 2>&1 | Out-Null; Log 'receiver stopped' }
    foreach ($kid in $keyIds) {   # deleting a team alone leaves its key behind (DT 5.2)
        try { Call $adminH 'DELETE' "/api/v1/team/key/$kid" | Out-Null; Log 'health key deleted' } catch { Log "could not delete a health key: $(ErrText $_)" }
    }
    foreach ($t in $teams) {
        try { Call $adminH 'DELETE' '/api/v1/team' @{ uuid = $t.uuid } | Out-Null; Log "team $($t.name) deleted" } catch { Log "could not delete team $($t.name): $(ErrText $_)" }
    }
    Remove-Item Env:\DT_API_KEY -ErrorAction SilentlyContinue
    docker compose -f $Compose stop 2>&1 | ForEach-Object { Log "compose: $_" }
    if ($pushed) { Status 'done-pushed' } elseif ($result -eq 'PASS') { Status 'failed-push' } else { Status 'done-failed' }
    Log "DONE (result $result, pushed $pushed) - containers stopped; images, data volumes and the adapter cache kept."
}
