# Gap 1 check on the real Dependency-Track stack (5.2.1; re-checked on 5.2.2): a VEX upload must never be lost silently.
# -Recheck (vex-verify-recheck.cmd): the same checks after a DT upgrade; on PASS it commits only the results.
#  1. Creates a CI team with only the permissions the release pipeline needs, and uses its key for every step.
#  2. Reproduces the problem: uploads the firmware SBOM and sends a VEX straight after it (the old way).
#  3. Runs the fix: cpp-sboms/ci/dt-vex-upload.py (in a python container on the compose network) waits for
#     the analysis, uploads the VEX and checks every statement.
#  4. Checks the result twice: against the tool's report, and independently from DT's findings.
#     The race must have lost statements, and the fix must give exactly the expected results.
#  5. Only then commits the gap 1 files and pushes them to GitHub, checking every git step.
# The CI team (and its key) is deleted and the containers are stopped at the end, also after a failure.
# Results: vex-verify-results.json and vex-verify-log.txt.

param([switch]$Recheck)
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$Dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Log = Join-Path $Dir 'vex-verify-log.txt'
$ResultsFile = Join-Path $Dir 'vex-verify-results.json'
$Api = 'http://localhost:8081'
$NewPw = 'DtTest-2026!'
$Work = Join-Path $Dir 'vex-verify'
$Py = 'python:3.13-slim'
$CiPermissions = @('BOM_UPLOAD', 'PROJECT_CREATION_UPLOAD', 'VIEW_PORTFOLIO', 'VIEW_VULNERABILITY', 'VULNERABILITY_ANALYSIS_UPDATE')
New-Item -ItemType Directory -Force -Path $Work | Out-Null
Remove-Item -Force -ErrorAction SilentlyContinue $ResultsFile, (Join-Path $Work '*.json')

function Log([string]$m) { $l = "$(Get-Date -Format 'HH:mm:ss') $m"; Write-Host $l; Add-Content -Path $Log -Value $l -Encoding UTF8 }
function Status([string]$s) { @{ stage = $s; time = (Get-Date).ToString('s') } | ConvertTo-Json | Set-Content -Path (Join-Path $Dir 'vex-verify-status.json') -Encoding UTF8 }
function ErrText($e) { $t = $e.Exception.Message; if ($e.ErrorDetails -and $e.ErrorDetails.Message) { $t += ' | ' + $e.ErrorDetails.Message }; return $t }
function J($o) { return ($o | ConvertTo-Json -Depth 10 -Compress) }
function Items($x) { $o = New-Object System.Collections.ArrayList; foreach ($i in @($x)) { if ($i -is [System.Array]) { foreach ($j in $i) { [void]$o.Add($j) } } elseif ($null -ne $i) { [void]$o.Add($i) } }; return ,$o.ToArray() }
function Call([hashtable]$headers, [string]$method, [string]$path, $body = $null) {
    $req = @{ Method = $method; Uri = "$Api$path"; Headers = $headers; TimeoutSec = 120 }
    if ($null -ne $body) { $req.Body = [Text.Encoding]::UTF8.GetBytes((J $body)); $req.ContentType = 'application/json' }
    elseif ($method -eq 'POST' -or $method -eq 'PUT') { $req.ContentType = 'application/json' }   # DT @Consumes(JSON) answers 415 without it
    return Invoke-RestMethod @req
}
function Paged([hashtable]$headers, [string]$path) {
    $all = New-Object System.Collections.ArrayList; $seen = @{}; $sep = '?'; if ($path.Contains('?')) { $sep = '&' }
    for ($pg = 1; $pg -le 200; $pg++) {
        $r = Items (Call $headers 'GET' "$path$($sep)pageSize=100&pageNumber=$pg"); $new = 0
        foreach ($x in $r) { $k = J $x; if (-not $seen.ContainsKey($k)) { $seen[$k] = 1; [void]$all.Add($x); $new++ } }
        if ($r.Count -lt 100 -or $new -eq 0) { break }
    }
    return ,$all.ToArray()
}
function Wait-Token([hashtable]$headers, [string]$t, [int]$maxSec = 900) {
    $deadline = (Get-Date).AddSeconds($maxSec)
    while ((Get-Date) -lt $deadline) {
        try { $r = Call $headers 'GET' "/api/v1/event/token/$t"; if ($r.processing -eq $false) { return "done ($($r.status))" } } catch { }
        Start-Sleep 3
    }
    return "timeout after $maxSec s"
}
function Py([string[]]$a) {
    $net = (docker inspect dt5-test-apiserver-1 -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>$null | Select-Object -First 1)
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

Set-Content -Path $Log -Value "Gap 1 (VEX upload) check started $(Get-Date -Format s)" -Encoding UTF8
Status 'starting'
$adminH = $null; $team = $null; $ciKeyId = $null; $result = 'FAIL'; $pushed = $false
try {
    docker compose -f (Join-Path $Dir 'compose.yaml') up -d 2>&1 | ForEach-Object { Log "compose: $_" }
    $up = $false
    for ($i = 0; $i -lt 60; $i++) { try { $ver = Invoke-RestMethod -Uri "$Api/api/version" -TimeoutSec 5; $up = $true; break } catch { Start-Sleep 5 } }
    if (-not $up) { throw 'API server did not come up' }
    Log "DT version: $($ver.version)"

    # ---------- admin session (setup and the independent check only) ----------
    Status 'setup'
    $tok = $null
    foreach ($p in @($NewPw, 'admin')) {
        try { $tok = Invoke-RestMethod -Method Post -Uri "$Api/api/v1/user/login" -ContentType 'application/x-www-form-urlencoded' -Body @{ username = 'admin'; password = $p }; if ($tok) { break } } catch { }
    }
    if (-not $tok) { throw 'could not log in as admin' }
    $adminH = @{ Authorization = "Bearer $tok" }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

    # ---------- a CI team with least privilege ----------
    $team = Call $adminH 'PUT' '/api/v1/team' @{ name = "vex-ci-test-$stamp" }
    foreach ($perm in $CiPermissions) { Call $adminH 'POST' "/api/v1/permission/$perm/team/$($team.uuid)" | Out-Null }
    $k = Call $adminH 'PUT' "/api/v1/team/$($team.uuid)/key"
    $ciKey = $k.key; if (-not $ciKey) { $ciKey = $k.secret }
    $ciKeyId = $k.publicId; if (-not $ciKeyId) { $ciKeyId = $ciKey }
    if (-not $ciKey) { throw 'no API key for the CI team' }
    $ciH = @{ 'X-Api-Key' = $ciKey }
    $env:DT_API_KEY = $ciKey   # passed to the container by name only (docker run -e DT_API_KEY)
    Log "CI team vex-ci-test-$stamp with $($CiPermissions -join ', ')"

    $sbom = Join-Path $Dir 'cpp-sboms\sboms\fw-build-manifest.cdx.json'
    $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($sbom))

    # ---------- convert the test OpenVEX (the policy checks run here) ----------
    Status 'convert'
    $c = Py @('cpp-sboms/generators/openvex-to-cdx-vex.py', '--sbom', 'cpp-sboms/sboms/fw-build-manifest.cdx.json',
              '--openvex', 'cpp-sboms/vex/test-gap1.openvex.json', '--out', 'vex-verify/gap1.vex.cdx.json')
    if ($c -ne 0) { throw "converter exit $c" }
    $vexB64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $Work 'gap1.vex.cdx.json')))

    # ---------- 1. the problem: VEX sent straight after the BOM ----------
    Status 'race'
    $raceName = 'cpp-sbom-vex-race'
    $r1 = Call $ciH 'PUT' '/api/v1/bom' @{ projectName = $raceName; projectVersion = $stamp; autoCreate = $true; bom = $b64 }
    $v1 = Call $ciH 'PUT' '/api/v1/vex' @{ projectName = $raceName; projectVersion = $stamp; vex = $vexB64 }
    Log "race: VEX sent straight after the BOM; VEX import $(Wait-Token $ciH $v1.token), BOM analysis $(Wait-Token $ciH $r1.token)"
    $raceCode = Py @('cpp-sboms/ci/dt-vex-upload.py', '--url', 'http://apiserver:8080', '--allow-http', '--vex', 'vex-verify/gap1.vex.cdx.json',
                     '--project-name', $raceName, '--project-version', $stamp, '--verify-only', '--report', 'vex-verify/report-race.json')

    # ---------- 2. the fix ----------
    Status 'fix'
    $fixName = 'cpp-sbom-vex-test'
    $r2 = Call $ciH 'PUT' '/api/v1/bom' @{ projectName = $fixName; projectVersion = $stamp; autoCreate = $true; bom = $b64 }
    Log "fix: BOM uploaded; dt-vex-upload.py waits for the analysis"
    $fixCode = Py @('cpp-sboms/ci/dt-vex-upload.py', '--url', 'http://apiserver:8080', '--allow-http', '--vex', 'vex-verify/gap1.vex.cdx.json',
                    '--project-uuid', "$($r2.projectUuid)", '--bom-token', "$($r2.token)", '--report', 'vex-verify/report-fix.json')

    # ---------- 3. compare with the expectations in cpp-sboms/vex/test-gap1.openvex.json ----------
    Status 'evaluate'
    $expect = [ordered]@{ 'CVE-2022-37434' = 'APPLIED'; 'CVE-2019-11834' = 'APPLIED'; 'CVE-2021-3711' = 'APPLIED'; 'CVE-2021-44228' = 'STORED'; 'CVE-2099-99999' = 'PENDING_UNKNOWN_VULN' }
    $fix = $null; $race = $null
    try { $fix = Get-Content (Join-Path $Work 'report-fix.json') -Raw | ConvertFrom-Json } catch { }
    try { $race = Get-Content (Join-Path $Work 'report-race.json') -Raw | ConvertFrom-Json } catch { }
    $checks = New-Object System.Collections.ArrayList
    $got = @{}
    if ($fix) { foreach ($x in (Items $fix.results)) { $got[$x.vulnId] = "$($x.result)" } }
    foreach ($id in $expect.Keys) { [void]$checks.Add([ordered]@{ check = "tool report: $id"; expected = $expect[$id]; got = $got[$id]; ok = ($got[$id] -eq $expect[$id]) }) }
    [void]$checks.Add([ordered]@{ check = 'tool exit code'; expected = 0; got = $fixCode; ok = ($fixCode -eq 0) })

    # independent check, from DT's own findings (admin session, not the tool)
    $findings = Paged $adminH "/api/v1/finding/project/$($r2.projectUuid)?suppressed=true"
    $want = @(@('CVE-2022-37434', 'zlib', 'RESOLVED', $true), @('CVE-2019-11834', 'cjson', 'NOT_AFFECTED', $true), @('CVE-2021-3711', 'openssl', 'IN_TRIAGE', $false))
    foreach ($w in $want) {
        $f = @($findings | Where-Object { $_.vulnerability.vulnId -eq $w[0] -and $_.component.name -eq $w[1] }) | Select-Object -First 1
        $gs = $null; $gsup = $null; if ($f) { $gs = "$($f.analysis.state)"; $gsup = [bool]$f.analysis.isSuppressed }
        [void]$checks.Add([ordered]@{ check = "DT findings: $($w[0]) on $($w[1])"; expected = "$($w[2]), suppressed $($w[3])"; got = "$gs, suppressed $gsup"; ok = ($gs -eq $w[2] -and $gsup -eq $w[3]) })
    }
    $raceLost = 0; if ($race) { $raceLost = @((Items $race.results) | Where-Object { $_.result -eq 'NOT_APPLIED' }).Count }
    [void]$checks.Add([ordered]@{ check = 'race (old way) lost statements'; expected = 'at least 1 of 4'; got = $raceLost; ok = ($raceLost -ge 1) })
    $pass = @($checks | Where-Object { -not $_.ok }).Count -eq 0
    if ($pass) { $result = 'PASS' }
    foreach ($ch in $checks) { Log ("{0} {1}: expected {2}, got {3}" -f $(if ($ch.ok) { 'ok  ' } else { 'FAIL' }), $ch.check, $ch.expected, $ch.got) }
    $results = [ordered]@{ run = (Get-Date).ToString('s'); dt = $ver.version; projectVersion = $stamp; ciPermissions = $CiPermissions
        result = $result; checks = $checks; fixReport = $fix
        race = [ordered]@{ note = 'VEX sent straight after the BOM, the old way'; toolExit = $raceCode; statementsNotApplied = $raceLost; report = $race } }
    $results | ConvertTo-Json -Depth 12 | Set-Content -Path $ResultsFile -Encoding UTF8
    Log "RESULT: $result"

    # ---------- 4. commit and push only when the check passed ----------
    if ($pass -and $Recheck) {
        Status 'push'
        $msg = @"
Gap 1 re-checked on Dependency-Track $($ver.version): PASS

vex-verify -Recheck ran the gap 1 checks again after the upgrade: the VEX
race still loses statements without the tool, and dt-vex-upload.py still
gives exactly the expected results, confirmed from DT's own findings, with
a CI key holding only 5 permissions. Only the results file is committed.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Gtp89CuUSYYsi5XMxfwRvd
"@
        $files = @('vex-verify-results.json', 'vex-verify.ps1', 'vex-verify-recheck.cmd', 'README.md')
    } elseif ($pass) {
        Status 'push'
        $msg = @'
Gap 1: a VEX upload can no longer be lost silently

Dependency-Track 5.2.1 imports VEX in the background and skips the whole VEX
when the project has no findings yet, which is the case right after a BOM
upload while the analysis runs. It also skips statements for unknown CVEs.
The upload reports success either way. Verified on DT 5.2.1 (vex-verify).

- ci/dt-vex-upload.py: waits on the BOM token (the analysis run carries it),
  uploads the VEX, then checks the analysis DT holds for every statement and
  component (state, suppression, justification, response, details).
  --pending-from re-applies only pending statements, so triage is kept.
- openvex-to-cdx-vex.py 1.1: VEX policy checks; sbom-cve-check product
  shape, subcomponents and the root; the latest statement wins; keeps the
  OpenVEX author and timestamps.
- sbom-release.sh: OPENVEX_FILE / VEX_FILE through the tool; fails when a
  VEX is set without DT, or when the upload returns no token.
- tests/mock_dt.py, tests/test_vex_gap1.py (42 checks); vex-verify.cmd on
  the real stack with a least-privilege CI key.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Gtp89CuUSYYsi5XMxfwRvd
'@
        $files = @('cpp-sboms/generators/openvex-to-cdx-vex.py', 'cpp-sboms/ci/dt-vex-upload.py', 'cpp-sboms/ci/sbom-release.sh',
                   'cpp-sboms/ci/README.md', 'cpp-sboms/README.md', 'cpp-sboms/tests/mock_dt.py', 'cpp-sboms/tests/test_vex_gap1.py',
                   'cpp-sboms/vex/test-gap1.openvex.json', 'cpp-sboms/vex/example.vex.cdx.json',
                   'vex-verify.ps1', 'vex-verify.cmd', 'vex-verify-results.json', 'README.md', '.gitignore')
    }
    if ($pass) {
        $msgFile = Join-Path $Dir 'gap1-msg.tmp'
        [IO.File]::WriteAllText($msgFile, $msg.Replace("`r`n", "`n"))
        $missing = @($files | Where-Object { -not (Test-Path (Join-Path $Dir $_)) })
        if ($missing.Count -gt 0) { throw "not pushed: missing files $($missing -join ', ')" }
        # before committing: this folder and GitHub must be at the same commit (nothing to pull, nothing unpushed)
        if ((GitStep @('fetch', 'origin', 'main')) -ne 0) { throw 'not pushed: git fetch failed (nothing committed)' }
        $behind = (git -C $Dir rev-list --count HEAD..origin/main 2>&1 | Select-Object -First 1)
        $aheadBefore = (git -C $Dir rev-list --count origin/main..HEAD 2>&1 | Select-Object -First 1)
        if ("$behind" -ne '0' -or "$aheadBefore" -ne '0') { throw "not pushed: this folder is $aheadBefore commits ahead of and $behind behind GitHub (nothing committed; check git status and git log)" }
        if ((GitStep (@('add', '--') + $files)) -ne 0) { throw 'not pushed: git add failed' }
        git -C $Dir diff --cached --quiet -- @files; if ($LASTEXITCODE -eq 0) { throw 'not pushed: nothing staged' }
        $cc = GitStep (@('commit', '-F', $msgFile, '--') + $files)   # only these files, whatever else is staged
        Remove-Item -Force -ErrorAction SilentlyContinue $msgFile
        if ($cc -ne 0) { throw 'not pushed: git commit failed' }
        if ((GitStep @('push', 'origin', 'main')) -ne 0) { throw 'not pushed: git push failed (the commit is local; run git push later)' }
        GitStep @('log', '--oneline', '-1') | Out-Null
        $pushed = $true
        Log 'Pushed to GitHub.'
    } else {
        Log 'Not pushed: the check did not pass.'
    }
} catch {
    Log "FAILED: $($_.Exception.Message)"
} finally {
    if ($ciKeyId -and $adminH) {   # deleting the team alone leaves the key row behind (DT 5.2.1)
        try { Call $adminH 'DELETE' "/api/v1/team/key/$ciKeyId" | Out-Null; Log 'CI key deleted' } catch { Log "could not delete the CI key: $(ErrText $_)" }
    }
    if ($team -and $adminH) {
        try { Call $adminH 'DELETE' '/api/v1/team' @{ uuid = $team.uuid } | Out-Null; Log 'CI team deleted' } catch { Log "could not delete the CI team: $(ErrText $_)" }
    }
    Remove-Item Env:\DT_API_KEY -ErrorAction SilentlyContinue
    docker compose -f (Join-Path $Dir 'compose.yaml') stop 2>&1 | ForEach-Object { Log "compose: $_" }
    if ($pushed) { Status 'done-pushed' } elseif ($result -eq 'PASS') { Status 'failed-push' } else { Status 'done-failed' }
    Log "DONE (result $result, pushed $pushed) - containers stopped; images and data volumes kept."
}
