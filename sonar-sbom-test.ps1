# SonarQube Advanced Security: import the C++ / firmware sample SBOMs (sonar.sca.sbomImportPaths) into
# SonarQube staging and collect what Sonar reports, for comparison with Dependency-Track.
#   sonar-sca-test\results.json        server version, per project: scanner exit code, CE task status, API answers
#   sonar-sca-test\<project>\*.json     raw answers of the SCA endpoints that responded
#   sonar-sca-test-log.txt              log (never contains the token)
# The token is asked for in a hidden prompt, kept in memory only and handed to the scanner as SONAR_TOKEN.
# sonar-sca-test\ is excluded from git: it holds data from an internal server.

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$Dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Log = Join-Path $Dir 'sonar-sca-test-log.txt'
$Out = Join-Path $Dir 'sonar-sca-test'
$Sonar = 'https://sonarqubestaging.hxgntech.com'
$ScannerVersion = '8.5.0.16571'
$Tools = Join-Path $Dir '.tools'
New-Item -ItemType Directory -Force -Path $Out, $Tools | Out-Null

function Log([string]$m) { $l = "$(Get-Date -Format 'HH:mm:ss') $m"; Write-Host $l; Add-Content -Path $Log -Value $l -Encoding UTF8 }
function Status([string]$s) { @{ stage = $s; time = (Get-Date).ToString('s') } | ConvertTo-Json | Set-Content -Path (Join-Path $Dir 'sonar-sca-test-status.json') -Encoding UTF8 }
function J($o) { return ($o | ConvertTo-Json -Depth 8 -Compress) }
function ErrText($e) { $t = $e.Exception.Message; if ($e.ErrorDetails -and $e.ErrorDetails.Message) { $t += ' | ' + $e.ErrorDetails.Message }; return $t }

Set-Content -Path $Log -Value "Sonar SBOM import test started $(Get-Date -Format s) against $Sonar" -Encoding UTF8
Status 'starting'

# ---------- token (hidden prompt, memory only) ----------
$sec = Read-Host -AsSecureString "SonarQube staging token (user token with Execute Analysis and Create Projects; input hidden)"
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
$Token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
if (-not $Token) { Log 'FAILED: no token entered'; Status 'failed-token'; exit 1 }
$H = @{ Authorization = "Bearer $Token" }

# ---------- server ----------
$results = [ordered]@{ run = (Get-Date).ToString('s'); server = $Sonar; projects = [ordered]@{} }
try { $results.version = (Invoke-WebRequest -UseBasicParsing -Uri "$Sonar/api/server/version" -Headers $H -TimeoutSec 30).Content; Log "server version: $($results.version)" }
catch { Log "FAILED: cannot reach $Sonar : $(ErrText $_)"; Status 'failed-server'; exit 1 }
try { $nav = Invoke-RestMethod -Uri "$Sonar/api/navigation/global" -Headers $H -TimeoutSec 30; $results.edition = $nav.edition; Log "edition: $($nav.edition)" } catch { Log "navigation/global: $(ErrText $_)" }
try { $v = Invoke-RestMethod -Uri "$Sonar/api/authentication/validate" -Headers $H -TimeoutSec 30; Log "token valid: $($v.valid)"; if (-not $v.valid) { Status 'failed-token'; exit 1 } } catch { Log "authentication/validate: $(ErrText $_)" }
foreach ($p in @('/api/v2/api-docs', '/api/v2/openapi')) {
    try { $r = Invoke-WebRequest -UseBasicParsing -Uri "$Sonar$p" -Headers $H -TimeoutSec 60
          [IO.File]::WriteAllText((Join-Path $Out 'sonar-api-v2.json'), $r.Content); Log "saved Web API v2 description from $p"; break } catch { Log "GET $p : $(ErrText $_)" }
}

try { $en = Invoke-RestMethod -Uri "$Sonar/api/v2/sca/enabled" -Headers $H -TimeoutSec 30; $results.scaEnabled = $en.enabled; Log "SCA (Advanced Security) enabled: $($en.enabled)"
      if (-not $en.enabled) { Log 'FAILED: SCA is not licensed or not enabled on this server (Administration > Configuration > General settings > Advanced Security)'; Status 'failed-sca-disabled'; $results | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $Out 'results.json') -Encoding UTF8; exit 1 } }
catch { Log "sca/enabled: $(ErrText $_)" }

# ---------- scanner (Windows build with its own JRE), checksum-checked ----------
Status 'scanner'
$zip = Join-Path $Tools "sonar-scanner-cli-$ScannerVersion-windows-x64.zip"
$url = "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-$ScannerVersion-windows-x64.zip"
if (-not (Test-Path $zip)) { Log "downloading $url"; try { Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip -TimeoutSec 600 } catch { Log "FAILED download: $(ErrText $_)"; Status 'failed-scanner'; exit 1 } }
try { $c = (Invoke-WebRequest -UseBasicParsing -Uri "$url.sha256" -TimeoutSec 60).Content
      if ($c -is [byte[]]) { $c = [Text.Encoding]::ASCII.GetString($c) }   # served as octet-stream
      $want = ("$c".Trim() -split '\s+')[0].ToLower()
      $got = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
      if ($want -ne $got) { Log "FAILED: scanner checksum mismatch ($got vs $want)"; Remove-Item $zip; Status 'failed-scanner'; exit 1 }
      Log 'scanner checksum OK' } catch { Log "WARNING: no published checksum checked: $(ErrText $_)" }
$scanDir = Join-Path $Tools "sonar-scanner-$ScannerVersion-windows-x64"
if (-not (Test-Path $scanDir)) { Expand-Archive -Path $zip -DestinationPath $Tools -Force }
$scanner = Join-Path $scanDir 'bin\sonar-scanner.bat'
if (-not (Test-Path $scanner)) { Log "FAILED: $scanner not found"; Status 'failed-scanner'; exit 1 }

# ---------- one Sonar project per SBOM ----------
$sboms = [ordered]@{
    'cpp-sbom-test-fw-conanpurl'    = 'cpp-sboms\dt-variants\fw-build-manifest-conanpurl.cdx.json'
    'cpp-sbom-test-cmake-conanpurl' = 'cpp-sboms\dt-variants\cmake-build-derived-conanpurl.cdx.json'
    'cpp-sbom-test-fw-githubpurl'   = 'cpp-sboms\sboms\fw-build-manifest.cdx.json'
}
$env:SONAR_TOKEN = $Token
Add-Type -AssemblyName System.Net.Http
$script:Http = New-Object System.Net.Http.HttpClient
$script:Http.Timeout = [TimeSpan]::FromSeconds(120)
# use the Windows certificate store, so an internal CA behind the staging server is trusted
$env:SONAR_SCANNER_OPTS = '-Djavax.net.ssl.trustStoreType=Windows-ROOT'
foreach ($key in $sboms.Keys) {
    Status "scan $key"
    $e = [ordered]@{ sbom = $sboms[$key] }
    $work = Join-Path $Out $key
    if (Test-Path $work) { Get-ChildItem $work -Recurse -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    Copy-Item (Join-Path $Dir $sboms[$key]) (Join-Path $work 'sbom.cdx.json')
    Push-Location $work
    $scanLog = Join-Path $work 'scanner.log'
    & $scanner "-Dsonar.host.url=$Sonar" "-Dsonar.projectKey=$key" "-Dsonar.projectName=$key" '-Dsonar.sources=.' `
        '-Dsonar.inclusions=sbom.cdx.json' '-Dsonar.scm.disabled=true' '-Dsonar.sca.enabled=true' '-Dsonar.sca.cfamily=true' `
        '-Dsonar.sca.sbomImportPaths=sbom.cdx.json' *> $scanLog
    $e.scannerExit = $LASTEXITCODE
    Pop-Location
    Log "$key scanner exit $($e.scannerExit) (log: sonar-sca-test\$key\scanner.log)"
    $e.scannerSca = @(Select-String -Path $scanLog -Pattern 'SCA|sbom|SBOM|dependenc' | Select-Object -First 15 | ForEach-Object { $_.Line.Trim() })
    $rt = Join-Path $work '.scannerwork\report-task.txt'
    if (Test-Path $rt) {
        $ce = (Get-Content $rt | Where-Object { $_ -like 'ceTaskUrl=*' }) -replace '^ceTaskUrl=', ''
        for ($i = 0; $i -lt 60; $i++) {
            try { $t = Invoke-RestMethod -Uri $ce -Headers $H -TimeoutSec 30; $e.ceStatus = $t.task.status; if ($t.task.status -in @('SUCCESS', 'FAILED', 'CANCELED')) { $e.ceError = $t.task.errorMessage; break } } catch { $e.ceStatus = "poll error: $(ErrText $_)" }
            Start-Sleep 5
        }
        Log "$key background task: $($e.ceStatus) $($e.ceError)"
    }
    # SCA analysis runs after the background task: wait for /api/v2/sca/analyses (internal API) to finish
    for ($i = 0; $i -lt 60; $i++) {
        try { $an = Invoke-RestMethod -Uri "$Sonar/api/v2/sca/analyses?projectKey=$key" -Headers $H -TimeoutSec 30; $e.scaAnalysis = $an
              if ($an.status -in @('COMPLETED', 'FAILED')) { break } } catch { $e.scaAnalysis = "poll: $(ErrText $_)" }
        Start-Sleep 5
    }
    Log "$key SCA analysis: $(J $e.scaAnalysis)"
    function Save([string]$name, [string]$path, [string]$accept = 'application/json') {
        # .NET HttpClient: Windows PowerShell 5.1 can refuse a custom Accept header on Invoke-WebRequest
        try { $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, "$Sonar$path")
              $req.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue('Bearer', $Token)
              [void]$req.Headers.Accept.ParseAdd($accept)
              $resp = $script:Http.SendAsync($req).GetAwaiter().GetResult()
              $txt = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
              [IO.File]::WriteAllText((Join-Path $work "$name.json"), $txt)
              return "$([int]$resp.StatusCode) ($($txt.Length) chars)" }
        catch { return "error $(ErrText $_)" }
    }
    $e.api = [ordered]@{}
    $e.api.releases = Save 'releases' "/api/v2/sca/releases?projectKey=$key&pageSize=500&pageIndex=1"
    $e.api.issuesReleases = Save 'issues-releases' "/api/v2/sca/issues-releases?projectKey=$key&pageSize=500&pageIndex=1"
    $e.api.riskVex = Save 'risk-report.vex.cdx' "/api/v2/sca/risk-reports?component=$key" 'application/vnd.cyclonedx+json'
    $e.api.riskJson = Save 'risk-report' "/api/v2/sca/risk-reports?component=$key"
    $e.api.sbom = Save 'sbom-report.cdx' "/api/v2/sca/sbom-reports?component=$key&type=cyclonedx&onlyProductionScope=false" 'application/vnd.cyclonedx+json'
    Log "$key API answers: $(($e.api.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', ')"
    # Identifier test without a scan: what does Sonar know about each package URL?
    if ($key -eq 'cpp-sbom-test-fw-conanpurl') {
        $purls = @('pkg:conan/zlib@1.2.11', 'pkg:conan/openssl@1.1.1k', 'pkg:conan/cjson@1.7.10', 'pkg:conan/expat@2.4.1',
                   'pkg:conan/fmt@8.0.0', 'pkg:conan/nlohmann_json@3.9.1', 'pkg:github/madler/zlib@v1.2.11',
                   'pkg:github/openssl/openssl@OpenSSL_1_1_1k', 'pkg:generic/busybox@1.33.1', 'pkg:generic/glibc@2.39',
                   'pkg:vcpkg/zlib@1.3.2', 'pkg:deb/ubuntu/libc6@2.39-0ubuntu8.9?distro=ubuntu-24.04')
        try { $body = [Text.Encoding]::UTF8.GetBytes((@{ projectKey = $key; purls = $purls } | ConvertTo-Json -Compress))
              $rr = Invoke-WebRequest -UseBasicParsing -Method Post -Uri "$Sonar/api/v2/sca/release-research/releases" -Headers $H -ContentType 'application/json' -Body $body -TimeoutSec 120
              $txt = $rr.Content; if ($txt -is [byte[]]) { $txt = [Text.Encoding]::UTF8.GetString($txt) }
              [IO.File]::WriteAllText((Join-Path $Out 'release-research.json'), $txt); Log "release-research: 200 ($($txt.Length) chars)" }
        catch { Log "release-research: $(ErrText $_)" }
    }
    $results.projects[$key] = $e
}
Remove-Item Env:\SONAR_TOKEN -ErrorAction SilentlyContinue
$script:Http.Dispose()
$Token = $null; $H = $null
$results | ConvertTo-Json -Depth 8 | Set-Content -Path (Join-Path $Out 'results.json') -Encoding UTF8
Log "DONE - open $Sonar and look at the projects cpp-sbom-test-* (Dependencies / Dependency risks)"
Status 'done'
