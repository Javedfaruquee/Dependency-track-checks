# conan audit test: checks the C++ test SBOMs and single references against Conan Audit (ConanCenter provider,
# vulnerability data from JFrog). The token is typed here (hidden) and passed to a throw-away container as an
# environment variable; it is not written to disk or logged. Uses about 20 of the 100 free queries per day.
$ErrorActionPreference = 'Continue'
$Dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Log = Join-Path $Dir 'conan-audit-log.txt'
function Log([string]$m) { $l = "$(Get-Date -Format 'HH:mm:ss') $m"; Write-Host $l; Add-Content -Path $Log -Value $l -Encoding UTF8 }
Set-Content -Path $Log -Value "conan audit test started $(Get-Date -Format s)" -Encoding UTF8
$ss = Read-Host 'Conan Audit token (input hidden)' -AsSecureString
$b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
try { $env:CONAN_AUDIT_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
if (-not $env:CONAN_AUDIT_TOKEN) { Log 'FAILED: no token entered'; exit 1 }
$out = Join-Path $Dir 'conan-audit'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$sboms = @('cpp-conan-native', 'cpp-conan-normalised', 'cpp-vcpkg-normalised', 'cpp-vendored-declared')
if (Test-Path (Join-Path $Dir 'sboms\cpp-nvd-gap.cdx.json')) { $sboms += 'cpp-nvd-gap' }
$refs = @('openssl/1.1.1k', 'zlib/1.2.11', 'libpng/1.6.34', 'cjson/1.7.10', 'fmt/8.0.0', 'cjson/1.7.19', 'zlib/1.3.1')
$sh = @(
  'set -e',
  'pip install -q --disable-pip-version-check conan >/dev/null 2>&1',
  'conan --version',
  'conan profile detect >/dev/null 2>&1 || true',
  'conan audit provider auth conancenter --token="$CONAN_AUDIT_TOKEN" >/dev/null && echo "provider authenticated"',
  'set +e'
)
foreach ($s in $sboms) { $sh += "echo SBOM $s; conan audit list -s /work/sboms/$s.cdx.json -f json --out-file /work/conan-audit/sbom-$s.json 2>/work/conan-audit/sbom-$s.err; echo exit=`$?" }
foreach ($r in $refs) { $n = $r -replace '[/@]', '_'; $sh += "echo REF $r; conan audit list $r -f json --out-file /work/conan-audit/ref-$n.json 2>/work/conan-audit/ref-$n.err; echo exit=`$?" }
$script = ($sh -join "`n")
[IO.File]::WriteAllText((Join-Path $out 'run.sh'), $script.Replace("`r", ''))
Log 'running conan audit in a python:3.13-slim container (installs the latest Conan 2)'
docker run --rm -e CONAN_AUDIT_TOKEN -v "${Dir}:/work" python:3.13-slim sh /work/conan-audit/run.sh 2>&1 | ForEach-Object { Log "conan: $_" }
$env:CONAN_AUDIT_TOKEN = $null
# summary
foreach ($f in (Get-ChildItem $out -Filter '*.json')) {
    $txt = Get-Content $f.FullName -Raw
    $cves = @([regex]::Matches($txt, 'CVE-\d{4}-\d{4,}') | ForEach-Object { $_.Value } | Sort-Object -Unique)
    Log "$($f.BaseName): $($cves.Count) distinct CVEs  $((($cves | Select-Object -First 8) -join ' '))"
}
foreach ($f in (Get-ChildItem $out -Filter '*.err')) { $e = (Get-Content $f.FullName -Raw); if ($e -and $e.Trim()) { Log "$($f.BaseName) stderr: $($e.Trim().Substring(0, [Math]::Min(300, $e.Trim().Length)))" } }
Log 'DONE'
