#!/usr/bin/env bash
# One entry point for GitHub Actions, GitLab CI and TeamCity: generate -> gate -> sign -> publish.
#   sbom-release.sh cmake    <source-dir> <build-dir> <product-binary> <out-dir>
#   sbom-release.sh firmware <build-manifest.json> <fw-dir> <third-party-src-dir> <out-dir>
# Env:
#   SBOMQS              sbomqs binary (default: installed with install-sbomqs.sh)
#   CMAKE_TARGET        CMake target name if it differs from the binary name
#   ARTIFACT_BASE_URL   artifact repository base used in the SBOM (…/<product>/<version>/<file>)
#   SOURCE_URL          repository URL of the product (CMake)
#   SIGN_SBOM=true      sign with sign-sbom.sh (release builds only; needs the SignPath variables)
#   DT_URL, DT_API_KEY  upload the SBOM to Dependency-Track (optional)
#   JF_TARGET           upload SBOM, signature and gate report with the JFrog CLI, e.g. "sbom-local/<product>/<version>/" (optional)
#   SBOM_CPE_EXCEPTIONS JSON file of third-party components allowed without a CPE, each with a reason (optional)
#   OPENVEX_FILE        OpenVEX for this release (e.g. from Yocto sbom-cve-check); converted and uploaded to DT (optional)
#   VEX_FILE            CycloneDX VEX for this release, uploaded to DT as is (optional; OPENVEX_FILE wins)
#   VEX_FAIL_ON_PENDING=true  fail when a VEX statement cannot be applied yet (unknown CVE, no findings)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
gen=${SBOM_GENERATORS:-"$here/../generators"}
kind=$1; shift
SBOMQS=${SBOMQS:-$(bash "$here/install-sbomqs.sh" "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/sbomqs")}
gate_extra=()
if [ -n "${SBOM_CPE_EXCEPTIONS:-}" ]; then gate_extra+=(--cpe-exceptions "$SBOM_CPE_EXCEPTIONS"); fi
case "$kind" in
  cmake)
    src=$1 build=$2 bin=$3 out=$4; mkdir -p "$out"
    sbom="$out/$(basename "$bin").cdx.json"
    python3 "$gen/cmake-sbom.py" "$src" "$build" "$bin" "$sbom"
    python3 "$gen/sbom-gate.py" --sbom "$sbom" --sbomqs "$SBOMQS" ${gate_extra[@]+"${gate_extra[@]}"} \
      --link-txt "$build/CMakeFiles/${CMAKE_TARGET:-$(basename "$bin")}.dir/link.txt" --report "$out/sbom-gate.json" ;;
  firmware)
    man=$1 fw=$2 srcd=$3 out=$4; mkdir -p "$out"
    sbom="$out/$(python3 -c 'import json,sys; p=json.load(open(sys.argv[1]))["product"]; print(p["name"]+"-"+p["version"])' "$man").cdx.json"
    python3 "$gen/fw-sbom.py" "$man" "$fw" "$srcd" "$sbom"
    python3 "$gen/sbom-gate.py" --sbom "$sbom" --sbomqs "$SBOMQS" ${gate_extra[@]+"${gate_extra[@]}"} \
      --rootfs "$fw/rootfs" --report "$out/sbom-gate.json" ;;
  *) echo "unknown kind: $kind (cmake|firmware)" >&2; exit 2 ;;
esac
if [ "${SIGN_SBOM:-false}" = "true" ]; then bash "$here/sign-sbom.sh" "$sbom"; fi
vex=""
if [ -n "${OPENVEX_FILE:-}" ]; then
  # policy checks run here, so a bad VEX fails the build even before anything is uploaded
  vex="$out/$(basename "$sbom" .cdx.json).vex.cdx.json"
  python3 "$gen/openvex-to-cdx-vex.py" --sbom "$sbom" --openvex "$OPENVEX_FILE" --out "$vex"
elif [ -n "${VEX_FILE:-}" ]; then
  vex="$VEX_FILE"
fi
if [ -n "$vex" ] && { [ -z "${DT_URL:-}" ] || [ -z "${DT_API_KEY:-}" ]; }; then
  echo "a VEX is set (OPENVEX_FILE or VEX_FILE) but DT_URL or DT_API_KEY is not: the VEX would never reach Dependency-Track" >&2
  exit 2
fi
if [ -n "${DT_URL:-}" ] && [ -n "${DT_API_KEY:-}" ]; then
  IFS=$'\t' read -r pname pver < <(python3 -c 'import json,sys; c=json.load(open(sys.argv[1]))["metadata"]["component"]; print(c["name"], c["version"], sep="\t")' "$sbom")
  # the key goes through a file descriptor, not the command line
  resp=$(curl -fsS -X POST "$DT_URL/api/v1/bom" -H @<(printf 'X-Api-Key: %s\n' "$DT_API_KEY") \
    --form-string "projectName=$pname" --form-string "projectVersion=$pver" --form-string "autoCreate=true" \
    -F "bom=@$sbom")
  read -r token puuid < <(printf '%s' "$resp" | python3 -c 'import json,sys; r=json.load(sys.stdin); print(r.get("token") or "-", r.get("projectUuid") or "-")')
  echo "uploaded to Dependency-Track: $pname $pver (token $token)" >&2
  if [ -n "$vex" ]; then
    if [ "$token" = "-" ]; then echo "the BOM upload returned no token, so the VEX can't wait for the analysis" >&2; exit 2; fi
    # waits for the BOM analysis, uploads, and checks every statement (a VEX sent too early is dropped by DT)
    vex_args=(--url "$DT_URL" --vex "$vex" --bom-token "$token" --report "$out/vex-report.json")
    if [ "$puuid" != "-" ]; then vex_args+=(--project-uuid "$puuid"); else vex_args+=(--project-name "$pname" --project-version "$pver"); fi
    if [ "${VEX_FAIL_ON_PENDING:-false}" = "true" ]; then vex_args+=(--fail-on-pending); fi
    python3 "$here/dt-vex-upload.py" "${vex_args[@]}"
  fi
fi
if [ -n "${JF_TARGET:-}" ] && command -v jf >/dev/null; then
  for f in "$sbom" "$sbom.p7s" "$sbom.tsr" "$out/sbom-gate.json" "${vex:-}" "$out/vex-report.json"; do
    if [ -n "$f" ] && [ -f "$f" ]; then jf rt upload "$f" "$JF_TARGET"; fi
  done
fi
echo "SBOM: $sbom" >&2
