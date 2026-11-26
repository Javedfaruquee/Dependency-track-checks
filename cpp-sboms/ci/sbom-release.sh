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
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
gen=${SBOM_GENERATORS:-"$here/../generators"}
kind=$1; shift
SBOMQS=${SBOMQS:-$(bash "$here/install-sbomqs.sh" "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/sbomqs")}
case "$kind" in
  cmake)
    src=$1 build=$2 bin=$3 out=$4; mkdir -p "$out"
    sbom="$out/$(basename "$bin").cdx.json"
    python3 "$gen/cmake-sbom.py" "$src" "$build" "$bin" "$sbom"
    python3 "$gen/sbom-gate.py" --sbom "$sbom" --sbomqs "$SBOMQS" \
      --link-txt "$build/CMakeFiles/${CMAKE_TARGET:-$(basename "$bin")}.dir/link.txt" --report "$out/sbom-gate.json" ;;
  firmware)
    man=$1 fw=$2 srcd=$3 out=$4; mkdir -p "$out"
    sbom="$out/$(python3 -c 'import json,sys; p=json.load(open(sys.argv[1]))["product"]; print(p["name"]+"-"+p["version"])' "$man").cdx.json"
    python3 "$gen/fw-sbom.py" "$man" "$fw" "$srcd" "$sbom"
    python3 "$gen/sbom-gate.py" --sbom "$sbom" --sbomqs "$SBOMQS" --rootfs "$fw/rootfs" --report "$out/sbom-gate.json" ;;
  *) echo "unknown kind: $kind (cmake|firmware)" >&2; exit 2 ;;
esac
if [ "${SIGN_SBOM:-false}" = "true" ]; then bash "$here/sign-sbom.sh" "$sbom"; fi
if [ -n "${DT_URL:-}" ] && [ -n "${DT_API_KEY:-}" ]; then
  read -r pname pver < <(python3 -c 'import json,sys; c=json.load(open(sys.argv[1]))["metadata"]["component"]; print(c["name"], c["version"])' "$sbom")
  curl -fsS -X POST "$DT_URL/api/v1/bom" -H "X-Api-Key: $DT_API_KEY" \
    --form-string "projectName=$pname" --form-string "projectVersion=$pver" --form-string "autoCreate=true" \
    -F "bom=@$sbom" >/dev/null && echo "uploaded to Dependency-Track: $pname $pver" >&2
fi
if [ -n "${JF_TARGET:-}" ] && command -v jf >/dev/null; then
  for f in "$sbom" "$sbom.p7s" "$sbom.tsr" "$out/sbom-gate.json"; do [ -f "$f" ] && jf rt upload "$f" "$JF_TARGET"; done
fi
echo "SBOM: $sbom" >&2
