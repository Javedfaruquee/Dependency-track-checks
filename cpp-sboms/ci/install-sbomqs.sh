#!/usr/bin/env bash
# Install a pinned sbomqs release and check it against the published checksum.
# usage: install-sbomqs.sh [dest-dir]   (prints the binary path)
set -euo pipefail
VER=${SBOMQS_VERSION:-2.1.3}
SHA=${SBOMQS_SHA256:-c96f07a6a27314c1c268af141af04f1c1b49e61400d7058f6419ca4f7f3bdd6b}   # sbomqs_2.1.3_Linux_x86_64.tar.gz
dest=${1:-"$PWD/.tools"}; mkdir -p "$dest"
tgz="$dest/sbomqs_${VER}_Linux_x86_64.tar.gz"
url=${SBOMQS_URL:-"https://github.com/interlynk-io/sbomqs/releases/download/v${VER}/sbomqs_${VER}_Linux_x86_64.tar.gz"}
[ -f "$tgz" ] || curl -fsSL -o "$tgz" "$url"
echo "$SHA  $tgz" | sha256sum -c - >&2
tar -xzf "$tgz" -C "$dest" sbomqs
echo "$dest/sbomqs"
