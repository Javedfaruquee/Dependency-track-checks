#!/usr/bin/env bash
# Check an SBOM's SignPath signature and its timestamp (for customers, auditors and the SBOM manager intake).
# usage: verify-sbom.sh <sbom.cdx.json> <signer-ca-chain.pem> [tsa-ca-chain.pem]
set -euo pipefail
sbom=$1 ca=$2 tsa=${3:-}
openssl cms -verify -binary -content "$sbom" -in "$sbom.p7s" -inform PEM -CAfile "$ca" -purpose any -out /dev/null
if [ -n "$tsa" ] && [ -f "$sbom.tsr" ]; then
  openssl ts -verify -data "$sbom.p7s" -in "$sbom.tsr" -CAfile "$tsa"
fi
