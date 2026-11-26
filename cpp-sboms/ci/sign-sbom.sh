#!/usr/bin/env bash
# Sign an SBOM with SignPath (Code Signing Gateway, hash-based) and timestamp the signature.
#   <sbom>.p7s  detached CMS signature (PEM) that carries the signing certificate
#   <sbom>.tsr  RFC 3161 timestamp over the signature (we are responsible for timestamps
#               with hash-based signing: https://docs.signpath.io/crypto-providers#timestamps)
# Agent needs: OpenSSL 3 with libp11 (pkcs11 engine) and the SignPath Cryptoki provider.
# Env (CI secrets/variables):
#   PKCS11_MODULE_PATH            full path to libSignPath.Cryptoki.so
#   SIGNPATH_ORGANIZATION_ID      SignPath organisation ID
#   SIGNPATH_API_TOKEN            CI user API token (secret)
#   SIGNPATH_PROJECT_SLUG, SIGNPATH_SIGNING_POLICY_SLUG   the key to sign with
#   SIGNING_CERT_PEM              the policy's certificate in PEM (download from SignPath, convert with
#                                 openssl x509 -inform DER -in certificate.cer -outform PEM -out certificate.pem)
#   TSA_URL                       RFC 3161 timestamp authority (for example the issuing CA's TSA)
set -euo pipefail
sbom=$1
: "${PKCS11_MODULE_PATH:?}" "${SIGNPATH_ORGANIZATION_ID:?}" "${SIGNPATH_API_TOKEN:?}"
: "${SIGNPATH_PROJECT_SLUG:?}" "${SIGNPATH_SIGNING_POLICY_SLUG:?}" "${SIGNING_CERT_PEM:?}" "${TSA_URL:?}"
export PKCS11_MODULE_PATH SIGNPATH_ORGANIZATION_ID SIGNPATH_API_TOKEN
# Command as given in the SignPath docs (crypto-providers/cryptoki#openssl-cms)
openssl cms -engine pkcs11 -signer "$SIGNING_CERT_PEM" \
  -inkey "pkcs11:id=$SIGNPATH_PROJECT_SLUG/$SIGNPATH_SIGNING_POLICY_SLUG;type=private;pin-value=CONFIG" \
  -keyform engine -sign -binary -in "$sbom" -noattr -out "$sbom.p7s" -outform PEM
# Timestamp the signature (OpenSSL ts, not part of SignPath's docs)
openssl ts -query -data "$sbom.p7s" -sha256 -cert -out "$sbom.tsq"
curl -fsS -H 'Content-Type: application/timestamp-query' --data-binary @"$sbom.tsq" "$TSA_URL" -o "$sbom.tsr"
openssl ts -reply -in "$sbom.tsr" -text | grep -E 'Time stamp|Status:' >&2
rm -f "$sbom.tsq"
echo "signed: $sbom.p7s, timestamp: $sbom.tsr" >&2
