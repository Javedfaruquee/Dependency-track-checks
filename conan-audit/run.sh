set -e
pip install -q --disable-pip-version-check conan >/dev/null 2>&1
conan --version
conan profile detect >/dev/null 2>&1 || true
conan audit provider auth conancenter --token="$CONAN_AUDIT_TOKEN" >/dev/null && echo "provider authenticated"
set +e
echo SBOM cpp-conan-native; conan audit list -s /work/sboms/cpp-conan-native.cdx.json -f json --out-file /work/conan-audit/sbom-cpp-conan-native.json 2>/work/conan-audit/sbom-cpp-conan-native.err; echo exit=$?
echo SBOM cpp-conan-normalised; conan audit list -s /work/sboms/cpp-conan-normalised.cdx.json -f json --out-file /work/conan-audit/sbom-cpp-conan-normalised.json 2>/work/conan-audit/sbom-cpp-conan-normalised.err; echo exit=$?
echo SBOM cpp-vcpkg-normalised; conan audit list -s /work/sboms/cpp-vcpkg-normalised.cdx.json -f json --out-file /work/conan-audit/sbom-cpp-vcpkg-normalised.json 2>/work/conan-audit/sbom-cpp-vcpkg-normalised.err; echo exit=$?
echo SBOM cpp-vendored-declared; conan audit list -s /work/sboms/cpp-vendored-declared.cdx.json -f json --out-file /work/conan-audit/sbom-cpp-vendored-declared.json 2>/work/conan-audit/sbom-cpp-vendored-declared.err; echo exit=$?
echo SBOM cpp-nvd-gap; conan audit list -s /work/sboms/cpp-nvd-gap.cdx.json -f json --out-file /work/conan-audit/sbom-cpp-nvd-gap.json 2>/work/conan-audit/sbom-cpp-nvd-gap.err; echo exit=$?
echo REF openssl/1.1.1k; conan audit list openssl/1.1.1k -f json --out-file /work/conan-audit/ref-openssl_1.1.1k.json 2>/work/conan-audit/ref-openssl_1.1.1k.err; echo exit=$?
echo REF zlib/1.2.11; conan audit list zlib/1.2.11 -f json --out-file /work/conan-audit/ref-zlib_1.2.11.json 2>/work/conan-audit/ref-zlib_1.2.11.err; echo exit=$?
echo REF libpng/1.6.34; conan audit list libpng/1.6.34 -f json --out-file /work/conan-audit/ref-libpng_1.6.34.json 2>/work/conan-audit/ref-libpng_1.6.34.err; echo exit=$?
echo REF cjson/1.7.10; conan audit list cjson/1.7.10 -f json --out-file /work/conan-audit/ref-cjson_1.7.10.json 2>/work/conan-audit/ref-cjson_1.7.10.err; echo exit=$?
echo REF fmt/8.0.0; conan audit list fmt/8.0.0 -f json --out-file /work/conan-audit/ref-fmt_8.0.0.json 2>/work/conan-audit/ref-fmt_8.0.0.err; echo exit=$?
echo REF cjson/1.7.19; conan audit list cjson/1.7.19 -f json --out-file /work/conan-audit/ref-cjson_1.7.19.json 2>/work/conan-audit/ref-cjson_1.7.19.err; echo exit=$?
echo REF zlib/1.3.1; conan audit list zlib/1.3.1 -f json --out-file /work/conan-audit/ref-zlib_1.3.1.json 2>/work/conan-audit/ref-zlib_1.3.1.err; echo exit=$?