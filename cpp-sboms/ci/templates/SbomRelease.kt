// TeamCity Kotlin DSL template. Add it to the project (templates(SbomRelease)) and attach it to the
// build configuration; the step runs after the build steps, in the same checkout directory.
// Parameters to set per build configuration: sbom.kind, sbom.args. Tokens are TeamCity password
// parameters (credentialsJSON tokens), never plain text in the DSL.
import jetbrains.buildServer.configs.kotlin.*
import jetbrains.buildServer.configs.kotlin.buildSteps.script

object SbomRelease : Template({
    id("SbomRelease")
    name = "SBOM release gate"

    params {
        param("sbom.kind", "cmake")
        param("sbom.args", ". build build/install/bin/sensorhub-gateway sbom-out")
        param("sbom.tooling.repo", "https://git.example.com/security/sbom-tooling.git")
        param("sbom.tooling.ref", "v1.0.0")
        // Sign only on release builds: set to true in the release configuration
        param("env.SIGN_SBOM", "false")
        param("env.SIGNPATH_ORGANIZATION_ID", "")
        param("env.SIGNPATH_PROJECT_SLUG", "")
        param("env.SIGNPATH_SIGNING_POLICY_SLUG", "")
        param("env.PKCS11_MODULE_PATH", "/opt/signpath/libSignPath.Cryptoki.so")
        param("env.SIGNING_CERT_PEM", "/opt/signpath/signing-cert.pem")
        param("env.TSA_URL", "")
        param("env.ARTIFACT_BASE_URL", "")
        param("env.DT_URL", "")
        password("env.SIGNPATH_API_TOKEN", "credentialsJSON:00000000-0000-0000-0000-000000000000", display = ParameterDisplay.HIDDEN)
        password("env.DT_API_KEY", "credentialsJSON:00000000-0000-0000-0000-000000000001", display = ParameterDisplay.HIDDEN)
    }

    steps {
        script {
            id = "sbom_release"
            name = "SBOM: generate, gate, sign, publish"
            scriptContent = """
                set -euo pipefail
                rm -rf .sbom-tooling
                git clone --depth 1 --branch "%sbom.tooling.ref%" "%sbom.tooling.repo%" .sbom-tooling
                export SOURCE_URL="%vcsroot.url%"
                bash .sbom-tooling/ci/sbom-release.sh %sbom.kind% %sbom.args%
            """.trimIndent()
        }
    }

    artifactRules = "sbom-out => sbom"
    // The release configuration (env.SIGN_SBOM=true) also needs an agent with the SignPath Cryptoki
    // provider, for example: requirements { exists("signpath.cryptoki") }  (set in buildAgent.properties)
})
