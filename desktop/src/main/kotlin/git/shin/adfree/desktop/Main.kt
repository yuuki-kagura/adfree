package git.shin.adfree.desktop

import git.shin.adfree.model.DnsProvider
import git.shin.adfree.model.ProtocolType
import git.shin.adfree.update.UpdateUiState
import git.shin.adfree.update.isNewerVersion
import git.shin.adfree.update.normalizeVersion
import git.shin.adfree.update.shouldOfferUpdate

/**
 * Console smoke test for the shared domain on a host JVM: the version rules,
 * the update state machine and a provider model all run without any Android
 * class on the classpath.
 */
fun main() {
    println("AdFree shared core on ${System.getProperty("os.name")}")
    println("normalizeVersion(\"v1.2.3-rc1\") = ${normalizeVersion("v1.2.3-rc1")}")
    println("isNewerVersion(\"1.2.0\", \"1.1.1\") = ${isNewerVersion("1.2.0", "1.1.1")}")
    println("shouldOfferUpdate(\"v1.2.0\", \"1.1.1\") = ${shouldOfferUpdate("v1.2.0", "1.1.1")}")

    val provider = DnsProvider(
        id = "adguard",
        name = "AdGuard DNS",
        address = "94.140.14.14",
        type = ProtocolType.DNS_UDP,
        description = "Smoke-test row from the shared model",
    )
    println("DnsProvider -> ${provider.name} (${provider.address}, ${provider.type})")

    val state: UpdateUiState = UpdateUiState.Idle
    println("UpdateUiState -> $state")

    if (!runEngineProbe()) {
        System.exit(1)
    }
}
