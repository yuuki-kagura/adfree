package git.shin.adfree.di

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import git.shin.adfree.core.CoreEngine
import git.shin.adfree.data.AdGuardRepository
import git.shin.adfree.model.parseDnsEndpoint
import git.shin.adfree.security.ThreatAnalyzer
import git.shin.adfree.ui.AdGuardViewModel
import git.shin.adfree.vpn.PrivateDns
import git.shin.adfree.vpn.VpnController

/**
 * Hand-rolled DI container (enough here, no Hilt needed).
 *
 * Initialisation order matters: [CoreEngine] must outlive everything, because
 * its native threads keep running after the service is destroyed.
 */
class AdGuardAppContainer(private val context: Context) {

    val coreEngine: CoreEngine by lazy {
        CoreEngine().also {
            // The core owns everything under the app's files directory from
            // here on: filters, scripts, the CA and the request-log database.
            // The call is idempotent, so a later restart is a no-op.
            runCatching { git.shin.adfree.core.coreSetDataRoot(context.filesDir.absolutePath) }
        }
    }

    val vpnController: VpnController by lazy { VpnController(context, coreEngine) }

    val repository: AdGuardRepository by lazy { AdGuardRepository(context, coreEngine) }

    /** Offline threat analysis via heuristics plus the filter engine; no API key. */
    val threatAnalyzer: ThreatAnalyzer by lazy { ThreatAnalyzer(repository, coreEngine) }

    /**
     * True while Private DNS is in strict ("provider hostname") mode.
     *
     * Automatic mode is intentionally excluded: there the resolver falls back
     * to plain UDP:53 after our DoT reset, so the filter still sees lookups.
     * Strict mode has no fallback, and RSTing port 853 would leave the device
     * with no resolution at all.
     */
    val privateDnsStrict: Boolean
        get() = PrivateDns.mode(context) == PrivateDns.Mode.STRICT

    fun provideViewModelFactory(): ViewModelProvider.Factory {
        return object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                if (modelClass.isAssignableFrom(AdGuardViewModel::class.java)) {
                    return AdGuardViewModel(
                        repository = repository,
                        vpnController = vpnController,
                        threatAnalyzer = threatAnalyzer,
                        coreEngine = coreEngine,
                        onConfigChanged = { syncConfigToEngine() },
                        isPrivateDnsStrict = { privateDnsStrict },
                    ) as T
                }
                throw IllegalArgumentException("Unknown ViewModel: ${modelClass.name}")
            }
        }
    }

    /** Push the current UI configuration down to the core. */
    fun syncConfigToEngine() {
        val settings = repository.settings.value
        // Android's strict Private DNS (DoT to a named provider) goes straight
        // to an outside resolver, so it never reaches the tunnel's DNS filter.
        // RSTing port 853 while the system resolver depends on it leaves the
        // device without any resolution — the user asked for Private DNS, so
        // let it through and let the UI explain that filtering is weaker.
        val privateDns = privateDnsStrict
        coreEngine.configure(
            mitmEnabled = settings.isHttpsFilteringEnabled,
            fullEch = settings.isFullEchEnabled,
            blockQuic = settings.blockQuic,
            blockDoh = settings.blockDoh,
            blockDot = settings.blockDot && !privateDns,
            adBlocking = settings.isAdBlockingEnabled,
            trackingProtection = settings.isTrackingProtectionEnabled,
            dnsProtection = settings.isDnsProtectionEnabled,
            smartFiltering = settings.isSmartFilteringEnabled,
            blockMode = settings.blockMode,
            logAllowed = settings.logAllowedRequests,
            ecoMode = settings.isEcoBatteryModeEnabled,
            httpsSkipHosts = settings.httpsSkipHosts,
            httpsOnlyHosts = settings.httpsOnlyHosts,
            httpsOnlyMode = settings.httpsOnlyMode,
            proxyEnabled = settings.proxy.enabled,
            proxyHost = settings.proxy.host,
            proxyPort = settings.proxy.port,
            proxyUsername = settings.proxy.username,
            proxyPassword = settings.proxy.password,
        )
        val provider = repository.dnsProviders.value
            .firstOrNull { it.id == settings.selectedDnsProviderId }
        if (provider != null) {
            parseDnsEndpoint(provider.address)?.let { endpoint ->
                coreEngine.setResolver(endpoint.host, endpoint.port)
            }
        }
    }
}
