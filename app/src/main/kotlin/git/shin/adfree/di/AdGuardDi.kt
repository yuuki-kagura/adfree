package git.shin.adfree.di

import android.content.Context
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import git.shin.adfree.core.ConfigOutcome
import git.shin.adfree.core.ConfigWarning
import git.shin.adfree.core.CoreEngine
import git.shin.adfree.data.AdGuardRepository
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

    val repository: AdGuardRepository by lazy {
        // The repository writes state; reconfiguring the engine is the
        // container's job because it owns the Private DNS system setting.
        AdGuardRepository(context, coreEngine) { applyConfig() }
    }

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
                        onConfigChanged = { applyConfig() },
                        isPrivateDnsStrict = { privateDnsStrict },
                    ) as T
                }
                throw IllegalArgumentException("Unknown ViewModel: ${modelClass.name}")
            }
        }
    }

    /**
     * Rebuilds the engine from the persisted state.
     *
     * Android's strict Private DNS (DoT to a named provider) goes straight to
     * an outside resolver, so it never reaches the tunnel's DNS filter. RSTing
     * port 853 while the system resolver depends on it leaves the device
     * without any resolution — the user asked for Private DNS, so the core
     * carves it out and the UI explains that filtering is weaker.
     */
    fun applyConfig(): ConfigOutcome {
        val outcome = coreEngine.applyConfig(privateDnsStrict)
        if (outcome.warning != ConfigWarning.NONE) {
            Log.w(TAG, "config fell back: ${outcome.warning}")
        }
        return outcome
    }

    private companion object {
        private const val TAG = "AdGuardDi"
    }
}
