package git.shin.adfree.di

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.util.Log
import git.shin.adfree.core.ConfigOutcome
import git.shin.adfree.core.ConfigWarning
import git.shin.adfree.core.CoreEngine
import git.shin.adfree.data.AdGuardRepository
import git.shin.adfree.security.ThreatAnalyzer
import git.shin.adfree.ui.AdGuardViewModel
import git.shin.adfree.update.AppUpdateController
import git.shin.adfree.vpn.PrivateDns
import git.shin.adfree.vpn.VpnController
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.net.Inet4Address

/**
 * Hand-rolled DI container (enough here, no Hilt needed).
 *
 * Initialisation order matters: [CoreEngine] must outlive everything, because
 * its native threads keep running after the service is destroyed.
 */
class AdGuardAppContainer(private val context: Context) {

    val coreEngine: CoreEngine by lazy {
        CoreEngine(
            log = git.shin.adfree.platform.LogSink { Log.i("AdFreeCore", it) },
            caExporter = git.shin.adfree.core.AndroidCaExporter(),
            caTrustChecker = git.shin.adfree.core.AndroidCaTrustChecker(),
        ).also {
            // The core owns everything under the app's files directory from
            // here on: filters, scripts, the CA and the request-log database.
            // The call is idempotent, so a later restart is a no-op.
            runCatching { git.shin.adfree.core.coreSetDataRoot(context.filesDir.absolutePath) }
        }
    }

    val vpnController: VpnController by lazy { VpnController(context, coreEngine) }

    val platformHost: git.shin.adfree.platform.AndroidPlatformHost by lazy {
        git.shin.adfree.platform.AndroidPlatformHost(context)
    }
    val fileHost: git.shin.adfree.platform.AndroidFileHost by lazy {
        git.shin.adfree.platform.AndroidFileHost(context)
    }
    val appInventory: git.shin.adfree.platform.AndroidAppInventory by lazy {
        git.shin.adfree.platform.AndroidAppInventory(context)
    }
    private val reminders: git.shin.adfree.platform.AndroidReminders by lazy {
        git.shin.adfree.platform.AndroidReminders(context)
    }
    private val automationStore: git.shin.adfree.platform.AndroidKeyValueStore by lazy {
        git.shin.adfree.platform.AndroidKeyValueStore(
            context.getSharedPreferences("adfree_automation", Context.MODE_PRIVATE),
        )
    }

    val repository: AdGuardRepository by lazy {
        // The repository writes state; reconfiguring the engine is the
        // container's job because it owns the Private DNS system setting.
        AdGuardRepository(
            platform = platformHost,
            files = fileHost,
            inventory = appInventory,
            reminders = reminders,
            store = automationStore,
            engine = coreEngine,
        ) { applyConfig() }
    }

    /** Offline threat analysis via heuristics plus the filter engine; no API key. */
    val threatAnalyzer: ThreatAnalyzer by lazy { ThreatAnalyzer(repository, coreEngine) }

    /**
     * The OTA question for the whole process: the Settings row, the once-a-day
     * automatic check that rides the filter refresh, and the download. Lazy so
     * nothing is built until the first trigger, and it reads its language and
     * enable switch through [repository] at check time.
     */
    val appUpdate: AppUpdateController by lazy {
        AppUpdateController(context)
    }

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

    /**
     * The last fallback the core had to take, so the UI can explain why the
     * tunnel is not using the resolver/proxy the user picked.
     */
    private val _configWarning = MutableStateFlow(ConfigWarning.NONE)
    val configWarning: StateFlow<ConfigWarning> = _configWarning.asStateFlow()

    init {
        // A Wi-Fi/mobile switch changes the system DNS the fallback retries
        // through, so the plan has to be rebuilt on that network's behalf.
        runCatching {
            context.getSystemService(ConnectivityManager::class.java)
                ?.registerDefaultNetworkCallback(object : ConnectivityManager.NetworkCallback() {
                    override fun onLinkPropertiesChanged(
                        network: Network,
                        linkProperties: LinkProperties,
                    ) {
                        applyConfig()
                    }
                })
        }
    }

    /**
     * The one state holder for the whole process. A plain instance rather
     * than a ViewModel factory: the state must outlive Activities and the
     * same object backs the desktop host's window.
     */
    val viewModel: AdGuardViewModel by lazy {
        AdGuardViewModel(
            repository = repository,
            tunnel = git.shin.adfree.platform.AndroidTunnelControl(vpnController),
            threatAnalyzer = threatAnalyzer,
            coreEngine = coreEngine,
            platform = platformHost,
            log = git.shin.adfree.platform.LogSink { Log.i("AdFree", it) },
            onConfigChanged = { applyConfig() },
            isPrivateDnsStrict = { privateDnsStrict },
            configWarning = configWarning,
            appUpdate = appUpdate,
        )
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
        // The core's default fallback retries through the network's own
        // resolvers, and only Android can read those. Refreshing them on
        // every apply also follows Wi-Fi/mobile switches.
        coreEngine.setSystemDns(systemDnsServers())
        val outcome = coreEngine.applyConfig(privateDnsStrict)
        _configWarning.value = outcome.warning
        if (outcome.warning != ConfigWarning.NONE) {
            Log.w(TAG, "config fell back: ${outcome.warning}")
        }
        return outcome
    }

    private fun systemDnsServers(): List<String> {
        val manager = context.getSystemService(ConnectivityManager::class.java) ?: return emptyList()
        // While the tunnel runs it is the default network, and its DNS server
        // is this very forwarder. Using that as the fallback would loop the
        // query back into the core, so only non-VPN networks qualify.
        val props = manager.allNetworks
            .asSequence()
            .filter { network ->
                val caps = manager.getNetworkCapabilities(network) ?: return@filter false
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            }
            .mapNotNull { manager.getLinkProperties(it) }
            .firstOrNull { it.dnsServers.isNotEmpty() }
            ?: return emptyList()
        // The fallback sends from an IPv4 UDP socket, so IPv6 entries would
        // only fail silently.
        return props.dnsServers.filterIsInstance<Inet4Address>().mapNotNull { it.hostAddress }
    }

    private companion object {
        private const val TAG = "AdGuardDi"
    }
}
