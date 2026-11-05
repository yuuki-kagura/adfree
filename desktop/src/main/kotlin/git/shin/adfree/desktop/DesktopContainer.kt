package git.shin.adfree.desktop

import git.shin.adfree.core.ConfigOutcome
import git.shin.adfree.core.ConfigWarning
import git.shin.adfree.core.CoreEngine
import git.shin.adfree.core.coreSetDataRoot
import git.shin.adfree.data.AdGuardRepository
import git.shin.adfree.l10n.L10n
import git.shin.adfree.platform.LogSink
import git.shin.adfree.platform.NoopReminders
import git.shin.adfree.security.ThreatAnalyzer
import git.shin.adfree.ui.AdGuardViewModel
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

/**
 * The desktop's hand-rolled container, mirroring the Android one object for
 * object: same repository, engine and ViewModel — only the seams differ.
 */
class DesktopContainer(
    /** Tests point this at a scratch dir; the app uses XDG data home. */
    val dataRoot: File = File(
        System.getenv("XDG_DATA_HOME")
            ?: File(System.getProperty("user.home"), ".local/share").absolutePath,
        "adfree",
    ),
) {

    val coreLibrary: File? = findCoreLibrary()

    /** False when no libadfree_core.so was found: the window says so instead of crashing. */
    val engineAvailable: Boolean = coreLibrary != null

    init {
        coreLibrary?.let {
            System.setProperty("uniffi.component.adfree.libraryOverride", it.absolutePath)
        }
    }

    val coreEngine: CoreEngine by lazy {
        CoreEngine(
            log = LogSink { System.err.println("[core] $it") },
            caExporter = DesktopCaExporter(dataRoot),
            // The core reads the distro bundle itself (see `rust/src/trust.rs`):
            // trusted means the PEM is in /usr/local/share/ca-certificates and
            // `update-ca-certificates` has run. Called straight on the bindings
            // because this runs while the engine itself is being built.
            caTrustChecker = git.shin.adfree.platform.CaTrustChecker {
                runCatching { git.shin.adfree.core.coreRootTrustStatus().installed }
                    .getOrDefault(false)
            },
        ).also {
            dataRoot.mkdirs()
            runCatching { coreSetDataRoot(dataRoot.absolutePath) }
        }
    }

    /** The system's privilege answers: the mark, the rules, the service. */
    val privileges = DesktopPrivileges()

    /** Set by the shell so the app can hand its window over to a privileged instance. */
    var onEngineTakeover: () -> Unit = {}

    val platformHost = DesktopPlatformHost(
        File(dataRoot, "adfree-ca.pem"),
        // Read when the screen asks, so the card follows the listeners rather
        // than a snapshot taken at startup.
        proxyStatus = {
            val up = coreEngine.isProxyRunning()
            val marked = privileges.canSetFirewallMark()
            listOf(
                "HTTP(S)" to "127.0.0.1:${CoreEngine.PROXY_TCP_PORT}",
                "DNS" to "127.0.0.1:${CoreEngine.PROXY_DNS_PORT}",
                // Which of the two layouts is in play decides whether anything
                // reaches the filter at all, so the card says it plainly.
                "Traffic" to if (marked) "the machine's own, redirected" else "only what is pointed here",
                "Rules" to when {
                    !marked -> "not installed (no CAP_NET_ADMIN)"
                    privileges.rulesInstalled() -> "installed"
                    else -> "not installed"
                },
                "State" to if (up) "listening" else "stopped",
            )
        },
        privileges = privileges,
        onEngineTakeover = { onEngineTakeover() },
    )
    val fileHost = DesktopFileHost()
    val inventory = DesktopAppInventory()
    private val reminders = NoopReminders()
    val store: git.shin.adfree.platform.KeyValueStore by lazy {
        DesktopKeyValueStore(File(dataRoot, "automation.properties"))
    }

    val repository: AdGuardRepository by lazy {
        AdGuardRepository(
            platform = platformHost,
            files = fileHost,
            inventory = inventory,
            reminders = reminders,
            store = store,
            engine = coreEngine,
        ) { applyConfig() }
    }

    val threatAnalyzer: ThreatAnalyzer by lazy { ThreatAnalyzer(repository, coreEngine) }

    val appUpdate: DesktopAppUpdate by lazy { DesktopAppUpdate(coreEngine.version) }

    private val _configWarning = MutableStateFlow(ConfigWarning.NONE)
    val configWarning: StateFlow<ConfigWarning> = _configWarning.asStateFlow()

    /** Desktop protection has no OS tunnel to report, so the switch follows the persisted intent. */
    private val protectionWanted = MutableStateFlow(false)

    val viewModel: AdGuardViewModel by lazy {
        AdGuardViewModel(
            repository = repository,
            tunnel = DesktopTunnelControl(coreEngine, protectionWanted, privileges),
            threatAnalyzer = threatAnalyzer,
            coreEngine = coreEngine,
            platform = platformHost,
            log = LogSink { System.err.println("[ui] $it") },
            onConfigChanged = { applyConfig() },
            isPrivateDnsStrict = { false },
            configWarning = configWarning,
            appUpdate = appUpdate,
        )
    }

    /** Loads persisted state once and keeps the language table in sync. */
    fun start(scope: CoroutineScope) {
        if (!engineAvailable) return
        repository.hydrateState()
        scope.launch {
            repository.settings.map { it.isProtectionActive }.collect { protectionWanted.value = it }
        }
        scope.launch {
            repository.settings.map { it.appLanguage }.collect { L10n.language = it }
        }
        L10n.systemLanguage = platformHost.deviceLanguage()
        applyConfig()
    }

    fun applyConfig(): ConfigOutcome {
        coreEngine.setSystemDns(systemDnsServers())
        val outcome = coreEngine.applyConfig(privateDnsStrict = false)
        _configWarning.value = outcome.warning
        return outcome
    }

    /** The core's fallback resolver retries through the system's own servers. */
    private fun systemDnsServers(): List<String> = runCatching {
        File("/etc/resolv.conf").readLines().mapNotNull { line ->
            val parts = line.trim().split(Regex("\\s+"))
            parts.getOrNull(1)?.takeIf { parts.firstOrNull() == "nameserver" && it.contains('.') }
        }
    }.getOrDefault(emptyList())
}
