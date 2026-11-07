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
            // The core reads the distro's own trust store (see
            // `rust/src/trust.rs`): trusted means the PEM is in whichever
            // anchor directory this machine has and its rehash has run.
            // Called straight on the bindings because this runs while the
            // engine itself is being built.
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
        // than a snapshot taken at startup. The ports are the ones the core
        // actually holds while a filter is up, and the configured ones when it
        // is not — plus the reason a bind was refused, which is the one thing
        // a "stopped" alone never tells the user.
        proxyStatus = {
            val status = coreEngine.proxyStatus()
            val configured = repository.settings.value.localProxy
            val tcp = if (status.running) status.tcpPort.toInt() else configured.tcpPort
            val dns = if (status.running) status.dnsPort.toInt() else configured.dnsPort
            val marked = privileges.canSetFirewallMark()
            // A port nothing listens on says why next to the number it tried:
            // "stopped" alone would leave the user guessing which of the two
            // listeners the kernel turned down.
            fun endpoint(port: Int, reason: String): String {
                val address = "127.0.0.1:$port"
                return if (reason.isBlank()) address else "$address — $reason"
            }
            listOf(
                "HTTP(S)" to endpoint(tcp, status.tcpError),
                "DNS" to endpoint(dns, status.dnsError),
                // The switch from Settings says whether this machine's own
                // conversations reach the filter at all, so the card shows
                // which way it is set rather than leaving it to memory.
                "Loopback" to if (configured.filterLocalhost) "filtered like anything else" else "left alone",
                // Which of the two layouts is in play decides whether anything
                // reaches the filter at all, so the card says it plainly.
                "Traffic" to if (marked) "the machine's own, redirected" else "only what is pointed here",
                "Rules" to when {
                    !marked -> "not installed (no CAP_NET_ADMIN)"
                    privileges.rulesInstalled() -> "installed"
                    else -> "not installed"
                },
                "State" to if (status.running) "listening" else "stopped",
            )
        },
        privileges = privileges,
        onEngineTakeover = { onEngineTakeover() },
        coreLibrary = coreLibrary,
        exportCaPem = { coreEngine.exportCaCertificate() },
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
            tunnel = DesktopTunnelControl(
                coreEngine,
                protectionWanted,
                privileges,
                // Read at every start rather than captured: the ports are the
                // ones the user last applied, so the listeners and the
                // redirect rules always name the same numbers.
                localProxy = { repository.settings.value.localProxy },
            ),
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
        // The certificate has to exist before anything asks whether it is
        // trusted: the core reads its own PEM to answer that, and a process
        // that has not minted one yet answers "no" about a certificate it has
        // never looked at. Android does this in its Application; the desktop
        // has the same hour, and hydration acts on the answer.
        coreEngine.ensureCa()
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

    /**
     * Filtering the machine's own traffic on a desktop is worth nothing while
     * TLS stays sealed, so HTTPS is the default here wherever the certificate
     * can be made trusted: the CA goes into the system store through polkit,
     * the same authority the redirect rules are asked of, and filtering comes
     * on after it. Once per install, because a switch the user later turns off
     * must stay off; Settings keeps offering the same ask by hand.
     *
     * The shell calls this rather than [start], and on its IO thread: the
     * elevation dialog blocks until it is answered, and a headless test has no
     * business raising one.
     */
    fun applyHttpsDefault(scope: CoroutineScope) {
        if (!engineAvailable) return
        if (store.getBoolean(KEY_HTTPS_DEFAULT_APPLIED, false)) return
        store.putBoolean(KEY_HTTPS_DEFAULT_APPLIED, true)
        scope.launch(Dispatchers.IO) {
            if (!coreEngine.isCaTrusted()) {
                val reason = platformHost.installSystemCa()
                // The store is the authority, not the dialog: an ask that
                // reported a refusal after the certificate had landed is a
                // success, and one that came back clean while nothing is
                // trusted must not switch HTTPS on. An untrusted certificate
                // would make the engine a plain relay wearing a filtering
                // switch.
                if (!coreEngine.isCaTrusted()) {
                    if (reason != null) platformHost.toast(reason)
                    return@launch
                }
            }
            if (!repository.settings.value.isHttpsFilteringEnabled) {
                repository.toggleHttpsFiltering(true)
            }
        }
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

    private companion object {
        /** Set the first time the HTTPS default is applied, so it is never re-asked. */
        const val KEY_HTTPS_DEFAULT_APPLIED = "https_default_applied"
    }
}
