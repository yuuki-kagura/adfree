package git.shin.adfree.desktop

import git.shin.adfree.platform.AppInventory
import git.shin.adfree.platform.CaExporter
import git.shin.adfree.platform.DnsPrivacyMode
import git.shin.adfree.platform.FileHost
import git.shin.adfree.platform.InstalledApp
import git.shin.adfree.platform.KeyValueStore
import git.shin.adfree.platform.PlatformHost
import git.shin.adfree.platform.TunnelControl
import git.shin.adfree.platform.AppUpdate
import git.shin.adfree.model.LocalProxySettings
import git.shin.adfree.update.UpdateOutcome
import git.shin.adfree.update.UpdateUiState
import java.awt.Desktop
import java.awt.Frame
import java.awt.FileDialog
import java.io.File
import java.io.FileWriter
import java.io.Writer
import java.net.URI
import java.util.Locale
import java.util.Properties
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import git.shin.adfree.core.CoreEngine

/**
 * The desktop answers the UI can honour: toasts become in-app snackbars,
 * URLs open in the browser, and the OS-settings prompts report honestly that
 * Linux has nothing of the sort. Nothing throws; nothing pretends.
 */
class DesktopPlatformHost(
    /** Where [DesktopCaExporter] writes the PEM, so the toast can name it. */
    private val caFile: File? = null,
    /** The listener rows, read live: the container supplies it from the core. */
    private val proxyStatus: () -> List<Pair<String, String>> = { emptyList() },
    /** The system's privilege answers; null where the host has none to ask. */
    private val privileges: DesktopPrivileges? = null,
    /** Runs when the privileged engine has taken over: this window must go. */
    private val onEngineTakeover: () -> Unit = {},
    /** The core image the elevated helper has to load, named by absolute path. */
    private val coreLibrary: File? = null,
    /** Writes the certificate where the helper can read it; null when there is none. */
    private val exportCaPem: () -> String? = { null },
) : PlatformHost {

    /** Toasts the window pipes into the scaffold's snackbar host. */
    val toasts = MutableSharedFlow<String>(extraBufferCapacity = 8)

    override fun toast(text: String) {
        System.err.println("[toast] $text")
        toasts.tryEmit(text)
    }

    override fun openUrl(url: String) {
        runCatching {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(URI(url))
            } else {
                ProcessBuilder("xdg-open", url).start()
            }
        }.onFailure { toast("cannot open $url: ${it.message}") }
    }

    // No OS notification centre integration: the HTTPS reminder stays silent.
    override fun notificationsEnabled(): Boolean = false
    override fun openNotificationSettings() = Unit
    override fun requestNotificationPermission() = Unit
    override fun ignoringBatteryOptimizations(): Boolean = false
    override fun openBatterySettings() = Unit
    override fun requestIgnoreBatteryOptimizations() = Unit
    override fun miuiNoRestrictApps(): String? = null
    override fun privateDnsMode(): DnsPrivacyMode = DnsPrivacyMode.UNKNOWN
    override fun openPrivateDnsSettings() = Unit

    // Only reached where there is no polkit to ask (see [installSystemCa]). The
    // anchor directory is a distro answer — Debian, Arch and Fedora keep the
    // certificate in three different places and rehash it with three different
    // commands — so this names the file instead of a command that may not
    // exist here.
    override fun openCertificateInstaller() {
        val pem = caFile?.absolutePath ?: return
        toast("put $pem in this system's CA anchor directory and refresh its trust store")
    }

    override fun openAppDetails(packageName: String) = Unit
    override fun deviceLanguage(): String = Locale.getDefault().language.lowercase(Locale.ROOT)
    override fun packageName(): String = "git.shin.adfree"

    // Protection here is the local transparent proxy, not a system tunnel, so
    // the tunnel-shaped controls stay hidden and the proxy card takes their
    // place; notifications and the battery whitelist have no Linux answer.
    override fun supportsSystemTunnel(): Boolean = false
    override fun supportsNotifications(): Boolean = false
    override fun supportsBatteryOptimization(): Boolean = false
    override fun supportsCertificateInstaller(): Boolean = false
    override fun supportsAppCatalogue(): Boolean = false

    // The window draws its own header: an OS title bar carries no notion of
    // where in the app you are, and there is no system back gesture here.
    override fun supportsWindowHeader(): Boolean = true

    override fun localProxyStatus(): List<Pair<String, String>> = proxyStatus()

    // The listeners are this platform's own, so their ports are the user's to
    // move; Settings shows them where the Android host shows nothing at all.
    override fun supportsLocalProxyPorts(): Boolean = true

    // The redirect that captures the machine's own traffic is a kernel
    // request, so the app asks the system for it through polkit — the desktop
    // answer to the VPN consent a phone shows. Once the mark works the offer
    // is gone: asking again would start a second instance that cannot bind the
    // ports this one is holding.
    override fun supportsPrivilegedEngine(): Boolean = privileges != null && !privileges.canSetFirewallMark()

    override fun requestPrivilegedEngine(): String? {
        val helper = privileges ?: return null
        val env = buildMap {
            listOf(
                "DISPLAY",
                "WAYLAND_DISPLAY",
                "XAUTHORITY",
                "XDG_RUNTIME_DIR",
                "XDG_DATA_HOME",
                "HOME",
                "ADFREE_CORE_LIB",
            ).forEach { key ->
                System.getenv(key)?.let { value -> put(key, value) }
            }
        }
        val outcome = helper.requestPrivilegedEngine(env)
        return when (outcome) {
            is PrivilegeOutcome.Ok -> {
                onEngineTakeover()
                null
            }
            is PrivilegeOutcome.Denied -> outcome.reason
            is PrivilegeOutcome.Failed -> outcome.reason
        }
    }

    // Trusting the certificate is the other half of the same conversation: on
    // Android the app asks `su`, here it asks polkit. Without it the HTTPS
    // switch stays off forever, because this platform has no OS screen where a
    // user could import the PEM themselves.
    override fun supportsSystemCaInstall(): Boolean = privileges != null && coreLibrary != null

    override fun installSystemCa(): String? {
        val helper = privileges ?: return null
        val library = coreLibrary ?: return "the filtering core was not found, so nothing can install the certificate"
        val exported = exportCaPem() ?: caFile?.takeIf(File::isFile)?.absolutePath
            ?: return "no certificate to install yet"
        return when (val outcome = helper.requestRootCaInstall(exported, library.absolutePath)) {
            is PrivilegeOutcome.Ok -> null
            is PrivilegeOutcome.Denied -> outcome.reason
            is PrivilegeOutcome.Failed -> outcome.reason
        }
    }
}

/** Real files instead of SAF: the uriText is simply the absolute path. */
class DesktopFileHost : FileHost {

    override suspend fun openText(): String? = dialog(FileDialog.LOAD, null)

    override suspend fun createDocument(suggestedName: String, mime: String): String? =
        dialog(FileDialog.SAVE, suggestedName)

    private fun dialog(mode: Int, name: String?): String? {
        if (!Desktop.isDesktopSupported() || GraphicsEnvironmentHeadless()) return null
        val file = FileDialog(null as Frame?, if (mode == FileDialog.LOAD) "Open" else "Save", mode)
        if (name != null) file.file = name
        file.isVisible = true
        val chosen = file.file ?: return null
        return File(file.directory, chosen).absolutePath
    }

    private fun GraphicsEnvironmentHeadless(): Boolean =
        java.awt.GraphicsEnvironment.isHeadless()

    override fun readText(uriText: String): String? =
        runCatching { File(uriText).readText() }.getOrNull()

    override fun writeText(uriText: String, text: String): Boolean =
        runCatching { File(uriText).writeText(text) }.isSuccess

    override fun openWrite(uriText: String): Writer? =
        runCatching { FileWriter(uriText) }.getOrNull()

    override fun displayName(uriText: String): String = File(uriText).name

    override fun persistRead(uriText: String) = Unit
}

/** No app catalogue on a desktop: the Apps tab lists what the engine knows. */
class DesktopAppInventory : AppInventory {
    override fun installedApps(): List<InstalledApp> = emptyList()
    override fun icon(packageName: String): androidx.compose.ui.graphics.ImageBitmap? = null
}

/** Properties file under the data root; the automation token survives restarts. */
class DesktopKeyValueStore(private val file: File) : KeyValueStore {

    private val props = Properties()

    init {
        runCatching { file.inputStream().use { props.load(it) } }
    }

    override fun getString(key: String): String? = props.getProperty(key)

    override fun putString(key: String, value: String?) {
        if (value == null) props.remove(key) else props.setProperty(key, value)
        flush()
    }

    override fun getBoolean(key: String, default: Boolean): Boolean =
        props.getProperty(key)?.toBooleanStrictOrNull() ?: default

    override fun putBoolean(key: String, value: Boolean) {
        props.setProperty(key, value.toString())
        flush()
    }

    private fun flush() {
        runCatching { file.parentFile?.mkdirs() }
        runCatching { file.outputStream().use { props.store(it, "AdFree desktop") } }
    }
}

/**
 * Desktop protection is the AdGuard-for-Windows shape: no tunnel, a local
 * transparent proxy and DNS server that the machine's own traffic is brought
 * onto by kernel redirect rules (or an explicit proxy setting). The switch
 * follows the listeners themselves — a taken port shows as protection off,
 * never as a filter that is not running.
 */
class DesktopTunnelControl(
    private val coreEngine: CoreEngine,
    protectionWanted: StateFlow<Boolean>,
    private val privileges: DesktopPrivileges? = null,
    /** Where the listeners are configured to bind; read at every start. */
    private val localProxy: () -> LocalProxySettings = { LocalProxySettings() },
) : TunnelControl {

    override val isVpnActive: StateFlow<Boolean> = protectionWanted

    override fun isTunnelUp(): Boolean = coreEngine.isProxyRunning()

    override fun needsConsent(): Boolean = false

    override fun startVpnService() {
        val ports = localProxy()
        val status = coreEngine.startProxy(ports.tcpPort, ports.dnsPort, ports.filterLocalhost)
        if (!status.running) {
            // Say which listener refused and what the kernel said about it:
            // the Home card shows the same words, and a bare "did not come up"
            // would leave the user with a port to guess at.
            val reasons = listOf(
                "HTTP(S) :${ports.tcpPort}" to status.tcpError,
                "DNS :${ports.dnsPort}" to status.dnsError,
            ).filter { it.second.isNotBlank() }
                .joinToString("; ") { (label, reason) -> "$label: $reason" }
            System.err.println(
                "[desktop] proxy listeners did not come up" +
                    (if (reasons.isBlank()) "" else " — $reasons"),
            )
            return
        }
        // With the mark in hand the redirect is safe to put in: the proxy can
        // tell its own traffic apart. Without it the rules would catch the
        // traffic the proxy dials and feed it back to itself, so protection
        // stays at what is pointed at it instead of taking the machine down.
        // The rules name the ports the listeners actually took, not the ones
        // the settings asked for, and carry the same loopback switch the core
        // just took — the two halves must not disagree about whether this
        // machine's own conversations are filtered.
        val helper = privileges ?: return
        if (!helper.canSetFirewallMark()) return
        when (val outcome = helper.installRules(
            status.tcpPort.toInt(),
            status.dnsPort.toInt(),
            ports.filterLocalhost,
        )) {
            is PrivilegeOutcome.Ok -> System.err.println("[desktop] redirect rules installed")
            is PrivilegeOutcome.Denied -> System.err.println("[desktop] redirect rules: ${outcome.reason}")
            is PrivilegeOutcome.Failed -> System.err.println("[desktop] redirect rules: ${outcome.reason}")
        }
    }

    override fun stopVpnService() {
        privileges?.removeRules()
        coreEngine.stopProxy()
    }

    override fun restartVpnService() {
        if (!isVpnActive.value) return
        // The listeners hold the ports they were raised on and the redirect
        // rules name those same numbers, so a restart has to take both down
        // and put them back — a port the settings just moved would otherwise
        // leave the proxy listening on the old one and the rules pointing at
        // a port nobody holds.
        if (coreEngine.isProxyRunning()) stopVpnService()
        startVpnService()
    }

    override fun onPermissionResult(granted: Boolean) = Unit

    override fun refreshStatusNotification() = Unit
}

/** The desktop ships through package managers: report the version, install nothing. */
class DesktopAppUpdate(private val currentVersion: String) : AppUpdate {

    private val _state = MutableStateFlow<UpdateUiState>(UpdateUiState.Idle)
    override val state: StateFlow<UpdateUiState> = _state

    private val _outcomes = MutableSharedFlow<UpdateOutcome>(extraBufferCapacity = 4)
    override val outcomes: SharedFlow<UpdateOutcome> = _outcomes

    override fun manualCheck() {
        System.err.println("[desktop] app update: $currentVersion (managed by the package manager)")
    }

    override fun downloadAndInstall(info: git.shin.adfree.update.UpdateInfo) = Unit
}

/** Puts the CA where the user can import it into the system trust store. */
class DesktopCaExporter(private val dataRoot: File) : CaExporter {
    override fun export(pem: String): String? {
        val out = File(dataRoot, "adfree-ca.pem")
        return runCatching {
            out.parentFile.mkdirs()
            out.writeText(pem)
            out.absolutePath
        }.getOrNull()
    }
}
