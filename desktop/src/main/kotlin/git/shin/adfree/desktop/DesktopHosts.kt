package git.shin.adfree.desktop

import git.shin.adfree.platform.AppInventory
import git.shin.adfree.core.coreExportNodeCa
import git.shin.adfree.core.coreRemoveNodeCa
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
    /** The system's privilege answers; null where the host has none to ask. */
    private val privileges: DesktopPrivileges? = null,
    /** Runs when the privileged engine has taken over: this window must go. */
    private val onEngineTakeover: () -> Unit = {},
    /** The core image the elevated helper has to load, named by absolute path. */
    private val coreLibrary: File? = null,
    /** Writes the certificate where the helper can read it; null when there is none. */
    private val exportCaPem: () -> String? = { null },
    /** The user-owned stores (NSS) the system bundle does not reach. */
    private val trustStores: DesktopTrustStores = DesktopTrustStores(),
    /**
     * The port the protection unit's proxy listens on. Asked before a restart
     * so a unit that is already filtering is left running: the machine's open
     * connections through it belong to other programs.
     */
    private val privilegedPort: () -> Int = { DesktopPrivileges.DEFAULT_PROXY_PORT },
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

    // The listeners are this platform's own, so their ports are the user's to
    // move; Settings shows them where the Android host shows nothing at all.
    override fun supportsLocalProxyPorts(): Boolean = true

    /**
     * The redirect that captures the machine's own traffic is a kernel request,
     * so the app asks the system for it through polkit — the desktop answer to
     * the VPN consent a phone shows. Filtering is switched on with the shield,
     * so the shield asks: the first ask writes a unit and a rule, every later
     * one starts that unit without a dialog.
     */
    override fun requestPrivilegedEngine(): String? {
        val helper = privileges ?: return null
        val env = buildMap {
            listOf(
                "DISPLAY",
                "WAYLAND_DISPLAY",
                "XAUTHORITY",
                "XDG_RUNTIME_DIR",
                // The unit is a system service that still signs into this
                // user's session bus: without the address it would look for a
                // bus at the default path and find nothing to put the icon on.
                "DBUS_SESSION_BUS_ADDRESS",
                "XDG_DATA_HOME",
                "HOME",
                "ADFREE_CORE_LIB",
            ).forEach { key ->
                System.getenv(key)?.let { value -> put(key, value) }
            }
            // The elevated instance is a fresh JVM with a sanitized
            // environment, so it has to be told where the core is even when
            // this process was not: `findCoreLibrary` resolves it relative to
            // the working directory, and a shell that never exported
            // `ADFREE_CORE_LIB` leaves the child to guess. This process already
            // found the library — hand the absolute path over instead of
            // hoping the child repeats the search.
            coreLibrary?.let { put("ADFREE_CORE_LIB", it.absolutePath) }
        }
        val outcome = helper.requestPrivilegedEngine(env, privilegedPort())
        return when (outcome) {
            is PrivilegeOutcome.Ok -> {
                System.err.println("[desktop] the privileged instance is up; this window is leaving")
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
            is PrivilegeOutcome.Ok -> {
                // The system bundle is one store of several: NSS applications
                // (Chromium, Electron, Firefox) read their own database, and on
                // a distro that ships Mozilla's roots as `libnssckbi.so` the
                // anchor directory never reaches them. The certificate landing
                // in the bundle is therefore not the same as the browser
                // trusting it, and fixing that per application — an environment
                // variable here, a flag there — is not something a packaged app
                // can be given. Write the store itself.
                trustStores.installAndLog(File(exported))
                null
            }
            is PrivilegeOutcome.Denied -> outcome.reason
            is PrivilegeOutcome.Failed -> outcome.reason
        }
    }

    /**
     * Makes the user-owned trust stores agree with the system bundle, on every
     * start.
     *
     * Idempotent and cheap, so it is not gated on the once-per-install flag the
     * HTTPS default uses: a browser installed *after* the certificate was is
     * exactly the case that flag misses — NSS would create its database at the
     * browser's first launch, and that database would never hear about the CA.
     */
    fun refreshUserTrustStores() {
        val pem = caFile?.takeIf(File::isFile) ?: exportCaPem()?.let(::File)?.takeIf(File::isFile) ?: return
        trustStores.installAndLog(pem)
        // Node ignores NSS and the system bundle alike, so the one store it
        // does read — `NODE_EXTRA_CA_CERTS` — is set where a desktop app can
        // set it: the user's own shell configuration. The core writes it, the
        // same as every other store, so the app process stays a UI.
        for (edit in coreExportNodeCa(pem.absolutePath)) {
            if (edit.ok) System.err.println("[shell] Node CA exported to shell config: ${edit.path}")
            else System.err.println("[shell] shell config skipped (${edit.path}): ${edit.detail}")
        }
    }

    override fun supportsSystemCaRemoval(): Boolean = privileges != null && coreLibrary != null

    /**
     * Takes the certificate out of every store this install put it in: the NSS
     * databases first (they are the user's own files and need no dialogue),
     * then the distro anchor directory through the same `pkexec` helper that
     * wrote it.
     *
     * A host that reports a refusal from the system store still removes the NSS
     * entries: leaving a trusted CA in a browser after the user asked to remove
     * it is worse than reporting half a removal.
     */
    override fun removeSystemCa(): String? {
        val helper = privileges ?: return null
        val library = coreLibrary
            ?: return "the filtering core was not found, so nothing can remove the certificate"
        for (store in trustStores.remove()) {
            if (!store.ok) System.err.println("[trust] NSS database not updated (${store.path}): ${store.detail}")
        }
        for (edit in coreRemoveNodeCa()) {
            if (!edit.ok) System.err.println("[shell] shell config not updated (${edit.path}): ${edit.detail}")
        }
        return when (val outcome = helper.requestRootCaRemove(library.absolutePath)) {
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
    /**
     * Asks the system for the capability the redirect needs, and hands the
     * window over to the instance that has it. Null means that instance is on
     * its way; anything else is the system's own words about why it is not.
     */
    private val requestPrivileges: () -> String? = { null },
    /** Told when the ask was refused or broke, so the window can say so. */
    private val report: (String) -> Unit = {},
) : TunnelControl {

    override val isVpnActive: StateFlow<Boolean> = protectionWanted

    /** Set once the person has said no, so one refusal is one dialog. */
    private val privilegeAskRefused = java.util.concurrent.atomic.AtomicBoolean(false)

    override fun isTunnelUp(): Boolean = coreEngine.isProxyRunning()

    override fun needsConsent(): Boolean = false

    override fun startVpnService() {
        // A start means filtering: the transient pause the tray set must not
        // outlive the protection it was pausing.
        coreEngine.setProtectionPaused(false)
        // Full protection is what the shield asks for, so the shield is where
        // the privilege is requested: an instance without the mark takes the
        // machine's traffic only if it can mark its own sockets, and one that
        // hands over must do it *before* binding the ports the privileged
        // instance is about to take.
        //
        // The ask is a dialog — it waits for a person to read it and type a
        // password — so it cannot run on the thread that paints the window. A
        // machine that has been set up once answers it without a dialog, and a
        // refusal leaves this process filtering only what is pointed at it,
        // which is still a filter.
        if (privileges != null && !privileges.canSetFirewallMark() && !privilegeAskRefused.get()) {
            System.err.println("[desktop] protection needs CAP_NET_ADMIN; asking the system")
            Thread({
                val reason = requestPrivileges()
                if (reason == null) return@Thread
                // Refused once is refused for this run: protection that comes
                // back on after a port change must not raise the same dialog
                // again, and a machine that said no is a machine filtering only
                // what is pointed at it until the next launch.
                privilegeAskRefused.set(true)
                System.err.println("[desktop] privilege ask refused: $reason")
                report(reason)
                startListeners()
            }, "adfree-privilege-ask").apply { isDaemon = true }.start()
            return
        }
        startListeners()
    }

    /** Raises the listeners and the redirect that feeds them. */
    private fun startListeners() {
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
        coreEngine.setProtectionPaused(false)
        System.err.println("[desktop] protection stopping: removing rules and listeners")
        privileges?.removeRules()
        coreEngine.stopProxy()
    }

    override fun restartVpnService() {
        if (!isVpnActive.value) return
        System.err.println("[desktop] protection restarting on new ports")
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
