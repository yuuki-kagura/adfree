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

    // Linux has no in-app certificate screen: name the exact trust-store
    // commands instead of opening nothing (the PEM is already exported).
    override fun openCertificateInstaller() {
        val pem = caFile?.absolutePath ?: return
        toast("sudo cp $pem /usr/local/share/ca-certificates/adfree-ca.crt && sudo update-ca-certificates")
    }

    override fun openAppDetails(packageName: String) = Unit
    override fun deviceLanguage(): String = Locale.getDefault().language.lowercase(Locale.ROOT)
    override fun packageName(): String = "git.shin.adfree"

    // Phase 3 will flip the tunnel and CA flags with real Linux protection;
    // until then the UI hides these controls rather than offering dead ones.
    override fun supportsSystemTunnel(): Boolean = false
    override fun supportsNotifications(): Boolean = false
    override fun supportsBatteryOptimization(): Boolean = false
    override fun supportsCertificateInstaller(): Boolean = false
    override fun supportsAppCatalogue(): Boolean = false
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
 * Desktop protection is engine-side: there is no VpnService, so the switch
 * tracks the persisted intent rather than an OS tunnel nobody asked for.
 * The core still resolves and filters; capturing traffic would need a TUN fd,
 * which only a root launcher could hand it.
 */
class DesktopTunnelControl(
    private val coreEngine: CoreEngine,
    protectionWanted: StateFlow<Boolean>,
) : TunnelControl {

    override val isVpnActive: StateFlow<Boolean> = protectionWanted

    override fun isTunnelUp(): Boolean = isVpnActive.value

    override fun needsConsent(): Boolean = false

    override fun startVpnService() {
        System.err.println("[desktop] engine ready: ${coreEngine.isReady()}")
    }

    override fun stopVpnService() = Unit

    override fun restartVpnService() {
        System.err.println("[desktop] engine re-applied after config change")
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
