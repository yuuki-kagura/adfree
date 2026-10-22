package git.shin.adfree.core

import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.provider.Settings
import android.util.Log
import git.shin.adfree.AdGuardApplication
import git.shin.adfree.model.DnsBlockMode
import git.shin.adfree.model.NetworkRequestLog
import java.io.File
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Kotlin-side wrapper around the uniffi bindings (`adfree.kt`).
 *
 * All heavy lifting lives in native code: this class holds the TUN fd, the
 * already-`protect()`ed UDP sockets, and the few things that need an Android
 * context (logcat, the certificate's trip to Downloads).
 */
class CoreEngine {

    private val tag = "AdFreeCore"

    /** UDP sockets used to forward DNS, `VpnService.protect()`ed so they do not loop. */
    private val upstreamSockets = mutableListOf<java.net.DatagramSocket>()

    val version: String
        get() = runCatching { git.shin.adfree.core.coreVersion() }.getOrDefault("unknown")

    fun isReady(): Boolean = runCatching { git.shin.adfree.core.coreStats() }.isSuccess

    // ------------------------------------------------------------------ life

    fun start(tunFd: Int) {
        git.shin.adfree.core.coreStart(tunFd)
    }

    fun stop() {
        git.shin.adfree.core.coreStop()
        closeUpstreamSockets()
    }

    fun isRunning(): Boolean = runCatching { git.shin.adfree.core.coreIsRunning() }.getOrDefault(false)

    // -------------------------------------------------------------- DNS upstream

    /**
     * Create the UDP sockets the core forwards DNS with.
     *
     * The critical part: every socket must be `VpnService.protect()`ed, otherwise
     * packets towards the resolver re-enter our own TUN and DNS dies entirely.
     */
    @Synchronized
    fun prepareUpstreamSockets(vpnService: android.net.VpnService) {
        closeUpstreamSockets()
        repeat(SOCKET_COUNT) {
            runCatching { java.net.DatagramSocket().apply { reuseAddress = true } }
                .onSuccess { upstreamSockets += it }
        }
        val fds = upstreamSockets.mapNotNull { socket -> protectAndKeep(vpnService, socket) }
        Log.i(tag, "upstream DNS sockets protected: ${fds.size}/$SOCKET_COUNT")
        git.shin.adfree.core.coreProtectSockets(fds)
    }

    /**
     * `protect()`s a socket and hands its descriptor to the Rust core.
     *
     * The descriptor is handed over as-is and the `ParcelFileDescriptor` that
     * wraps it is kept alive for as long as the engine runs. That is deliberate:
     * on Android 12 and newer a dup()ed descriptor belongs to the descriptor
     * object that created it, so `dup()` + `close()` looks fine but the kernel
     * then answers `sendto()` with EBADF and nothing resolves. Keeping the
     * owner alive (and never closing it before `stop()`) is what actually works.
     */
    private fun protectAndKeep(
        vpnService: android.net.VpnService,
        socket: java.net.DatagramSocket,
    ): Int? = runCatching {
        vpnService.protect(socket)
        val pfd = android.os.ParcelFileDescriptor.fromDatagramSocket(socket)
        holderPipes += pfd
        pfd.fd
    }.getOrNull()

    private val holderPipes = mutableListOf<android.os.ParcelFileDescriptor>()

    @Synchronized
    private fun closeUpstreamSockets() {
        closeHeldSockets()
        upstreamSockets.clear()
    }

    /**
     * Releases every descriptor handed to the core. Called only from `stop()`,
     * once the engine has stopped using them.
     *
     * Every entry point that touches the two lists is `@Synchronized`: a
     * `stop()` racing the tunnel build otherwise iterates a list the other
     * side is still appending to, which is exactly the crash that used to
     * leave the tunnel half-built.
     */
    @Synchronized
    private fun closeHeldSockets() {
        holderPipes.forEach { runCatching { it.close() } }
        holderPipes.clear()
        upstreamSockets.forEach { runCatching { it.close() } }
    }

    // ----------------------------------------------------------------- config

    fun setResolver(host: String, port: Int) {
        runCatching { git.shin.adfree.core.coreSetResolver(host, port.toUShort()) }
            .onFailure { Log.w(tag, "setResolver($host:$port) failed", it) }
    }

    fun configure(
        mitmEnabled: Boolean,
        fullEch: Boolean,
        blockQuic: Boolean,
        blockDoh: Boolean,
        blockDot: Boolean,
        adBlocking: Boolean,
        trackingProtection: Boolean,
        dnsProtection: Boolean,
        blockMode: DnsBlockMode,
        logAllowed: Boolean,
        ecoMode: Boolean,
    ) {
        val config = git.shin.adfree.core.EngineConfig(
            mitmEnabled = mitmEnabled,
            fullEch = fullEch,
            blockQuic = blockQuic,
            blockDoh = blockDoh,
            blockDot = blockDot,
            adBlocking = adBlocking,
            trackingProtection = trackingProtection,
            dnsProtection = dnsProtection,
            blockMode = blockMode.code.toInt(),
            logAllowed = logAllowed,
            ecoMode = ecoMode,
        )
        runCatching { git.shin.adfree.core.coreConfigure(config) }
            .onFailure { Log.w(tag, "configure failed", it) }
    }

    fun setScreenOff(off: Boolean) = runCatching { git.shin.adfree.core.coreSetScreenOff(off) }

    // --------------------------------------------------------------- filters

    /**
     * Push the filter list (file paths) to the core and compile in the
     * background. The UI never blocks: the old engine serves until the new one
     * is ready.
     */
    fun setListsAsync(lists: List<FilterListBinding>, userRules: List<String>) {
        runCatching { git.shin.adfree.core.coreSetListsAsync(lists, userRules) }
            .onFailure { Log.w(tag, "setLists failed", it) }
    }

    /**
     * Lists whose body the most recent filter build could not read, keyed by
     * the `FilterListBinding.id` the app pushed. Empty when every enabled
     * list compiled.
     */
    fun filterBuildErrors(): Map<Int, String> =
        runCatching {
            git.shin.adfree.core.coreFilterBuildErrors().associate { it.listId to it.message }
        }.getOrDefault(emptyMap())

    /** Scan one host (Security Lab screen). */
    fun checkHost(host: String): HostVerdictBinding =
        runCatching { git.shin.adfree.core.coreCheckHost(host) }.getOrElse {
            HostVerdictBinding(blocked = false, rule = "", listName = "", category = 0)
        }

    fun clearDnsCache() = runCatching { git.shin.adfree.core.coreClearDnsCache() }

    fun setDohRanges(ranges: List<String>) {
        runCatching { git.shin.adfree.core.coreSetDohRanges(ranges) }
    }

    /**
     * Pushes the uid -> packages table the core matches `$app=` network rules
     * against.
     *
     * The core cannot read other apps' uid on Android 10+, so the platform has
     * to tell it: one row per uid, every package sharing it included. Cheap
     * enough to redo whenever an app is installed, removed or replaced.
     */
    fun pushUidApps(context: Context) {
        val pm = context.packageManager
        val installed = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0L))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledApplications(0)
        }
        val byUid = LinkedHashMap<Int, MutableList<String>>()
        for (info in installed) {
            byUid.getOrPut(info.uid) { mutableListOf() } += info.packageName
        }
        val rows = byUid.map { (uid, packages) ->
            git.shin.adfree.core.UidApps(uid = uid.toUInt(), packages = packages)
        }
        runCatching { git.shin.adfree.core.coreSetUidApps(rows) }
            .onFailure { Log.w(tag, "setUidApps failed", it) }
    }

    /**
     * Installs the callback the core uses to name the app that owns one TCP
     * connection, which is what `$app=` rules are matched against.
     *
     * `pushUidApps` above answers "which packages have this uid"; this answers
     * "whose uid is this connection". The kernel table the desktop core reads
     * (`/proc/net/tcp`) has been closed to apps since Android 10, but a
     * VpnService may ask the framework about the connections its own tunnel
     * carries — which is exactly the traffic being filtered.
     */
    fun setConnectionUidLookup(context: Context) {
        runCatching {
            git.shin.adfree.core.coreSetUidLookup(FrameworkUidLookup(context.applicationContext))
        }.onFailure { Log.w(tag, "setUidLookup failed", it) }
    }

    /**
     * Downloads one subscription into the store (`filters/<id>.txt`).
     *
     * The core owns the network call, the temp-file write, the rename and the
     * header parsing; this only turns the outcome into UI wording. Blocking,
     * so call it off the main thread.
     */
    fun downloadList(list: git.shin.adfree.model.FilterList): DownloadResult {
        val url = list.subscriptionUrl ?: return DownloadResult(false, "Danh sách này không có URL")
        val outcome = runCatching { git.shin.adfree.core.coreFilterFetch(list.id, url) }
            .getOrElse { return DownloadResult(false, "Lỗi: ${it.javaClass.simpleName}") }
        if (!outcome.ok) return DownloadResult(false, "Không tải được: ${outcome.message}")
        return DownloadResult(
            ok = true,
            message = "Đã tải ${list.name} (${outcome.lineCount} quy tắc)",
            lineCount = outcome.lineCount,
            version = outcome.version,
            updatedText = outcome.updatedText,
            detectedFormat = outcome.detectedFormat,
            sizeBytes = outcome.sizeBytes,
        )
    }

    /** Saves a list body the user imported from a file; same atomic write. */
    fun saveListText(id: String, text: String): git.shin.adfree.core.AssetState? =
        runCatching { git.shin.adfree.core.coreFilterSave(id, text) }.getOrNull()

    /**
     * State of a downloaded list, or null when it is not on disk.
     *
     * `withMeta = false` skips reading the body: pass it when only the path or
     * existence matters (pushing the engine's list, toggles).
     */
    fun filterState(id: String, withMeta: Boolean = true): git.shin.adfree.core.AssetState? =
        runCatching { git.shin.adfree.core.coreFilterState(id, withMeta) }.getOrNull()

    /** Deletes a list body. False when there was nothing to delete. */
    fun filterRemove(id: String): Boolean =
        runCatching { git.shin.adfree.core.coreFilterRemove(id) }.getOrDefault(false)

    /** Downloads one userscript body into the store (`scripts/<id>.js`). */
    fun scriptFetch(id: String, url: String): git.shin.adfree.core.DownloadOutcome =
        runCatching { git.shin.adfree.core.coreScriptFetch(id, url) }
            .getOrElse {
                git.shin.adfree.core.DownloadOutcome(
                    ok = false,
                    message = "Lỗi: ${it.javaClass.simpleName}",
                    lineCount = 0,
                    version = null,
                    updatedText = null,
                    detectedFormat = null,
                    sizeBytes = 0,
                    modifiedMs = 0,
                )
            }

    /** State of a userscript body, or null when it is not on disk. */
    fun scriptState(id: String): git.shin.adfree.core.AssetState? =
        runCatching { git.shin.adfree.core.coreScriptState(id) }.getOrNull()

    /** Saves a userscript body (imported from a file / pasted); same atomic write. */
    fun scriptSave(id: String, text: String): git.shin.adfree.core.AssetState? =
        runCatching { git.shin.adfree.core.coreScriptSave(id, text) }.getOrNull()

    /** Deletes a userscript body. False when there was nothing to delete. */
    fun scriptRemove(id: String): Boolean =
        runCatching { git.shin.adfree.core.coreScriptRemove(id) }.getOrDefault(false)

    /** The userscript body, for the core's script engine. */
    fun scriptText(id: String): String? =
        runCatching { git.shin.adfree.core.coreScriptText(id) }.getOrNull()

    /**
     * Writes the script bodies the core ships into the store, keeping them in
     * step with the app; returns how many files changed.
     */
    fun installBuiltinScripts(): Int =
        runCatching { git.shin.adfree.core.coreInstallBuiltinScripts().toInt() }.getOrDefault(0)

    /** "15/05/2025 23:04" from a file timestamp, for the list rows. */
    fun dateText(epochMs: Long): String =
        java.text.SimpleDateFormat("dd/MM/yyyy HH:mm", java.util.Locale.getDefault())
            .format(java.util.Date(epochMs))

    /**
     * Installs the callback the core uses to `protect()` the TCP sockets it
     * opens on demand (one per relayed connection).
     *
     * A preallocated pool is no longer possible: with every TCP flow relayed,
     * the number of live sockets follows the apps' behaviour instead of a
     * constant, so the core creates them itself and asks us to protect each.
     */
    fun setSocketProtector(protector: git.shin.adfree.core.SocketProtector) {
        runCatching { git.shin.adfree.core.coreSetSocketProtector(protector) }
            .onFailure { Log.w(tag, "setSocketProtector failed", it) }
    }

    /** Number of live relays, for the settings screen. */
    fun relayCount(): Int = runCatching { git.shin.adfree.core.coreRelayCount().toInt() }.getOrDefault(0)

    // ------------------------------------------------------------------- MITM

    /**
     * Returns the CA certificate PEM, minting and persisting the pair in the
     * store on first use. The private half stays under the core's directory,
     * mode 600, and never leaves the device.
     */
    fun ensureCa(): String = runCatching { git.shin.adfree.core.coreEnsureCa() }.getOrDefault("")

    /** Deletes the persisted CA so the next `ensureCa()` mints a fresh one. */
    fun resetCa() {
        runCatching { git.shin.adfree.core.coreResetCa() }
    }

    /**
     * Opens the Settings screen that leads to the CA installer.
     *
     * The platform refuses to install a CA certificate inline (`KeyChain`
     * install intents answer "Install CA certificates in Settings"), so the
     * user has to walk the Settings flow: Encryption & credentials → Install a
     * certificate → CA certificate → pick the exported file → confirm the
     * monitoring warning. [exportCaCertificate] puts that file where the
     * picker can reach it.
     */
    fun installCertificateIntent(): Intent =
        Intent(Settings.ACTION_SECURITY_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

    /**
     * Copies the CA certificate to the shared Downloads folder.
     *
     * The Settings file picker cannot open app-private storage, so the
     * certificate has to travel through the media store for the install flow
     * to finish. Only the certificate is copied; the private half stays in
     * [caKeyFile]. Returns the exported file name, or null when it failed.
     */
    fun exportCaCertificate(): String? {
        val pem = runCatching { ensureCa() }.getOrNull() ?: return null
        val name = "AdFree-CA.crt"
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return runCatching {
                @Suppress("DEPRECATION")
                val downloads = Environment
                    .getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                if (!downloads.exists() && !downloads.mkdirs()) return null
                File(downloads, name).writeText(pem)
                name
            }.getOrNull()
        }
        return runCatching {
            val resolver = AdGuardApplication.instance.contentResolver
            val collection = MediaStore.Downloads.EXTERNAL_CONTENT_URI
            // Replace any earlier copy: two identical rows would leave the
            // picker showing the same certificate twice with no way to tell
            // them apart.
            resolver.delete(
                collection,
                "${MediaStore.Downloads.DISPLAY_NAME} = ?",
                arrayOf(name),
            )
            val uri = resolver.insert(
                collection,
                ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, name)
                    put(MediaStore.Downloads.MIME_TYPE, "application/x-x509-ca-cert")
                    put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                    put(MediaStore.Downloads.IS_PENDING, 1)
                },
            ) ?: return null
            resolver.openOutputStream(uri)?.use { it.write(pem.toByteArray()) }
            resolver.update(
                uri,
                ContentValues().apply { put(MediaStore.Downloads.IS_PENDING, 0) },
                null,
                null,
            )
            name
        }.getOrNull()
    }

    /**
     * True when our CA sits in the device trust store.
     *
     * Trust is checked by comparing DER bytes, not aliases: the same
     * certificate can live in the user store (installed through the dialog
     * above) or in the system store (preloaded images, emulator tooling), and
     * either way the leaves we mint are accepted.
     */
    fun isCaTrusted(): Boolean {
        val pem = runCatching { git.shin.adfree.core.coreCaPem() }.getOrNull().orEmpty()
        if (pem.isBlank()) return false
        val expected = runCatching {
            CertificateFactory.getInstance("X.509")
                .generateCertificate(pem.byteInputStream())
        }.getOrNull() as? X509Certificate ?: return false
        val store = runCatching {
            KeyStore.getInstance("AndroidCAStore").apply { load(null, null) }
        }.getOrNull() ?: return false
        return runCatching {
            val aliases = store.aliases()
            while (aliases.hasMoreElements()) {
                val cert = store.getCertificate(aliases.nextElement()) as? X509Certificate
                    ?: continue
                if (cert.encoded.contentEquals(expected.encoded)) return true
            }
            false
        }.getOrDefault(false)
    }

    /** Current MITM status from the core. */
    fun mitmStatus(): git.shin.adfree.core.MitmStatus? =
        runCatching { git.shin.adfree.core.coreMitmStatus() }.getOrNull()

    /** Replaces the user script list plus the master switch. */
    fun setScripts(scripts: List<ScriptBinding>, enabled: Boolean) {
        runCatching { git.shin.adfree.core.coreSetScripts(scripts, enabled) }
            .onFailure { Log.w(tag, "setScripts failed", it) }
    }

    /** The combined JS served at the injection URL. */
    fun combinedScripts(): String =
        runCatching { git.shin.adfree.core.coreCombinedScripts() }.getOrDefault("")

    // ------------------------------------------------------------------ stats

    fun stats(): git.shin.adfree.core.StatsSnapshot =
        runCatching { git.shin.adfree.core.coreStats() }.getOrElse {
            StatsSnapshot(
                packetsTotal = 0,
                packetsDns = 0,
                packetsForwarded = 0,
                dnsBlocked = 0,
                dnsAllowed = 0,
                tcpReset = 0,
                quicDropped = 0,
                udpDropped = 0,
                dnsQueries = 0,
                dnsReplies = 0,
                dnsTimeouts = 0,
                bytesSaved = 0,
                decisionNsAvg = 0,
                decisionNsEwma = 0,
                decisionNsMax = 0,
                cacheHits = 0,
                activeRules = 0,
                engineBytes = 0,
                rssKb = 0,
                loopIterations = 0,
                busyNs = 0,
                tlsNs = 0,
                handshakeNs = 0,
                rewriteNs = 0,
                logDropped = 0,
                eventsPending = 0,
                eventsDropped = 0,
                filterBuildMs = 0,
                conntrackEntries = 0,
                pendingDns = 0,
                uptimeMs = 0,
                isBuilding = false,
            )
        }

    fun isBuilding(): Boolean = mitmStatus() != null && stats().activeRules == 0L

    fun isScreenOff(): Boolean = screenOffFlag

    fun markScreenOff() {
        screenOffFlag = true
    }

    fun markScreenOn() {
        screenOffFlag = false
    }

    fun markWantsStart() {
        pendingStart = true
        _wantsVpnStateFlow.value = true
    }

    fun markWantsStop() {
        pendingStart = false
        _wantsVpnStateFlow.value = false
    }

    val wantsStart: Boolean get() = pendingStart

    private val _wantsVpnStateFlow = kotlinx.coroutines.flow.MutableStateFlow(true)
    val wantsVpnStateFlow: kotlinx.coroutines.flow.StateFlow<Boolean> = _wantsVpnStateFlow

    fun resetStats() = runCatching { git.shin.adfree.core.coreResetStats() }

    // ------------------------------------------------ persisted request log

    /**
     * One page of the log stored in SQLite, newest first. Rust caps a page at
     * 500 rows; the app keeps its own, smaller page size.
     */
    fun logPage(offset: Int, limit: Int): List<LogEvent> =
        runCatching { git.shin.adfree.core.coreLogPage(offset.toUInt(), limit.toUInt()) }
            .getOrDefault(emptyList())

    /** Total rows in the persisted log (0 while the store is not open). */
    fun logCount(): Long = runCatching { git.shin.adfree.core.coreLogCount() }.getOrDefault(0L)

    /** Empties the persisted log, queued rows included. */
    fun logClear() = runCatching { git.shin.adfree.core.coreLogClear() }

    // ------------------------------------------------------------ log plumbing

    val nativeLogLines: List<String>
        get() = runCatching { git.shin.adfree.core.coreTakeLogLines() }.getOrDefault(emptyList())

    /**
     * Forwards whatever the core buffered to logcat. The core cannot log on the
     * packet threads (that would be I/O in the hot path), so warnings sit in a
     * bounded ring until something drains them — that has to happen or every
     * native warning is silently lost.
     */
    fun flushNativeLogLines() {
        for (line in nativeLogLines) {
            Log.i(TAG, line)
        }
    }

    companion object {
        private const val TAG = "AdFreeCore"
        private const val SOCKET_COUNT = 4
        private var pendingStart = true

        @Volatile
        var screenOffFlag = false
    }
}

/** Result of downloading a subscription or userscript. */
data class DownloadResult(
    val ok: Boolean,
    val message: String,
    val lineCount: Long = 0,
    val version: String? = null,
    val updatedText: String? = null,
    val detectedFormat: String? = null,
    /** Bytes on disk after the download; 0 for a failure. */
    val sizeBytes: Long = 0,
)

/**
 * The core's `$app=` attribution, answered by the framework.
 *
 * `ConnectivityManager.getConnectionOwnerUid` (API 34+) is the only
 * unprivileged way to learn which app owns a connection: a VpnService may ask
 * it about the flows its own tunnel carries, and the system names their owner
 * from the kernel's socket table on our behalf. `/proc/net/tcp` — what the
 * desktop core reads — has been closed to apps since Android 10.
 *
 * Every failure has to look like "no answer": an older release, a flow the
 * kernel already forgot, a permission the system no longer grants. The core
 * reads a missing uid as "apply no `$app=` rule at all", never as "apply every
 * one of them", so this stays safe while remaining useful.
 */
private class FrameworkUidLookup(private val context: Context) :
    git.shin.adfree.core.ConnectionUidLookup {

    override fun ownerUid(
        protocol: UByte,
        localIp: String,
        localPort: UShort,
        remoteIp: String,
        remotePort: UShort,
    ): UInt? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) return null
        return runCatching {
            val connections = context.getSystemService(android.net.ConnectivityManager::class.java)
                ?: return null
            // The core hands us the IP protocol number (6 TCP, 17 UDP), which
            // is what `getConnectionOwnerUid` documents as its first argument.
            val uid = connections.getConnectionOwnerUid(
                protocol.toInt(),
                java.net.InetSocketAddress(localIp, localPort.toInt()),
                java.net.InetSocketAddress(remoteIp, remotePort.toInt()),
            )
            if (uid == android.os.Process.INVALID_UID) null else uid.toUInt()
        }.getOrNull()
    }
}
