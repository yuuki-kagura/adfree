package git.shin.adfree.core

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.util.Log
import git.shin.adfree.model.DnsBlockMode
import git.shin.adfree.model.NetworkRequestLog
import java.io.File

/**
 * Kotlin-side wrapper around the uniffi bindings (`adfree.kt`).
 *
 * All heavy lifting lives in native code: this class holds the TUN fd, the
 * already-`protect()`ed UDP sockets, the CA files on disk, and the few things
 * that need an Android context (logcat, filter files).
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

    private fun closeUpstreamSockets() {
        closeHeldSockets()
        upstreamSockets.clear()
    }

    /**
     * Releases every descriptor handed to the core. Called only from `stop()`,
     * once the engine has stopped using them.
     */
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
        blockQuic: Boolean,
        blockDoh: Boolean,
        blockMode: DnsBlockMode,
        logAllowed: Boolean,
        ecoMode: Boolean,
    ) {
        val config = git.shin.adfree.core.EngineConfig(
            mitmEnabled = mitmEnabled,
            blockQuic = blockQuic,
            blockDoh = blockDoh,
            blockDot = true,
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

    fun addUserRules(rules: List<String>) {
        runCatching { git.shin.adfree.core.coreSetLists(listOf(), rules) }
            .onFailure { Log.w(tag, "addUserRules failed", it) }
    }

    fun deleteUserRules(rules: List<String>) {
        // The core compiles from "all current rules"; deleting means a rebuild without them.
        runCatching { git.shin.adfree.core.coreSetLists(listOf(), emptyList()) }
            .onFailure { Log.w(tag, "deleteUserRules failed", it) }
    }

    /**
     * Count the rule lines in a filter file (used by the UI when the file
     * already exists on disk, so no re-download is needed).
     */
    fun countRules(file: File): Int = runCatching {
        var count = 0
        file.forEachLine { line ->
            val t = line.trim()
            if (t.isNotEmpty() && !t.startsWith("!") && !t.startsWith("[") && !t.startsWith("#")) {
                count++
            }
        }
        count
    }.getOrDefault(0)

    /** Scan one host (Security Lab screen). */
    fun checkHost(host: String): HostVerdictBinding =
        runCatching { git.shin.adfree.core.coreCheckHost(host) }.getOrElse {
            HostVerdictBinding(blocked = false, rule = "", listName = "", category = 0)
        }

    fun clearDnsCache() = runCatching { git.shin.adfree.core.coreClearDnsCache() }

    fun setDohRanges(ranges: List<String>) {
        runCatching { git.shin.adfree.core.coreSetDohRanges(ranges) }
    }

    /** Download one subscription to `filesDir/filters/<id>.txt`. */
    fun downloadList(list: git.shin.adfree.model.FilterList): DownloadResult {
        val url = list.subscriptionUrl ?: return DownloadResult(false, "Danh sách này không có URL")
        val file = listFileFor(list)
        return try {
            val request = okhttp3.Request.Builder()
                .url(url)
                .header("User-Agent", USER_AGENT)
                .build()
            okhttp3.OkHttpClient.Builder()
                .connectTimeout(15, java.util.concurrent.TimeUnit.SECONDS)
                .readTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
                .build()
                .newCall(request)
                .execute()
                .use { response ->
                    if (!response.isSuccessful) {
                        return DownloadResult(false, "HTTP ${response.code}")
                    }
                    val body = response.body?.string().orEmpty()
                    if (body.isBlank()) return DownloadResult(false, "Danh sách rỗng")
                    file.writeText(body)
                    val count = body.lines().count { line ->
                        val t = line.trim()
                        t.isNotEmpty() && !t.startsWith("!") && !t.startsWith("[") && !t.startsWith("#")
                    }
                    DownloadResult(true, "Đã tải ${list.name} ($count quy tắc)", count.toLong())
                }
        } catch (e: Exception) {
            DownloadResult(false, "Lỗi: ${e.javaClass.simpleName}")
        }
    }

    fun listFileFor(list: git.shin.adfree.model.FilterList): File {
        val dir = File(filesRoot(), "filters").apply { mkdirs() }
        return File(dir, "${sanitizeId(list.id)}.txt")
    }

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

    /** Directory that holds the CA and filter files. */
    private fun coreFilesDir(): File = File(filesRoot(), "core").apply { mkdirs() }

    private fun caCertFile(): File = File(coreFilesDir(), "ca.pem")
    private fun caKeyFile(): File = File(coreFilesDir(), "ca-key.pem")

    /**
     * Returns the CA certificate PEM, creating the CA if needed.
     *
     * Both halves are persisted so the user installs the certificate once: the
     * key is mode 600 and only readable by this app.
     */
    fun ensureCa(): String {
        val certFile = caCertFile()
        val keyFile = caKeyFile()
        if (certFile.exists() && keyFile.exists()) {
            val cert = certFile.readText()
            val key = keyFile.readText()
            if (cert.isNotBlank() && key.isNotBlank() &&
                runCatching { git.shin.adfree.core.coreRestoreCa(cert, key) }.getOrDefault(false)
            ) {
                return git.shin.adfree.core.coreCaPem()
            }
        }
        val pem = runCatching { git.shin.adfree.core.coreGenerateCa() }.getOrDefault("")
        if (pem.isNotEmpty()) {
            val key = runCatching { git.shin.adfree.core.coreCaKeyPem() }.getOrDefault("")
            certFile.writeText(pem)
            if (key.isNotBlank()) keyFile.writeText(key)
        }
        return pem
    }

    /** Deletes the persisted CA so the next `ensureCa()` mints a fresh one. */
    fun resetCa() {
        runCatching { caCertFile().delete() }
        runCatching { caKeyFile().delete() }
    }

    /** Opens the system screen where the user installs a CA certificate. */
    fun installCertificateIntent(): Intent {
        // Android has no deep link for "install CA", so open the encryption screen
        // and let the user pick "Install a certificate".
        return Intent(Settings.ACTION_SECURITY_SETTINGS)
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

    fun drainEvents(max: Int): List<LogEvent> =
        runCatching { git.shin.adfree.core.coreDrainEvents(max) }.getOrDefault(emptyList())

    fun clearEvents() = runCatching { git.shin.adfree.core.coreClearEvents() }

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
        private const val USER_AGENT = "AdFree/1.0 (Android)"
        private var pendingStart = true

        @Volatile
        var screenOffFlag = false

        /** Where the app stores core files; injected by the DI container. */
        var filesRootProvider: () -> String = { "/data/data/git.shin.adfree/files" }

        fun filesRoot(): String = filesRootProvider()

        fun sanitizeId(id: String): String =
            id.map { if (it.isLetterOrDigit()) it else '_' }.joinToString("").take(64)
    }
}

/** Result of downloading a subscription. */
data class DownloadResult(
    val ok: Boolean,
    val message: String,
    val lineCount: Long = 0,
)
