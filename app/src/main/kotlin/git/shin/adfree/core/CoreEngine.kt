package git.shin.adfree.core

import android.content.ContentValues
import android.content.Intent
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
 * already-`protect()`ed UDP sockets, the CA files on disk, and the few things
 * that need an Android context (logcat, filter files).
 */
class CoreEngine {

    private val tag = "AdFreeCore"

    /** UDP sockets used to forward DNS, `VpnService.protect()`ed so they do not loop. */
    private val upstreamSockets = mutableListOf<java.net.DatagramSocket>()

    /** Shared HTTP client: a fresh one per download would waste a thread pool each time. */
    private val httpClient by lazy {
        okhttp3.OkHttpClient.Builder()
            .connectTimeout(15, java.util.concurrent.TimeUnit.SECONDS)
            .readTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
            .build()
    }

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
        val fetched = fetchUrl(url)
        if (!fetched.ok || fetched.body == null) return DownloadResult(false, fetched.message)
        val body = fetched.body
        val file = listFileFor(list)
        return try {
            file.writeText(body)
            val meta = parseListMeta(body)
            val count = body.lines().count { line ->
                val t = line.trim()
                t.isNotEmpty() && !t.startsWith("!") && !t.startsWith("[") && !t.startsWith("#")
            }
            DownloadResult(
                ok = true,
                message = "Đã tải ${list.name} ($count quy tắc)",
                lineCount = count.toLong(),
                version = meta.version,
                updatedText = meta.updatedText,
                detectedFormat = meta.format,
            )
        } catch (e: Exception) {
            DownloadResult(false, "Lỗi ghi tệp: ${e.javaClass.simpleName}")
        }
    }

    /** Plain GET with the app's User-Agent; filter lists and userscripts share it. */
    fun fetchUrl(url: String): FetchResult {
        return try {
            val request = okhttp3.Request.Builder()
                .url(url)
                .header("User-Agent", USER_AGENT)
                .build()
            httpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return FetchResult(false, "HTTP ${response.code}")
                val body = response.body?.string().orEmpty()
                if (body.isBlank()) return FetchResult(false, "Nội dung rỗng")
                FetchResult(ok = true, message = "OK", body = body)
            }
        } catch (e: Exception) {
            FetchResult(false, "Lỗi: ${e.javaClass.simpleName}")
        }
    }

    /**
     * Header metadata AdGuard-style comments carry, plus a guess at the syntax.
     * Hosts files look like `0.0.0.0 domain` lines instead of `||domain^`, and
     * the two formats are parsed differently, so this matters.
     */
    fun parseListMeta(text: String): ListMeta {
        var version: String? = null
        var updated: String? = null
        var hostsLike = 0
        var adblockLike = 0
        var inspected = 0
        for (line in text.lineSequence()) {
            if (inspected++ > 400) break
            val t = line.trim()
            when {
                t.startsWith("! Version:") -> version = t.substringAfter(':').trim().take(40)
                t.startsWith("! TimeUpdated:") -> updated = formatIsoDate(t.substringAfter(':')) ?: updated
                t.length < 3 || t.startsWith("!") || t.startsWith("#") || t.startsWith("[") -> {}
                HOSTS_LINE.containsMatchIn(t) -> hostsLike++
                else -> adblockLike++
            }
        }
        val format = when {
            hostsLike == 0 && adblockLike == 0 -> null
            hostsLike > adblockLike -> "hosts"
            else -> "standard"
        }
        return ListMeta(version, updated, format)
    }

    /** Header metadata of a list already on disk (only the first 60 lines are read). */
    fun readListMeta(file: File): ListMeta {
        val head = runCatching {
            file.bufferedReader().use { reader ->
                val sb = StringBuilder()
                var lines = 0
                while (lines < 60) {
                    val line = reader.readLine() ?: break
                    sb.append(line).append('\n')
                    lines++
                }
                sb.toString()
            }
        }.getOrDefault("")
        return parseListMeta(head)
    }

    /** "15/05/2025 23:04" from a file timestamp, for the list rows. */
    fun fileDateText(file: File): String =
        java.text.SimpleDateFormat("dd/MM/yyyy HH:mm", java.util.Locale.getDefault())
            .format(java.util.Date(file.lastModified()))

    private fun formatIsoDate(raw: String): String? = runCatching {
        val cleaned = raw.trim().take(19)
        val date = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", java.util.Locale.US).parse(cleaned)
        java.text.SimpleDateFormat("dd/MM/yyyy HH:mm", java.util.Locale.US).format(date!!)
    }.getOrNull()

    fun listFileFor(list: git.shin.adfree.model.FilterList): File {
        val dir = File(filesRoot(), "filters").apply { mkdirs() }
        return File(dir, "${sanitizeId(list.id)}.txt")
    }

    /** Where a userscript body lives: `filesDir/scripts/<id>.js`. */
    fun scriptFileFor(id: String): File {
        val dir = File(filesRoot(), "scripts").apply { mkdirs() }
        return File(dir, "${sanitizeId(id)}.js")
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
        private const val USER_AGENT = "AdFree/1.0 (Android)"
        private var pendingStart = true

        /** `0.0.0.0 example.com` / `127.0.0.1 example.com` host entries. */
        private val HOSTS_LINE = Regex("""^(0\.0\.0\.0|127\.0\.0\.1|::1?|::)\s+\S+""")

        @Volatile
        var screenOffFlag = false

        /** Where the app stores core files; injected by the DI container. */
        var filesRootProvider: () -> String = { "/data/data/git.shin.adfree/files" }

        fun filesRoot(): String = filesRootProvider()

        fun sanitizeId(id: String): String =
            id.map { if (it.isLetterOrDigit()) it else '_' }.joinToString("").take(64)
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
)

/** Raw HTTP GET result shared by list and script downloads. */
data class FetchResult(
    val ok: Boolean,
    val message: String,
    val body: String? = null,
)

/** Comment-header metadata of a filter list. */
data class ListMeta(
    val version: String?,
    val updatedText: String?,
    /** "hosts" or "standard"; null when the header was inconclusive. */
    val format: String?,
)
