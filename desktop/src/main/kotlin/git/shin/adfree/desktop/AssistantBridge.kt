package git.shin.adfree.desktop

import git.shin.adfree.core.CoreEngine
import git.shin.adfree.data.AdGuardRepository
import git.shin.adfree.platform.TunnelControl
import git.shin.adfree.ui.AdGuardIntent
import git.shin.adfree.ui.AdGuardTab
import git.shin.adfree.ui.AdGuardViewModel
import java.io.File
import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * The half AdGuard's browser extension needs and cannot have on its own.
 *
 * The extension (`adguard browser assistant`, chrome web store id
 * `fbohpolgemkbfphodcfgnpjcmedcjhpn`) is a Chrome MV3 extension. It cannot see
 * files, ports or a filtering engine, so everything it knows about *the app*
 * arrives over Chrome's **native messaging** channel: a 4-byte little-endian
 * length followed by JSON, on the stdin and stdout of a helper process named
 * `com.adguard.browser_extension_host.nm`.
 *
 * `adfree-native-host` is that helper: a pipe that forwards each message to
 * the Unix socket this class listens on. The protocol lives here, next to the
 * state it reports, so the host process stays a pass-through and a message can
 * never be answered by a process older than the window that owns the tunnel.
 *
 * Request and response shapes are AdGuard's, taken from the extension's own
 * source (`src/lib/types.ts` and `src/background/api`), because a client
 * cannot be asked to change: `{ id, type, parameters }` in,
 * `{ requestId, result: "ok"|"error", data?, parameters?, appState }` back.
 * `appState` travels on almost every answer — the extension feeds it straight
 * into its own state and throws if the three required flags are missing.
 */
class AssistantBridge(
    private val engine: CoreEngine,
    private val repository: AdGuardRepository,
    private val viewModel: AdGuardViewModel,
    private val tunnel: TunnelControl,
    private val appVersion: String,
    private val locale: () -> String,
    /**
     * Brings the window to the front. The extension's "Mở nhật ký lọc" and
     * "Cài đặt" are requests to *see* a screen: switching the tab in a window
     * that stays behind the browser is a button that does nothing.
     */
    private val raiseWindow: () -> Unit = {},
    private val log: (String) -> Unit = {},
) {

    private val json = Json { ignoreUnknownKeys = true }

    /** Guards [clients] and each client's write; Chrome may read slowly. */
    private val clients = mutableListOf<Client>()
    private val clientsLock = Mutex()

    private var server: ServerSocketChannel? = null
    private var running = false

    private class Client(val channel: SocketChannel) {
        val writeLock = Mutex()
    }

    /** Where the socket lives: next to the tray's other per-user runtime files. */
    fun socketFile(): File {
        val runtime = System.getenv("XDG_RUNTIME_DIR")
        val dir = if (runtime.isNullOrBlank()) {
            File(System.getProperty("user.home"), ".local/share/adfree")
        } else {
            File(runtime, "adfree")
        }
        dir.mkdirs()
        return File(dir, SOCKET_NAME)
    }

    /**
     * Starts listening, and keeps the extension's idea of the app current.
     *
     * A push is what makes the toolbar icon honest: protection switched off in
     * the window has to reach an already-open popup without it asking again.
     */
    fun start(scope: CoroutineScope) {
        if (running) return
        running = true
        val path = socketFile().toPath()
        runCatching { listen(path) }.onFailure {
            log("assistant bridge: cannot listen on $path: ${it.message}")
            running = false
            return
        }
        scope.launch(Dispatchers.IO) { acceptLoop() }
        scope.launch(Dispatchers.IO) { stateTicker() }
        log("assistant bridge: listening on $path")
    }

    /**
     * Pushes whenever the answer to "is this machine being filtered?" changes.
     *
     * Polling rather than listening: the three facts the extension shows come
     * from three different places — the persisted protection record, the core's
     * listener state, the HTTPS switch — and the interesting transitions happen
     * a moment *after* the intent that caused them (the redirect is installed,
     * the listeners bind, the engine is rebuilt). A push on the setting alone
     * fired too early and told the popup "off" right after the user switched it
     * on, and nothing corrected it afterwards.
     */
    private suspend fun stateTicker() {
        var last: String? = null
        while (running) {
            val current = appState().toString()
            if (current != last) {
                last = current
                push()
            }
            delay(STATE_TICK_MS)
        }
    }

    /**
     * Waits for an intent's effect to reach the state the extension reads.
     *
     * The popup keeps what the *answer* said, so answering before the listeners
     * come up would leave it showing the opposite of the truth until reopened.
     * The wait is bounded: an answer that takes longer than [STATE_SETTLE_MS]
     * is answered as it is, and the ticker corrects it when it lands.
     */
    private suspend fun settle(until: () -> Boolean) {
        val deadline = System.currentTimeMillis() + STATE_SETTLE_MS
        while (!until() && System.currentTimeMillis() < deadline) delay(50)
    }

    /**
     * Binds the socket, reclaiming it from a previous run.
     *
     * A Unix socket is a *file*: when the app is killed the file stays behind
     * and the next start cannot take the name. Deleting it blindly would be
     * wrong in the one case that matters — a second instance of the window —
     * so the file is probed first: a live listener accepts, a corpse refuses,
     * and only a corpse is removed.
     */
    private fun listen(path: java.nio.file.Path) {
        if (java.nio.file.Files.exists(path)) {
            val alive = runCatching {
                SocketChannel.open(UnixDomainSocketAddress.of(path)).use { }
                true
            }.getOrDefault(false)
            if (alive) {
                throw IllegalStateException("another AdFree window owns the socket")
            }
            java.nio.file.Files.deleteIfExists(path)
        }
        server = ServerSocketChannel.open(StandardProtocolFamily.UNIX).apply {
            bind(UnixDomainSocketAddress.of(path))
        }
    }

    fun stop() {
        running = false
        runCatching { server?.close() }
        server = null
        socketFile().delete()
    }

    private suspend fun acceptLoop() {
        val channel = server ?: return
        while (running) {
            val accepted = runCatching { channel.accept() }.getOrNull() ?: continue
            val client = Client(accepted)
            clientsLock.withLock { clients.add(client) }
            CoroutineScope(Dispatchers.IO).launch { serve(client) }
        }
    }

    private suspend fun serve(client: Client) {
        try {
            while (running) {
                val request = readFrame(client.channel) ?: return
                val response = respond(request)
                client.writeLock.withLock {
                    writeFrame(client.channel, response.toByteArray())
                }
            }
        } catch (error: Exception) {
            // A popup that closes mid-answer is normal and not a fault: Chrome
            // drops the connection when the panel is dismissed.
            val message = error.message.orEmpty()
            val wentAway = message.contains("Ống dẫn bị hỏng") ||
                message.contains("Broken pipe") ||
                message.contains("Connection reset") ||
                error is java.io.IOException && message.isBlank()
            if (!wentAway) log("assistant bridge: connection ended: $message")
        } finally {
            clientsLock.withLock { clients.remove(client) }
            runCatching { client.channel.close() }
        }
    }

    /** Writes the extension's own state shape to every connected popup. */
    private suspend fun push() {
        // The extension only hands an unsolicited message to its own listeners
        // when `requestId` carries this prefix (`background/api` drops the rest
        // as a reply nothing asked for); without it a push is silently thrown
        // away and an open popup keeps showing the state it opened with.
        val message = buildJsonObject {
            put("requestId", PUSH_REQUEST_ID)
            put("appState", appState())
        }.toString().toByteArray()
        clientsLock.withLock { clients.toList() }.forEach { client ->
            runCatching { client.writeLock.withLock { writeFrame(client.channel, message) } }
        }
    }

    // ------------------------------------------------------------ protocol

    private suspend fun respond(raw: ByteArray): String {
        val request = runCatching { json.parseToJsonElement(String(raw)).jsonObject }.getOrNull()
            ?: return error("", "malformed request")
        val id = request["id"]?.jsonPrimitive?.contentOrNull.orEmpty()
        val parameters = request["parameters"]?.let {
            runCatching { it.jsonObject }.getOrNull()
        } ?: JsonObject(emptyMap())
        val type = request["type"]?.jsonPrimitive?.contentOrNull.orEmpty()
        log("assistant bridge: $id -> $type")
        return runCatching {
            when (type) {
                "init" -> ok(id, parameters = initParameters())
                "getCurrentAppState" -> ok(id)
                "getCurrentFilteringState" -> {
                    // The popup's "start AdGuard" button asks for this page's
                    // state and says `forceStartApp`: the request *is* the
                    // start. Answering without starting left the button dead.
                    if (parameters["forceStartApp"]?.jsonPrimitive?.booleanOrNull == true) {
                        setProtection(true)
                        settle { protectionOn() }
                    }
                    ok(id, parameters = filteringState(parameters))
                }
                "setProtectionStatus" -> {
                    val on = parameters["isEnabled"]?.jsonPrimitive?.booleanOrNull ?: false
                    setProtection(on)
                    settle { protectionOn() == on }
                    ok(id)
                }
                "setFilteringStatus" -> {
                    val url = parameters["url"]?.jsonPrimitive?.contentOrNull
                    val filtering = parameters["isEnabled"]?.jsonPrimitive?.booleanOrNull ?: false
                    setFiltering(
                        url = url,
                        filtering = filtering,
                        https = parameters["isHttpsEnabled"]?.jsonPrimitive?.booleanOrNull,
                    )
                    val host = hostOf(url)
                    settle {
                        val excepted = host != null && isExcepted(host)
                        if (filtering) !excepted else excepted
                    }
                    ok(id)
                }
                "addRule" -> {
                    val rule = parameters["ruleText"]?.jsonPrimitive?.contentOrNull.orEmpty()
                    if (rule.isBlank()) error(id, "empty rule") else {
                        repository.addCustomRule(rule)
                        ok(id)
                    }
                }
                "removeCustomRules" -> {
                    removeRulesFor(parameters["url"]?.jsonPrimitive?.contentOrNull)
                    ok(id)
                }
                "openOriginalCert" -> ok(id)
                "reportSite" -> {
                    // AdFree has nobody to report to and does not phone home,
                    // so the request is acknowledged: the popup's flow ends.
                    log(
                        "assistant bridge: report requested for " +
                            parameters["url"]?.jsonPrimitive?.contentOrNull.orEmpty(),
                    )
                    ok(id)
                }
                "openFilteringLog" -> {
                    viewModel.onIntent(AdGuardIntent.SelectTab(AdGuardTab.ACTIVITY))
                    raiseWindow()
                    ok(id)
                }
                "openSettings" -> {
                    viewModel.onIntent(AdGuardIntent.SelectTab(AdGuardTab.SETTINGS))
                    raiseWindow()
                    ok(id)
                }
                "updateApp" -> {
                    viewModel.checkAppUpdateManually()
                    ok(id)
                }
                "pauseFiltering" -> {
                    val url = parameters["url"]?.jsonPrimitive?.contentOrNull
                    pauseFiltering(
                        url = url,
                        seconds = parameters["timeout"]?.jsonPrimitive?.intOrNull ?: 30,
                    )
                    // The popup shows "paused" from the answer, and the rule is
                    // the only evidence the page really is out of filtering.
                    hostOf(url)?.let { host -> settle { isExcepted(host) } }
                    ok(id)
                }
                else -> error(id, "unknown request type")
            }
        }.getOrElse { error(id, it.message ?: "failed") }
    }

    private fun initParameters(): JsonObject = initPayload(hostVersion())

    /**
     * A version the extension can compare, not our build label.
     *
     * `coreEngine.version` reads like `1.0.0 + adblock 0.13.3`; the extension
     * splits on dots and numbers the parts, so the suffix has to go before it
     * is compared (`Number("0 + adblock 0.13.3")` is NaN).
     */
    private fun hostVersion(): String =
        appVersion.trim().substringBefore(' ').ifBlank { "1.0.0" }

    /** Whether the machine is being filtered right now. */
    private fun protectionOn(): Boolean =
        engine.isProxyRunning() && repository.settings.value.isProtectionActive

    /** Required flags first: the extension throws when one of them is missing. */
    private fun appState(): JsonObject = buildJsonObject {
        put("isInstalled", true)
        put("isRunning", engine.isProxyRunning())
        put("isProtectionEnabled", protectionOn())
        put("isLicenseExpired", false)
        put("isAuthorized", true)
        put("locale", locale())
        // A command, not state: "updateApplicationAppOnly" leaves the
        // extension's own filtering feedback alone.
        put("feedbackAction", "updateApplicationAppOnly")
    }

    /**
     * What the popup shows for the tab in front: is this page filtered, is
     * HTTPS filtering on, and may the popup change its mind.
     *
     * "Filtered" is read from the rules rather than remembered: a page the user
     * excepted has an `@@||host^$document` rule, and that rule is the truth the
     * engine itself uses.
     */
    private fun filteringState(parameters: JsonObject): JsonObject {
        val host = hostOf(parameters["url"]?.jsonPrimitive?.contentOrNull)
        val excepted = host != null && isExcepted(host)
        return filteringPayload(host, excepted, repository.settings.value.isHttpsFilteringEnabled)
    }

    /** True when the rules say this host was taken out of filtering. */
    private fun isExcepted(host: String): Boolean =
        customRules().any { it.startsWith("@@") && ruleTargets(it, host) }

    private fun setProtection(on: Boolean) {
        if (protectionOn() == on) return
        viewModel.onIntent(AdGuardIntent.ToggleProtection)
    }

    private fun setFiltering(url: String?, filtering: Boolean, https: Boolean?) {
        val host = hostOf(url)
        if (host != null) {
            val exception = "@@||$host^${'$'}document"
            if (!filtering && customRules().none { it == exception }) {
                repository.addCustomRule(exception)
            }
            if (filtering) {
                customRules().filter { ruleTargets(it, host) && it.startsWith("@@") }
                    .forEach { repository.removeCustomRule(it) }
            }
        }
        if (https != null && https != repository.settings.value.isHttpsFilteringEnabled) {
            viewModel.onIntent(AdGuardIntent.ToggleHttps)
        }
    }

    /**
     * "Don't filter this page for N seconds" is the popup's pause button. It is
     * the same document exception the in-page assistant's temporary window
     * uses, removed again when the timer runs out.
     */
    private fun pauseFiltering(url: String?, seconds: Int) {
        val host = hostOf(url) ?: return
        val exception = "@@||$host^${'$'}document"
        if (customRules().none { it == exception }) {
            repository.addCustomRule(exception)
        }
        CoroutineScope(Dispatchers.IO).launch {
            delay((seconds.coerceIn(1, 600)) * 1000L)
            repository.removeCustomRule(exception)
        }
    }

    private fun removeRulesFor(url: String?) {
        val host = hostOf(url) ?: return
        customRules().filter { ruleTargets(it, host) }.forEach { repository.removeCustomRule(it) }
    }

    /** The user's own rules: what the app stores, which is what the engine gets. */
    private fun customRules(): List<String> =
        repository.filterLists.value.firstOrNull { it.isCustom }?.customRules.orEmpty()

    /** True when this rule names [host] (a site exception, an element rule). */
    private fun ruleTargets(rule: String, host: String): Boolean {
        val text = rule.trim().removePrefix("@@").removePrefix("||").removePrefix(".")
        return text.startsWith(host, ignoreCase = true)
    }

    private fun hostOf(url: String?): String? {
        if (url.isNullOrBlank()) return null
        return runCatching {
            val parsed = java.net.URI(url)
            if (parsed.scheme?.startsWith("http") != true) null else parsed.host?.lowercase()
        }.getOrNull()
    }

    private fun ok(id: String, parameters: JsonObject? = null): String = buildJsonObject {
        put("requestId", id)
        put("result", "ok")
        if (parameters != null) put("parameters", parameters)
        put("appState", appState())
    }.toString()

    private fun error(id: String, reason: String): String = buildJsonObject {
        put("requestId", id)
        put("result", "error")
        put("data", reason)
        put("appState", appState())
    }.toString()

    companion object {
        const val SOCKET_NAME: String = "adfree-assistant.sock"

        /**
         * What an unsolicited push is labelled with.
         *
         * `background/api`'s message pump accepts an unsolicited message only
         * when its `requestId` starts with `ADG` and is not one of the
         * single-request `ADG_CUSTOM_*` ids; anything else is treated as a
         * reply to a request that no longer exists and dropped. This id names
         * no request — it exists to pass that gate.
         */
        const val PUSH_REQUEST_ID: String = "ADG_STATE"

        /** How often the pushed state is recomputed; cheap enough to poll. */
        const val STATE_TICK_MS: Long = 500

        /** The longest an action may wait for its effect before answering. */
        const val STATE_SETTLE_MS: Long = 4_000

        /**
         * The init answer, with the field choices that keep the popup alive.
         *
         * The extension compares its own API version with this one and shows
         * "the app is out of date" when ours is lower; version 1 is what its
         * published build speaks.
         *
         * **No platform, deliberately.** The extension knows exactly two —
         * `windows` and `mac` — and gates its pause button on
         * `FILTERING_PAUSE_VERSION_SUPPORT_SINCE[platform.toUpperCase()]`. A
         * third name ("Linux") is not a harmless unknown: the lookup is
         * undefined, that undefined reaches the semver compare, and the popup
         * throws while composing its first data bundle. The panel then sits on
         * "AdGuard is starting…" forever. An empty platform is the answer the
         * extension's own code handles — no platform, no pause button.
         */
        internal fun initPayload(version: String): JsonObject = buildJsonObject {
            put("apiVersion", API_VERSION)
            put("version", version)
            put("platform", "")
            put("isValidatedOnHost", true)
        }

        /**
         * The per-tab answer. Every field here is one the popup reads without a
         * guard:
         *
         * - `originalCertStatus` is passed straight to `.toUpperCase()`, so a
         *   missing value throws and the popup never leaves its loading state.
         *   VALID is the extension's own starting value and the truthful one:
         *   a page the browser accepted reached it through a chain the browser
         *   still had to approve.
         * - `isFilteringEnabled` is derived from the user's rules rather than
         *   remembered — a page the user excepted has an `@@||host^$document`
         *   rule, and that rule is what the engine itself reads.
         */
        internal fun filteringPayload(
            host: String?,
            excepted: Boolean,
            httpsFiltering: Boolean,
        ): JsonObject = buildJsonObject {
            put("isFilteringEnabled", host != null && !excepted)
            put("isHttpsFilteringEnabled", httpsFiltering)
            put("canChangeFilteringStatus", true)
            put("originalCertStatus", "VALID")
            put("originalCertIssuer", null as String?)
            put("isPageFilteredByUserFilter", false)
        }

        /** The API version the published extension speaks. */
        const val API_VERSION: String = "1"

        /**
         * Chrome's native-messaging framing: a 4-byte **little-endian** length,
         * then that many bytes of JSON. Byte order is the point — a length read
         * the other way round is a nonsense size, and dropping the connection
         * over it would look exactly like the app not running.
         */
        internal fun readFrame(channel: SocketChannel): ByteArray? {
            val header = ByteBuffer.allocate(4)
            while (header.hasRemaining()) {
                if (channel.read(header) < 0) return null
            }
            header.flip()
            val length = java.lang.Integer.reverseBytes(header.int)
            if (length <= 0 || length > 64 * 1024 * 1024) return null
            val body = ByteBuffer.allocate(length)
            while (body.hasRemaining()) {
                if (channel.read(body) < 0) return null
            }
            return body.array()
        }

        internal fun writeFrame(channel: SocketChannel, payload: ByteArray) {
            val buffer = ByteBuffer.allocate(4 + payload.size)
            buffer.putInt(java.lang.Integer.reverseBytes(payload.size))
            buffer.put(payload)
            buffer.flip()
            while (buffer.hasRemaining()) channel.write(buffer)
        }
    }
}
