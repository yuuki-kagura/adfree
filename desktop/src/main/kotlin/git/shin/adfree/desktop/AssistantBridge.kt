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
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
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
        scope.launch(Dispatchers.IO) {
            repository.settings
                .map { it.isProtectionActive to it.isHttpsFilteringEnabled }
                .distinctUntilChanged()
                .collect { push() }
        }
        log("assistant bridge: listening on $path")
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
            log("assistant bridge: connection ended: ${error.message}")
        } finally {
            clientsLock.withLock { clients.remove(client) }
            runCatching { client.channel.close() }
        }
    }

    /** Writes the extension's own state shape to every connected popup. */
    private suspend fun push() {
        val message = buildJsonObject { put("appState", appState()) }.toString().toByteArray()
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
        return runCatching {
            when (request["type"]?.jsonPrimitive?.contentOrNull) {
                "init" -> ok(id, parameters = initParameters())
                "getCurrentAppState" -> ok(id)
                "getCurrentFilteringState" -> ok(id, parameters = filteringState(parameters))
                "setProtectionStatus" -> {
                    setProtection(parameters["isEnabled"]?.jsonPrimitive?.booleanOrNull ?: false)
                    ok(id)
                }
                "setFilteringStatus" -> {
                    setFiltering(
                        url = parameters["url"]?.jsonPrimitive?.contentOrNull,
                        filtering = parameters["isEnabled"]?.jsonPrimitive?.booleanOrNull ?: false,
                        https = parameters["isHttpsEnabled"]?.jsonPrimitive?.booleanOrNull,
                    )
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
                    ok(id)
                }
                "openSettings" -> {
                    viewModel.onIntent(AdGuardIntent.SelectTab(AdGuardTab.SETTINGS))
                    ok(id)
                }
                "updateApp" -> {
                    viewModel.checkAppUpdateManually()
                    ok(id)
                }
                "pauseFiltering" -> {
                    pauseFiltering(
                        url = parameters["url"]?.jsonPrimitive?.contentOrNull,
                        seconds = parameters["timeout"]?.jsonPrimitive?.intOrNull ?: 30,
                    )
                    ok(id)
                }
                else -> error(id, "unknown request type")
            }
        }.getOrElse { error(id, it.message ?: "failed") }
    }

    private fun initParameters(): JsonObject = buildJsonObject {
        // The extension compares its own API version with this one and shows
        // "the app is out of date" when ours is lower. Version 1 is what its
        // published build speaks.
        put("apiVersion", API_VERSION)
        put("version", appVersion)
        put("platform", "Linux")
        put("isValidatedOnHost", true)
    }

    /** Required flags first: the extension throws when one of them is missing. */
    private fun appState(): JsonObject = buildJsonObject {
        val up = engine.isProxyRunning()
        put("isInstalled", true)
        put("isRunning", up)
        put("isProtectionEnabled", up && repository.settings.value.isProtectionActive)
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
        val excepted = host != null &&
            customRules().any { it.startsWith("@@") && ruleTargets(it, host) }
        return buildJsonObject {
            put("isFilteringEnabled", host != null && !excepted)
            put("isHttpsFilteringEnabled", repository.settings.value.isHttpsFilteringEnabled)
            put("canChangeFilteringStatus", true)
        }
    }

    private fun setProtection(on: Boolean) {
        val up = engine.isProxyRunning() && repository.settings.value.isProtectionActive
        if (up == on) return
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
