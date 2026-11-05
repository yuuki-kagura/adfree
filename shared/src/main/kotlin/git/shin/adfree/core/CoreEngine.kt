package git.shin.adfree.core


/**
 * Kotlin-side wrapper around the uniffi bindings (`adfree.kt`).
 *
 * All heavy lifting lives in native code: this class holds the TUN fd, the
 * already-`protect()`ed UDP sockets, and the few things that need an Android
 * context (logcat, the certificate's trip to Downloads).
 */
class CoreEngine(
    /** Where native warnings go; Android passes logcat, the desktop host stderr. */
    private val log: git.shin.adfree.platform.LogSink = git.shin.adfree.platform.LogSink { },
    /** Copies the CA where the platform installer can read it; null when the platform has none. */
    private val caExporter: git.shin.adfree.platform.CaExporter? = null,
    /** Looks the CA up in the platform trust store; null when the platform has none. */
    private val caTrustChecker: git.shin.adfree.platform.CaTrustChecker? = null,
) {

    val version: String
        get() = runCatching { git.shin.adfree.core.coreVersion() }.getOrDefault("unknown")

    fun isReady(): Boolean = runCatching { git.shin.adfree.core.coreStats() }.isSuccess

    // ------------------------------------------------------------------ life

    fun start(tunFd: Int) {
        git.shin.adfree.core.coreStart(tunFd)
    }

    fun stop() {
        git.shin.adfree.core.coreStop()
    }

    fun isRunning(): Boolean = runCatching { git.shin.adfree.core.coreIsRunning() }.getOrDefault(false)

    // ----------------------------------------------------------------- config    // ----------------------------------------------------------------- config

    fun setScreenOff(off: Boolean) = runCatching { git.shin.adfree.core.coreSetScreenOff(off) }

    /**
     * Pauses filtering without ending the tunnel. Transient: the persisted
     * protection record is untouched and a process restart filters again.
     */
    fun setProtectionPaused(paused: Boolean) {
        runCatching { git.shin.adfree.core.coreSetProtectionPaused(paused) }
    }

    fun isProtectionPaused(): Boolean =
        runCatching { git.shin.adfree.core.coreIsProtectionPaused() }.getOrDefault(false)

    // ------------------------------------------------------------ typed state

    /**
     * The whole persisted state, already merged with the built-in resolvers.
     * Kotlin hydrates its flows from this; defaults come from Rust only.
     */
    fun stateLoad(): git.shin.adfree.core.StateSnapshot =
        git.shin.adfree.core.coreStateLoad()

    fun saveProtection(value: git.shin.adfree.core.ProtectionState): Boolean =
        runCatching { git.shin.adfree.core.coreProtectionSave(value) }.getOrDefault(false)

    fun saveFirewall(rules: List<git.shin.adfree.core.AppFirewallRule>): Boolean =
        runCatching { git.shin.adfree.core.coreFirewallSave(rules) }.getOrDefault(false)

    fun saveDns(value: git.shin.adfree.core.DnsState): Boolean =
        runCatching { git.shin.adfree.core.coreDnsSave(value) }.getOrDefault(false)

    /** The active network's resolvers, used by the "system" fallback mode. */
    fun setSystemDns(servers: List<String>) {
        runCatching { git.shin.adfree.core.coreSetSystemDns(servers) }
    }

    fun saveFilters(value: git.shin.adfree.core.FilterState): Boolean =
        runCatching { git.shin.adfree.core.coreFiltersSave(value) }.getOrDefault(false)

    fun saveScripts(value: git.shin.adfree.core.ScriptState): Boolean =
        runCatching { git.shin.adfree.core.coreScriptsSave(value) }.getOrDefault(false)

    /** Rebuilds the engine config (modules, resolvers, firewall policy) from state. */
    fun applyConfig(privateDnsStrict: Boolean): git.shin.adfree.core.ConfigOutcome =
        runCatching { git.shin.adfree.core.coreApplyConfig(privateDnsStrict) }
            .getOrElse {
                git.shin.adfree.core.ConfigOutcome(
                    ok = false,
                    warning = git.shin.adfree.core.ConfigWarning.STORE_UNAVAILABLE,
                )
            }

    /** What Android should hand the tunnel as its DNS server. */
    fun resolverSnapshot(): git.shin.adfree.core.ResolverSnapshot =
        runCatching { git.shin.adfree.core.coreResolverSnapshot() }
            .getOrElse {
                git.shin.adfree.core.ResolverSnapshot(
                    tunnelDns = "94.140.14.14",
                    providerId = "",
                    warning = git.shin.adfree.core.ConfigWarning.STORE_UNAVAILABLE,
                )
            }

    /** Apps whose routing switch is off, for `addDisallowedApplication`. */
    fun excludedPackages(): List<String> =
        runCatching { git.shin.adfree.core.coreExcludedPackages() }.getOrDefault(emptyList())

    /** Protocol-aware resolver address validation, owned by the core. */
    fun validateDnsProvider(
        protocol: git.shin.adfree.core.DnsProtocol,
        address: String,
    ): git.shin.adfree.core.DnsValidation =
        runCatching { git.shin.adfree.core.coreValidateDnsProvider(protocol, address) }
            .getOrElse {
                git.shin.adfree.core.DnsValidation(
                    valid = false,
                    address = "",
                    port = 0u,
                    protocol = protocol,
                    error = git.shin.adfree.core.DnsError.INVALID_ADDRESS,
                )
            }

    /** Same validator the resolver uses, so a rewrite cannot be saved half-valid. */
    fun validateDnsRewrite(
        host: String,
        answer: String,
    ): git.shin.adfree.core.DnsRewriteValidation =
        runCatching { git.shin.adfree.core.coreValidateDnsRewrite(host, answer) }
            .getOrElse {
                git.shin.adfree.core.DnsRewriteValidation(
                    valid = false,
                    host = host,
                    answer = answer,
                    error = git.shin.adfree.core.DnsRewriteError.ANSWER_INVALID,
                )
            }

    /** Blocking resolver probe; call it off the UI thread. */
    fun probeDns(
        protocol: git.shin.adfree.core.DnsProtocol,
        address: String,
    ): git.shin.adfree.core.DnsProbeResult =
        runCatching { git.shin.adfree.core.coreProbeDns(protocol, address) }
            .getOrElse {
                git.shin.adfree.core.DnsProbeResult(
                    ok = false,
                    latencyMs = 0u,
                    error = git.shin.adfree.core.DnsProbeError.NETWORK,
                )
            }

    fun backupExport(): String =
        runCatching { git.shin.adfree.core.coreBackupExport() }.getOrDefault("")

    fun backupImport(json: String): git.shin.adfree.core.BackupOutcome =
        runCatching { git.shin.adfree.core.coreBackupImport(json) }
            .getOrElse {
                git.shin.adfree.core.BackupOutcome(
                    ok = false,
                    error = git.shin.adfree.core.BackupError.STORE_UNAVAILABLE,
                )
            }

    /** The default network, classified by the VPN service's network callback. */
    fun setNetworkType(kind: Int) {
        runCatching {
            git.shin.adfree.core.coreSetNetworkType(kind.coerceIn(0, 3).toByte().toUByte())
        }.onFailure { log.line("AdFreeCore: setNetworkType failed failed: $it") }
    }

    /** Whether the active cellular network is roaming, as the callback sees it. */
    fun setRoaming(roaming: Boolean) {
        runCatching { git.shin.adfree.core.coreSetRoaming(roaming) }
            .onFailure { log.line("AdFreeCore: setRoaming failed failed: $it") }
    }

    // --------------------------------------------------------------- filters

    /**
     * Push the filter list (file paths) to the core and compile in the
     * background. The UI never blocks: the old engine serves until the new one
     * is ready.
     */
    fun setListsAsync(lists: List<FilterListBinding>, userRules: List<String>) {
        runCatching { git.shin.adfree.core.coreSetListsAsync(lists, userRules) }
            .onFailure { log.line("AdFreeCore: setLists failed failed: $it") }
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
     * against. The platform builds the rows: only it can see every installed
     * app's uid.
     */
    fun setUidApps(rows: List<git.shin.adfree.core.UidApps>) {
        runCatching { git.shin.adfree.core.coreSetUidApps(rows) }
            .onFailure { log.line("AdFreeCore: setUidApps failed: $it") }
    }

    /**
     * Downloads one subscription into the store (`filters/<id>.txt`).
     *
     * The core owns the network call, the temp-file write, the rename and the
     * header parsing. The returned error code is what the UI localizes;
     * [DownloadResult.message] stays a diagnostic. Blocking, so call it off
     * the main thread.
     */
    fun downloadList(list: git.shin.adfree.model.FilterList): DownloadResult {
        val url = list.subscriptionUrl
            ?: return DownloadResult(false, git.shin.adfree.core.DownloadError.NO_URL)
        val outcome = runCatching { git.shin.adfree.core.coreFilterFetch(list.id, url) }
            .getOrElse {
                return DownloadResult(
                    false,
                    git.shin.adfree.core.DownloadError.NETWORK,
                    it.javaClass.simpleName,
                )
            }
        if (!outcome.ok) {
            return DownloadResult(false, outcome.error, outcome.message)
        }
        return DownloadResult(
            ok = true,
            error = git.shin.adfree.core.DownloadError.NONE,
            lineCount = outcome.lineCount,
            version = outcome.version,
            updatedText = outcome.updatedText,
            detectedFormat = outcome.detectedFormat,
            sizeBytes = outcome.sizeBytes,
            modifiedMs = outcome.modifiedMs,
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

    /**
     * Downloads a services table (domain, company) into `filters/services.tsv`,
     * which then replaces the table this build ships. The core refuses a body it
     * cannot binary search, so a bad subscription leaves the previous one in
     * place. Blocking: call it off the main thread.
     */
    fun downloadServicesTable(url: String): DownloadResult =
        servicesOutcome(runCatching { git.shin.adfree.core.coreServicesFetch(url) })

    /**
     * Stores a services table the platform has already read (a file the user
     * picked), through the same conversion and checks as
     * [downloadServicesTable]. Blocking: call it off the main thread.
     */
    fun saveServicesTable(text: String): DownloadResult =
        servicesOutcome(runCatching { git.shin.adfree.core.coreServicesSave(text) })

    /** The one shape both services entry points answer with. */
    private fun servicesOutcome(
        result: Result<git.shin.adfree.core.DownloadOutcome>,
    ): DownloadResult {
        val outcome = result.getOrElse {
            return DownloadResult(
                false,
                git.shin.adfree.core.DownloadError.NETWORK,
                it.javaClass.simpleName,
            )
        }
        if (!outcome.ok) return DownloadResult(false, outcome.error, outcome.message)
        return DownloadResult(
            ok = true,
            error = git.shin.adfree.core.DownloadError.NONE,
            sizeBytes = outcome.sizeBytes,
            modifiedMs = outcome.modifiedMs,
        )
    }

    /** The downloaded table, or null when the shipped one is in charge. */
    fun servicesState(): git.shin.adfree.core.AssetState? =
        runCatching { git.shin.adfree.core.coreServicesState() }.getOrNull()

    /** Backs the labels with the shipped table. False when nothing was downloaded. */
    fun servicesRemove(): Boolean =
        runCatching { git.shin.adfree.core.coreServicesRemove() }.getOrDefault(false)

    /** Downloads one userscript body into the store (`scripts/<id>.js`). */
    fun scriptFetch(id: String, url: String): git.shin.adfree.core.DownloadOutcome =
        runCatching { git.shin.adfree.core.coreScriptFetch(id, url) }
            .getOrElse {
                git.shin.adfree.core.DownloadOutcome(
                    ok = false,
                    message = it.javaClass.simpleName,
                    lineCount = 0,
                    version = null,
                    updatedText = null,
                    detectedFormat = null,
                    sizeBytes = 0,
                    modifiedMs = 0,
                    error = git.shin.adfree.core.DownloadError.NETWORK,
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
            .onFailure { log.line("AdFreeCore: setSocketProtector failed failed: $it") }
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
     * Hands the certificate PEM to the platform exporter, which puts it where
     * the platform's install picker can reach it. Returns the exported file
     * name, or null when the platform cannot export.
     */
    fun exportCaCertificate(): String? {
        val pem = runCatching { ensureCa() }.getOrNull().orEmpty()
        if (pem.isBlank()) return null
        return runCatching { caExporter?.export(pem) }.getOrNull()
    }

    /**
     * True when our CA sits in the platform's trust store. The store itself is
     * a platform concept, so the check is delegated; platforms without one
     * honestly answer false.
     */
    fun isCaTrusted(): Boolean {
        val pem = runCatching { git.shin.adfree.core.coreCaPem() }.getOrNull().orEmpty()
        if (pem.isBlank()) return false
        return runCatching { caTrustChecker?.isTrusted(pem) == true }.getOrDefault(false)
    }

    /** Current MITM status from the core. */
    fun mitmStatus(): git.shin.adfree.core.MitmStatus? =
        runCatching { git.shin.adfree.core.coreMitmStatus() }.getOrNull()

    /**
     * Root-mode state: whether su/root exists and whether the CA already sits
     * in the system store. Never elevates, so it is safe to call on resume.
     */
    fun rootTrustStatus(): git.shin.adfree.core.RootTrustBinding? =
        runCatching { git.shin.adfree.core.coreRootTrustStatus() }.getOrNull()

    /**
     * Installs the CA into the OS system trust store. Blocking: on Android the
     * first call may wait on the su consent dialog, so call it off the main
     * thread.
     */
    fun installRootCa(): git.shin.adfree.core.RootTrustBinding? =
        runCatching { git.shin.adfree.core.coreInstallRootCa() }.getOrNull()

    /** Removes the CA from the OS system trust store. Blocking, like install. */
    fun removeRootCa(): git.shin.adfree.core.RootTrustBinding? =
        runCatching { git.shin.adfree.core.coreRemoveRootCa() }.getOrNull()

    /** Replaces the user script list plus the master switch. */
    fun setScripts(scripts: List<ScriptBinding>, enabled: Boolean) {
        runCatching { git.shin.adfree.core.coreSetScripts(scripts, enabled) }
            .onFailure { log.line("AdFreeCore: setScripts failed failed: $it") }
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
                quicBlocked = 0,
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

    /** One page of rows older than [beforeId], newest first (cursor paging). */
    fun logPageBefore(beforeId: Long, limit: Int): List<LogEvent> =
        runCatching { git.shin.adfree.core.coreLogPageBefore(beforeId, limit.toUInt()) }
            .getOrDefault(emptyList())

    /** Whole-log blocked/allowed totals, independent of the loaded window. */
    fun logStatusCounts(): git.shin.adfree.core.LogStatusCounts =
        runCatching { git.shin.adfree.core.coreLogStatusCounts() }
            .getOrDefault(git.shin.adfree.core.LogStatusCounts(0L, 0L))

    /** Blocked counts, requests and bytes saved per package since [sinceMs]. */
    fun appUsageSince(sinceMs: Long, transport: Int = -1): List<git.shin.adfree.core.AppUsage> =
        runCatching { git.shin.adfree.core.coreAppUsageSinceTransport(sinceMs, transport) }
            .getOrDefault(emptyList())

    /**
     * Blocked counts and requests per domain since [sinceMs], each already
     * labelled by the core's services table. Empty when the store is not open;
     * a row whose company is unknown comes back with an empty label.
     */
    fun domainUsageSince(
        sinceMs: Long,
        transport: Int = -1,
    ): List<git.shin.adfree.core.DomainUsage> =
        runCatching { git.shin.adfree.core.coreDomainUsageSince(sinceMs, transport) }
            .getOrDefault(emptyList())

    /** Whole-window totals for the Statistics header. */
    fun logWindowTotalsSince(
        sinceMs: Long,
        transport: Int = -1,
    ): git.shin.adfree.core.WindowTotals =
        runCatching { git.shin.adfree.core.coreLogWindowTotalsSince(sinceMs, transport) }
            .getOrDefault(git.shin.adfree.core.WindowTotals(0uL, 0uL, 0uL, 0uL, 0uL, 0uL))

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
            log.line(line)
        }
    }

    companion object {
        private var pendingStart = true

        /** Must match `NETWORK_*` in `rust/src/engine.rs`. */
        const val NETWORK_UNKNOWN = 0
        const val NETWORK_WIFI = 1
        const val NETWORK_CELLULAR = 2
        const val NETWORK_OTHER = 3

        @Volatile
        var screenOffFlag = false
    }
}

/** Result of downloading a subscription or userscript. */
data class DownloadResult(
    val ok: Boolean,
    /** Code the UI localizes; [DownloadError.NONE] on success. */
    val error: git.shin.adfree.core.DownloadError,
    /** Diagnostic detail, never shown as-is in a localized UI. */
    val message: String = "",
    val lineCount: Long = 0,
    val version: String? = null,
    val updatedText: String? = null,
    val detectedFormat: String? = null,
    /** Bytes on disk after the download; 0 for a failure. */
    val sizeBytes: Long = 0,
    /** Modification time of the written body, for the auto-update interval. */
    val modifiedMs: Long = 0,
)
