package git.shin.adfree.data

import android.content.Context
import android.util.Log
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import git.shin.adfree.R
import git.shin.adfree.core.AssetState
import git.shin.adfree.core.CoreEngine
import git.shin.adfree.core.DnsProbeResult
import git.shin.adfree.core.DnsState
import git.shin.adfree.core.DownloadResult
import git.shin.adfree.core.FilterChoice
import git.shin.adfree.core.FilterListBinding
import git.shin.adfree.core.FilterState
import git.shin.adfree.core.ScriptBinding
import git.shin.adfree.core.ScriptRecord
import git.shin.adfree.core.ScriptState
import git.shin.adfree.core.StatsSnapshot
import git.shin.adfree.model.AppCategory
import git.shin.adfree.model.AppFirewallRule
import git.shin.adfree.model.DnsBlockMode
import git.shin.adfree.model.DnsProvider
import git.shin.adfree.model.DnsRewriteRule
import git.shin.adfree.model.FilterList
import git.shin.adfree.model.FilterStatus
import git.shin.adfree.model.filterUpdateDue
import git.shin.adfree.model.filterUrlError
import git.shin.adfree.model.normalizeHttpsHost
import git.shin.adfree.model.probeAddress
import git.shin.adfree.model.scriptNameFromFile
import git.shin.adfree.model.UserScriptInfo
import git.shin.adfree.model.UserScriptMetadata
import git.shin.adfree.model.parseUserScriptMetadata
import git.shin.adfree.model.parseUserRulesText
import git.shin.adfree.model.UserScriptStoreItem
import git.shin.adfree.model.UserScriptStoreSort
import git.shin.adfree.model.UserScriptStoreState
import git.shin.adfree.model.NetworkRequestLog
import git.shin.adfree.model.ProtectionStats
import git.shin.adfree.model.ProtectionSettings
import git.shin.adfree.model.ProxySettings
import git.shin.adfree.model.ProtocolType
import git.shin.adfree.ui.CoreText
import git.shin.adfree.ui.UiText
import git.shin.adfree.work.FilterUpdateScheduler
import java.io.IOException
import java.net.URLEncoder
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.flow.updateAndGet
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONArray
import org.json.JSONObject

/** Greasy Fork's public JSON search endpoint; blank query returns the top list. */
private const val GREASY_FORK_API = "https://api.greasyfork.org/en/scripts.json"

/** Keep the sheet light: 50 results is already a lot of rows to scan. */
private const val GREASY_FORK_LIMIT = 50

/** Upper bound on waiting for a filter compile before reading its errors. */
private const val FILTER_BUILD_WATCH_MS = 30_000L

/** Do not re-scan stale lists more than once per half hour while foregrounded. */
private const val AUTO_UPDATE_RESUME_MIN_INTERVAL_MS = 30 * 60 * 1000L

/** A backup is settings plus rules, not a media file; keep the read bounded. */
private const val MAX_BACKUP_BYTES = 4 * 1024 * 1024

/**
 * Single source of truth.
 *
 * Every number here comes from the Rust core ([CoreEngine]) — nothing is
 * hardcoded any more. This class' only jobs are: turn native data into
 * `StateFlow` for Compose, hold settings, and coordinate filter updates.
 */
class AdGuardRepository(
    private val context: Context,
    private val engine: CoreEngine,
    /**
     * Rebuilds the engine from the freshly persisted state. Injected so the
     * repository does not have to know about Private DNS (the DI container
     * owns that Android setting).
     */
    private val onConfigApplied: () -> Unit = {},
) {
    private val scope = CoroutineScope(Dispatchers.Default)

    private val _settings = MutableStateFlow(ProtectionSettings())
    val settings: StateFlow<ProtectionSettings> = _settings.asStateFlow()

    private val _stats = MutableStateFlow(ProtectionStats())
    val stats: StateFlow<ProtectionStats> = _stats.asStateFlow()

    private val _logs = MutableStateFlow<List<NetworkRequestLog>>(emptyList())
    val logs: StateFlow<List<NetworkRequestLog>> = _logs.asStateFlow()

    private val _logTotal = MutableStateFlow(0L)
    val logTotal: StateFlow<Long> = _logTotal.asStateFlow()

    /** How many of the newest rows the UI mirrors; grows one page per tap. */
    private var logWindow = LOG_PAGE_SIZE
    private var lastLogCount = -1L

    /**
     * False while the log screen is scrolled into history: fresh rows would
     * keep pushing the rows under the user's finger, so the window freezes
     * until they scroll back to the top.
     */
    private var logTailing = true

    private val _filterLists = MutableStateFlow<List<FilterList>>(emptyList())
    val filterLists: StateFlow<List<FilterList>> = _filterLists.asStateFlow()

    private val _appFirewallRules = MutableStateFlow<List<AppFirewallRule>>(emptyList())
    val appFirewallRules: StateFlow<List<AppFirewallRule>> = _appFirewallRules.asStateFlow()

    private val _dnsProviders = MutableStateFlow<List<DnsProvider>>(emptyList())
    val dnsProviders: StateFlow<List<DnsProvider>> = _dnsProviders.asStateFlow()

    private val _dnsRewrites = MutableStateFlow<List<DnsRewriteRule>>(emptyList())
    val dnsRewrites: StateFlow<List<DnsRewriteRule>> = _dnsRewrites.asStateFlow()

    private val _loadingMessage = MutableStateFlow<UiText?>(null)
    val loadingMessage: StateFlow<UiText?> = _loadingMessage.asStateFlow()

    /**
     * Shows a one-shot result message and clears it a few seconds later, so
     * the header cannot stay stuck on a progress label. The equality check
     * keeps a newer message from being cleared by an older timer.
     */
    private fun showTransientStatus(message: UiText?) {
        _loadingMessage.value = message
        if (message == null) return
        scope.launch {
            delay(4_000)
            if (_loadingMessage.value == message) _loadingMessage.value = null
        }
    }

    /** Localized wording for a download outcome; diagnostics stay behind the code. */
    private fun downloadMessage(result: DownloadResult, name: String): UiText =
        if (result.ok) {
            UiText.Formatted(R.string.filter_downloaded_name, name, result.lineCount)
        } else {
            CoreText.downloadError(result.error) ?: UiText.Raw(result.message)
        }

    private val _userscripts = MutableStateFlow<List<UserScriptInfo>>(emptyList())
    val userscripts: StateFlow<List<UserScriptInfo>> = _userscripts.asStateFlow()

    private val _scriptsMasterEnabled = MutableStateFlow(true)
    val scriptsMasterEnabled: StateFlow<Boolean> = _scriptsMasterEnabled.asStateFlow()

    private val _scriptStore = MutableStateFlow(UserScriptStoreState())
    val scriptStore: StateFlow<UserScriptStoreState> = _scriptStore.asStateFlow()
    private var scriptStoreJob: Job? = null

    /** Coalesces the post-build error checks started by [pushListsToEngine]. */
    private var filterBuildJob: Job? = null

    /** Guards the launch/resume subscription refresh against a double start. */
    private val autoUpdateRunning = AtomicBoolean(false)

    /** Last time a stale-list scan ran; throttles ON_RESUME checks. */
    @Volatile
    private var lastAutoUpdateCheckMs = 0L

    private val scriptStoreClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .build()
    }

    init {
        startStatsPoller()
    }

    // -------------------------------------------------------------- hydration

    /**
     * Fills every flow from the Rust-owned state, then starts the asynchronous
     * file refreshes. Called once at startup and again after a restore; Rust
     * owns the defaults, so nothing here invents one.
     */
    fun hydrateState() {
        val snapshot = engine.stateLoad()
        _dnsProviders.value = snapshot.dns.providers.map { it.toModel() }
        _dnsRewrites.value = snapshot.dns.rewrites.map { it.toModel() }
        _scriptsMasterEnabled.value = snapshot.scripts.master
        // Enumerating installed apps is binder work; keep it off the caller
        // (the Application's main thread) while the rest hydrates at once.
        val firewall = snapshot.firewall
        scope.launch {
            _appFirewallRules.value = withContext(Dispatchers.IO) { readInstalledApps(firewall) }
        }
        var settings = snapshot.protection.toModel()
        if (settings.isHttpsFilteringEnabled && !engine.isCaTrusted()) {
            // Terminating TLS with a certificate the device no longer trusts
            // would break every page it touches. Persist the correction so the
            // engine config and the UI agree from the first frame.
            settings = settings.copy(isHttpsFilteringEnabled = false)
            engine.saveProtection(settings.toCoreState())
        }
        _settings.value = settings
        // WorkManager keeps the periodic refresh across reboots and updates.
        // Syncing at startup also schedules it for users upgrading from a
        // build that only checked while the app was open.
        FilterUpdateScheduler.sync(context, settings.filterAutoUpdateHours)
        loadFilterState(snapshot.filters)
        loadScriptsState(snapshot.scripts)
    }

    /**
     * True when protection was on the last time the app ran: it is then
     * switched back on at launch instead of waiting for the user. A first run
     * has nothing saved and stays off.
     */
    fun protectionWasOn(): Boolean = _settings.value.isProtectionActive

    // ------------------------------------------------------ polling the engine

    /**
     * One tick every 500ms with the screen on, 2s when off. This is the
     * app's entire UI cost: two atomic reads plus a COUNT(*) on the log.
     */
    private fun startStatsPoller() {
        scope.launch {
            while (true) {
                val snapshot = engine.stats()
                _stats.value = snapshot.toUiStats(engine.isBuilding())
                // Native warnings are buffered natively so the packet threads
                // never do I/O; drain them here or they are lost.
                engine.flushNativeLogLines()
                refreshLogIfChanged()
                delay(if (engine.isScreenOff()) 2_000 else 500)
            }
        }
    }

    /**
     * Mirrors the newest slice of the database log. COUNT(*) is cheap, so a
     * tick only pays for rows once the writer actually persisted something.
     * While the user has paged back into history the window stays put, so the
     * rows under their finger do not shift every time traffic arrives.
     */
    private fun refreshLogIfChanged() {
        val total = engine.logCount()
        if (total == lastLogCount) return
        lastLogCount = total
        _logTotal.value = total
        if (!logTailing) return
        reloadLogWindow()
    }

    /** The log screen reports its scroll state here; see [logTailing]. */
    fun setLogTailing(tailing: Boolean) {
        if (tailing == logTailing) return
        logTailing = tailing
        if (tailing) reloadLogWindow()
    }

    private fun reloadLogWindow() {
        val rows = ArrayList<NetworkRequestLog>(logWindow)
        var offset = 0
        while (offset < logWindow) {
            val page = engine.logPage(offset, LOG_PAGE_SIZE)
            rows += page.map(NetworkRequestLog::from)
            if (page.size < LOG_PAGE_SIZE) break
            offset += page.size
        }
        _logs.value = rows
    }

    /** Shows one more page of older rows under the ones already on screen. */
    fun loadMoreLogs() {
        if (_logs.value.size >= _logTotal.value || logWindow >= MAX_LOG_ROWS) return
        logWindow += LOG_PAGE_SIZE
        reloadLogWindow()
    }

    private fun StatsSnapshot.toUiStats(building: Boolean): ProtectionStats {
        val blocked = dnsBlocked + tcpReset
        return ProtectionStats(
            adsBlocked = dnsBlocked,
            trackersBlocked = (quicDropped + udpDropped + tcpReset).toLong(),
            dataSavedBytes = bytesSaved,
            totalRequestsIntercepted = packetsTotal,
            activeRulesCount = activeRules.toInt(),
            engineLatencyNs = decisionNsEwma,
            engineLatencyPeakNs = decisionNsMax,
            memoryUsageKb = rssKb,
            cpuUsagePermille = cpuUsagePermille(),
            packetsTotal = packetsTotal,
            dnsQueries = dnsQueries,
            cacheHitRatio = cacheHitRatio(),
            isFilterBuilding = building,
            conntrackEntries = conntrackEntries.toInt(),
            uptimeMs = uptimeMs,
            filterBuildMs = filterBuildMs,
        )
    }

    private fun StatsSnapshot.cacheHitRatio(): Float {
        val total = cacheHits + (packetsDns - cacheHits).coerceAtLeast(0)
        if (total <= 0) return 0f
        return (cacheHits.toFloat() / total.toFloat()).coerceIn(0f, 1f) * 100f
    }

    /** Percentage of CPU the engine has actually consumed in the recent window. */
    private fun cpuUsagePermille(): Int {
        val snap = engine.stats()
        if (snap.busyNs == 0L || snap.uptimeMs == 0L) return 0
        val perMille = (snap.busyNs.toDouble() * 1000.0) / (snap.uptimeMs.toDouble() * 1_000_000.0)
        return perMille.coerceIn(0.0, 1000.0).toInt()
    }

    // ------------------------------------------------------------- settings

    /**
     * Single write path: the flow moves, the whole typed record lands in Rust,
     * and the engine is reconfigured from it. Kotlin keeps no copy of its own.
     */
    private fun updateSettings(transform: (ProtectionSettings) -> ProtectionSettings): ProtectionSettings {
        val next = _settings.updateAndGet(transform)
        engine.saveProtection(next.toCoreState())
        onConfigApplied()
        return next
    }

    fun toggleProtection(enabled: Boolean) {
        updateSettings { it.copy(isProtectionActive = enabled) }
        if (enabled) engine.markWantsStart() else engine.markWantsStop()
    }

    /** Restores the tunnel after a reboot when protection was on. */
    fun toggleAutoStart(enabled: Boolean) =
        updateSettings { it.copy(autoStart = enabled) }

    /** In-app language; the UI applies it through AppCompat's per-app locales. */
    fun setAppLanguage(language: git.shin.adfree.model.AppLanguage) =
        updateSettings { it.copy(appLanguage = language) }

    fun setThemeMode(mode: git.shin.adfree.model.ThemeMode) =
        updateSettings { it.copy(themeMode = mode) }

    fun toggleAdBlocking(enabled: Boolean) =
        updateSettings { it.copy(isAdBlockingEnabled = enabled) }

    fun toggleTrackingProtection(enabled: Boolean) =
        updateSettings { it.copy(isTrackingProtectionEnabled = enabled) }

    fun toggleDnsProtection(enabled: Boolean) =
        updateSettings { it.copy(isDnsProtectionEnabled = enabled) }

    fun toggleSmartFiltering(enabled: Boolean) =
        updateSettings { it.copy(isSmartFilteringEnabled = enabled) }

    fun toggleHttpsFiltering(enabled: Boolean) =
        updateSettings { it.copy(isHttpsFilteringEnabled = enabled) }

    fun toggleFullEch(enabled: Boolean) =
        updateSettings { it.copy(isFullEchEnabled = enabled) }

    /** Adds a host pattern to the HTTPS allowlist (sites left undecrypted). */
    fun addHttpsSkipHost(raw: String) {
        val host = normalizeHttpsHost(raw) ?: return
        updateSettings { settings ->
            if (settings.httpsSkipHosts.any { it.equals(host, ignoreCase = true) }) settings
            else settings.copy(httpsSkipHosts = settings.httpsSkipHosts + host)
        }
    }

    fun removeHttpsSkipHost(host: String) {
        updateSettings { it.copy(httpsSkipHosts = it.httpsSkipHosts - host) }
    }

    /** Adds a host to the list used when [setHttpsOnlyMode] is on. */
    fun addHttpsOnlyHost(raw: String) {
        val host = normalizeHttpsHost(raw) ?: return
        updateSettings { settings ->
            if (settings.httpsOnlyHosts.any { it.equals(host, ignoreCase = true) }) settings
            else settings.copy(httpsOnlyHosts = settings.httpsOnlyHosts + host)
        }
    }

    fun removeHttpsOnlyHost(host: String) {
        updateSettings { it.copy(httpsOnlyHosts = it.httpsOnlyHosts - host) }
    }

    /** Inverts HTTPS filtering: decrypt only the hosts in the blocklist. */
    fun setHttpsOnlyMode(enabled: Boolean) {
        updateSettings { it.copy(httpsOnlyMode = enabled) }
    }

    /** Routing mode: outbound SOCKS5 for new TCP flows, or direct. */
    fun updateProxy(proxy: ProxySettings) {
        updateSettings { it.copy(proxy = proxy) }
    }

    fun toggleFirewall(enabled: Boolean) =
        updateSettings { it.copy(isFirewallEnabled = enabled) }

    fun toggleEcoBatteryMode(enabled: Boolean) =
        updateSettings { it.copy(isEcoBatteryModeEnabled = enabled) }

    fun toggleStealthMode(enabled: Boolean) =
        updateSettings { it.copy(isStealthModeEnabled = enabled) }

    fun updateStealthSetting(
        stripUtm: Boolean? = null,
        blockWebRtc: Boolean? = null,
        disguiseUa: Boolean? = null,
        blockCookies: Boolean? = null,
    ) = updateSettings { cur ->
        cur.copy(
            stripUtmTracking = stripUtm ?: cur.stripUtmTracking,
            blockWebRtcLeaks = blockWebRtc ?: cur.blockWebRtcLeaks,
            disguiseUserAgent = disguiseUa ?: cur.disguiseUserAgent,
            blockThirdPartyCookies = blockCookies ?: cur.blockThirdPartyCookies,
        )
    }

    fun toggleBlockQuic(enabled: Boolean) = updateSettings { it.copy(blockQuic = enabled) }

    fun toggleBlockDoh(enabled: Boolean) = updateSettings { it.copy(blockDoh = enabled) }

    /**
     * DoT has its own switch because the system Private DNS mode decides
     * whether the core may drop port 853 at all; the core applies that
     * carve-out per configuration, not by rewriting the stored preference.
     */
    fun toggleBlockDot(enabled: Boolean) = updateSettings { it.copy(blockDot = enabled) }

    /** Forces the safe variants on the major search engines. */
    fun toggleSafeSearch(enabled: Boolean) =
        updateSettings { it.copy(safeSearch = enabled) }

    /** Refresh interval for subscriptions, in hours; 0 turns it off. */
    fun setFilterAutoUpdate(hours: Int) {
        val clamped = hours.coerceIn(0, 168)
        updateSettings { it.copy(filterAutoUpdateHours = clamped) }
        FilterUpdateScheduler.sync(context, clamped)
        showTransientStatus(
            if (clamped == 0) UiText.Resource(R.string.filter_auto_update_off)
            else UiText.Formatted(R.string.filter_auto_update_every_hours, clamped),
        )
    }

    fun toggleLogAllowed(enabled: Boolean) =
        updateSettings { it.copy(logAllowedRequests = enabled) }

    fun setBlockMode(mode: DnsBlockMode) = updateSettings { it.copy(blockMode = mode) }

    fun selectDnsProvider(id: String) {
        if (_dnsProviders.value.none { it.id == id }) return
        updateSettings { it.copy(selectedDnsProviderId = id) }
    }

    /** Adds/selects a resolver and returns the line the Settings snackbar shows. */
    fun addCustomDnsProvider(
        name: String,
        address: String,
        type: ProtocolType = ProtocolType.DNS_UDP,
    ): UiText {
        val trimmed = address.trim()
        if (trimmed.isEmpty()) return UiText.Resource(R.string.dns_address_empty)
        // The core owns the rules for every transport, so the form and the
        // forwarder cannot disagree about what a DoT or DoH address is.
        val protocol = type.toDnsProtocol()
        val validation = engine.validateDnsProvider(protocol, trimmed)
        if (!validation.valid) {
            return UiText.Resource(providerError(type, validation.error))
        }
        val host = validation.address
        val port = validation.port.toInt()
        val existing = _dnsProviders.value.firstOrNull {
            it.address == host && it.port == port && it.type == type
        }
        if (existing != null) {
            selectDnsProvider(existing.id)
            return UiText.Formatted(R.string.dns_provider_selected, existing.name)
        }
        val provider = DnsProvider(
            id = "custom_" + System.currentTimeMillis(),
            name = name.trim().ifBlank { host },
            address = host,
            type = type,
            description = context.getString(R.string.dns_custom_description),
            isCustom = true,
            port = port,
        )
        _dnsProviders.update { it + provider }
        persistDnsState()
        updateSettings { it.copy(selectedDnsProviderId = provider.id) }
        return UiText.Formatted(R.string.dns_custom_added, provider.name)
    }

    private fun providerError(type: ProtocolType, error: git.shin.adfree.core.DnsError): Int =
        when (error) {
            git.shin.adfree.core.DnsError.EMPTY -> R.string.dns_address_empty
            git.shin.adfree.core.DnsError.INVALID_PORT -> R.string.dns_invalid_port
            git.shin.adfree.core.DnsError.UNSUPPORTED_SCHEME -> when (type) {
                ProtocolType.DNS_UDP -> R.string.dns_udp_ip_only
                ProtocolType.DNS_DOT -> R.string.dns_dot_format
                else -> R.string.dns_doh_format
            }
            git.shin.adfree.core.DnsError.IP_V6_UDP_UNSUPPORTED -> R.string.dns_udp_ipv4_only
            else -> when (type) {
                ProtocolType.DNS_UDP -> R.string.dns_udp_ip_only
                ProtocolType.DNS_DOT -> R.string.dns_dot_format
                else -> R.string.dns_doh_format
            }
        }

    /** Sends one probe query to a saved resolver; `null` when it disappeared. */
    suspend fun probeDnsProvider(id: String): DnsProbeResult? = withContext(Dispatchers.IO) {
        val provider = _dnsProviders.value.firstOrNull { it.id == id }
            ?: return@withContext null
        engine.probeDns(provider.type.toDnsProtocol(), provider.probeAddress())
    }

    /** Adds or updates a rewrite and returns the line the snackbar shows. */
    fun addDnsRewrite(host: String, answer: String): UiText {
        val checked = engine.validateDnsRewrite(host, answer)
        if (!checked.valid) {
            return UiText.Resource(
                when (checked.error) {
                    git.shin.adfree.core.DnsRewriteError.HOST_EMPTY ->
                        R.string.dns_rewrite_error_host_empty
                    git.shin.adfree.core.DnsRewriteError.HOST_INVALID ->
                        R.string.dns_rewrite_error_host_invalid
                    git.shin.adfree.core.DnsRewriteError.ANSWER_EMPTY ->
                        R.string.dns_rewrite_error_answer_empty
                    git.shin.adfree.core.DnsRewriteError.ANSWER_INVALID ->
                        R.string.dns_rewrite_error_answer_invalid
                    else -> R.string.dns_rewrite_error_host_invalid
                },
            )
        }
        val rule = DnsRewriteRule(host = checked.host, answer = checked.answer)
        val updated = _dnsRewrites.value.any { it.host.equals(rule.host, ignoreCase = true) }
        _dnsRewrites.update { current ->
            current.filterNot { it.host.equals(rule.host, ignoreCase = true) } + rule
        }
        persistDnsState()
        onConfigApplied()
        return UiText.Formatted(
            if (updated) R.string.dns_rewrite_updated else R.string.dns_rewrite_added,
            rule.host,
        )
    }

    fun removeDnsRewrite(host: String) {
        if (_dnsRewrites.value.none { it.host.equals(host, ignoreCase = true) }) return
        _dnsRewrites.update { current ->
            current.filterNot { it.host.equals(host, ignoreCase = true) }
        }
        persistDnsState()
        onConfigApplied()
    }

    /** Writes the resolver list (built-ins are re-merged by Rust on load). */
    private fun persistDnsState() {
        engine.saveDns(
            DnsState(
                providers = _dnsProviders.value.map { it.toCoreRecord() },
                rewrites = _dnsRewrites.value.map { it.toCore() },
            )
        )
    }

    // ----------------------------------------------------------- filter lists

    /**
     * Seeds the catalogue, merges the user's saved choices and downloads what
     * is enabled but missing.
     *
     * Only enabled lists cost a download: a fresh install fetches the four
     * defaults and nothing else.
     */
    fun loadFilterState(saved: FilterState = engine.stateLoad().filters) {
        scope.launch {
            val savedIds = saved.enabledCatalogIds.toSet()
            val lists = mutableListOf<FilterList>()
            for (entry in FilterCatalog.filters) {
                // Never chosen: the catalogue defaults decide. Once the user
                // saved a choice, the saved set wins even when it is empty.
                val enabled = if (saved.catalogConfigured) savedIds.contains(entry.id) else entry.defaultEnabled
                lists += FilterList(
                    id = entry.listId ?: "cat_${entry.id}",
                    name = entry.name,
                    description = "",
                    nameRes = entry.nameRes,
                    descriptionRes = entry.descriptionRes,
                    ruleCount = 0,
                    isEnabled = enabled,
                    category = entry.group.id,
                    // Only a downloaded list has a real version: seeding it with
                    // the syntax made the detail sheet print "Phiên bản
                    // standard" before the first byte had arrived.
                    version = "",
                    isOnlineSubscription = true,
                    subscriptionUrl = entry.url,
                    lastUpdatedText = context.getString(R.string.filter_not_loaded),
                    groupId = entry.group.id,
                    format = entry.format,
                    catalogId = entry.id,
                    defaultEnabled = entry.defaultEnabled,
                    homepage = entry.homepage,
                    // The catalogue is the pre-approved set: trusted (KB
                    // §Trusted filters).
                    trusted = true,
                )
            }
            for (stored in saved.custom) {
                lists += FilterList(
                    id = stored.id,
                    name = stored.name,
                    description = context.getString(R.string.filter_custom_description),
                    ruleCount = 0,
                    isEnabled = stored.enabled,
                    category = "custom",
                    version = "",
                    isOnlineSubscription = stored.url.isNotBlank(),
                    subscriptionUrl = stored.url.ifBlank { null },
                    lastUpdatedText = context.getString(R.string.filter_not_loaded),
                    groupId = "custom",
                    format = stored.format.ifBlank { "standard" },
                    homepage = stored.homepage.ifBlank { null },
                    isUserAdded = true,
                    trusted = stored.trusted,
                )
            }
            val rules = if (saved.userRulesConfigured) saved.userRules else starterRules
            lists += FilterList(
                id = BUILTIN_CUSTOM,
                name = context.getString(R.string.filter_user_rules_name),
                description = context.getString(R.string.filter_user_rules_description),
                ruleCount = rules.size,
                isEnabled = rules.isNotEmpty(),
                category = "user",
                version = "",
                isCustom = true,
                customRules = rules,
            )

            _filterLists.value = lists
            refreshFilesAndDownload(lists.filterNot { it.isCustom })
            pushListsToEngine()
            saveFilterChoices()
            _loadingMessage.value = null
            // After the first compile so the engine is usable while the
            // refresh runs; only lists whose body is already on disk and
            // older than the configured interval are touched.
            updateStaleLists(reportToUi = true)
        }
    }

    /**
     * Re-checks stale subscriptions when the activity comes back to the
     * foreground (for example after a long session or a day in Recents).
     *
     * The worker now handles refreshes while the app is closed; this stays as
     * the catch-up path for a device where WorkManager has not run yet. The
     * 30-minute throttle keeps a failed download from retrying on every tab
     * switch or dialog dismissal.
     */
    fun autoUpdateIfStale() {
        val now = System.currentTimeMillis()
        if (now - lastAutoUpdateCheckMs < AUTO_UPDATE_RESUME_MIN_INTERVAL_MS) return
        lastAutoUpdateCheckMs = now
        scope.launch { updateStaleLists(reportToUi = true) }
    }

    /**
     * Entry point for [FilterUpdateWorker]: no progress line and no snackbar,
     * because there may be no Activity to show them. Returns how many list
     * bodies were downloaded successfully.
     */
    suspend fun backgroundUpdateStaleLists(): Int = updateStaleLists(reportToUi = false)

    /**
     * Refreshes enabled subscriptions older than `filterAutoUpdateHours`.
     *
     * A second caller arriving while a refresh runs gets 0 instead of starting
     * an overlapping download of the same lists. A failed download is not
     * retried here; the next scheduled or foreground check picks it up.
     */
    private suspend fun updateStaleLists(reportToUi: Boolean): Int {
        lastAutoUpdateCheckMs = System.currentTimeMillis()
        if (!autoUpdateRunning.compareAndSet(false, true)) return 0
        try {
            val hours = _settings.value.filterAutoUpdateHours
            if (hours <= 0) return 0
            val now = System.currentTimeMillis()
            val stale = _filterLists.value.filter {
                it.isEnabled && !it.isCustom && !it.subscriptionUrl.isNullOrBlank() &&
                    filterUpdateDue(it.lastUpdatedMs, now, hours)
            }
            if (stale.isEmpty()) return 0

            if (reportToUi) {
                _loadingMessage.value =
                    UiText.Formatted(R.string.filter_auto_update_progress, stale.size)
            }
            var updated = 0
            for (list in stale) {
                val result = withContext(Dispatchers.IO) { engine.downloadList(list) }
                if (result.ok) {
                    applyDownloadResult(list.id, result)
                    updated++
                } else {
                    applyFailure(list.id, downloadMessage(result, list.name))
                }
            }
            if (updated > 0) pushListsToEngine()
            if (reportToUi) {
                showTransientStatus(
                    if (updated == stale.size) {
                        UiText.Formatted(R.string.filter_auto_update_done, stale.size)
                    } else {
                        UiText.Formatted(
                            R.string.filter_auto_update_partial,
                            updated,
                            stale.size,
                        )
                    },
                )
            }
            return updated
        } finally {
            autoUpdateRunning.set(false)
            if (reportToUi) _loadingMessage.value = null
        }
    }

    /** Recounts files already on disk and downloads the enabled lists without one. */
    private suspend fun refreshFilesAndDownload(lists: List<FilterList>) {
        for (list in lists) {
            val state = withContext(Dispatchers.IO) { engine.filterState(list.id) }
            if (state != null) {
                applyFileStats(list.id, state)
                continue
            }
            if (!list.isEnabled || list.subscriptionUrl.isNullOrBlank()) continue
            _loadingMessage.value = UiText.Formatted(R.string.filter_downloading, list.name)
            val result = withContext(Dispatchers.IO) { engine.downloadList(list) }
            if (result.ok) {
                applyDownloadResult(list.id, result)
            } else {
                // Startup download failures used to vanish: the list stayed
                // "on" with zero rules and no trace of why. Persist the
                // reason on the list (row + detail sheet show it) and echo
                // the usual transient toast.
                val message = downloadMessage(result, list.name)
                applyFailure(list.id, message)
                showTransientStatus(message)
            }
        }
    }

    /** Refreshes count/date/version of one list from its stored body (no network). */
    private fun applyFileStats(listId: String, state: git.shin.adfree.core.AssetState) {
        _filterLists.update { current ->
            current.map {
                if (it.id == listId) {
                    it.copy(
                        ruleCount = state.lineCount.toInt(),
                        lastUpdatedText = state.updatedText ?: engine.dateText(state.modifiedMs),
                        lastUpdatedMs = state.modifiedMs,
                        version = state.version ?: it.version,
                        sizeBytes = state.sizeBytes,
                        // A body is on disk again, so the old failure is stale.
                        lastError = "",
                    )
                } else it
            }
        }
    }

    private fun applyDownloadResult(listId: String, result: DownloadResult) {
        _filterLists.update { current ->
            current.map {
                if (it.id == listId) {
                    it.copy(
                        ruleCount = result.lineCount.toInt(),
                        lastUpdatedText = result.updatedText ?: context.getString(R.string.filter_downloaded_now),
                        lastUpdatedMs = result.modifiedMs.takeIf { ms -> ms > 0 }
                            ?: System.currentTimeMillis(),
                        version = result.version ?: it.version,
                        format = result.detectedFormat ?: it.format,
                        sizeBytes = result.sizeBytes,
                        lastError = "",
                    )
                } else it
            }
        }
    }

    /**
     * Keeps a download failure on the list after the transient header toast
     * is gone: the row gets a red error line and the detail sheet an "Lỗi"
     * row, so a broken subscription never looks healthy.
     */
    private fun applyFailure(listId: String, message: UiText) {
        val text = message.resolve(context).ifBlank { context.getString(R.string.filter_download_failed) }
        _filterLists.update { current ->
            current.map {
                if (it.id == listId) {
                    it.copy(lastError = text)
                } else it
            }
        }
    }

    /**
     * Turns one list on or off. Enabling a list whose body is missing first
     * downloads it; the switch only moves to "on" after the file is on disk,
     * so a failed request can never leave the UI claiming a list is active.
     */
    fun toggleFilterList(listId: String, enabled: Boolean) {
        scope.launch {
            val list = _filterLists.value.firstOrNull { it.id == listId } ?: return@launch
            if (!enabled) {
                _filterLists.update { lists ->
                    lists.map { if (it.id == listId) it.copy(isEnabled = false) else it }
                }
            } else {
                val missingBody = withContext(Dispatchers.IO) {
                    engine.filterState(list.id, withMeta = false) == null
                }
                when {
                    list.isCustom || !missingBody -> {
                        _filterLists.update { lists ->
                            lists.map { if (it.id == listId) it.copy(isEnabled = true) else it }
                        }
                    }
                    list.subscriptionUrl.isNullOrBlank() -> {
                        _filterLists.update { lists ->
                            lists.map { if (it.id == listId) it.copy(isEnabled = false) else it }
                        }
                        showTransientStatus(
                            UiText.Formatted(R.string.filter_missing_body, list.name),
                        )
                    }
                    else -> {
                        // Keep the switch off while the fetch is in flight; only
                        // a successful download may turn it on.
                        _filterLists.update { lists ->
                            lists.map { if (it.id == listId) it.copy(isEnabled = false) else it }
                        }
                        _loadingMessage.value = UiText.Formatted(R.string.filter_downloading, list.name)
                        val result = withContext(Dispatchers.IO) { engine.downloadList(list) }
                        showTransientStatus(downloadMessage(result, list.name))
                        if (result.ok) {
                            applyDownloadResult(list.id, result)
                            _filterLists.update { lists ->
                                lists.map {
                                    if (it.id == listId) it.copy(isEnabled = true) else it
                                }
                            }
                        } else {
                            applyFailure(list.id, downloadMessage(result, list.name))
                        }
                    }
                }
            }
            saveFilterChoices()
            pushListsToEngine()
        }
    }

    /**
     * Marks a user-added list as trusted, or takes the mark back. Catalogue
     * lists and the user rules are trusted by construction; a list the user
     * typed a URL for may only run JavaScript rules, scriptlets and the
     * `$hls`/`$removeheader`/`$removeparam`/`$replace`/`$urltransform`
     * modifiers once they say so (KB §Trusted filters).
     */
    fun setFilterTrusted(listId: String, trusted: Boolean) {
        scope.launch {
            _filterLists.update { lists ->
                lists.map {
                    if (it.id == listId && it.isUserAdded) it.copy(trusted = trusted) else it
                }
            }
            saveFilterChoices()
            pushListsToEngine()
            showTransientStatus(
                if (trusted) UiText.Resource(R.string.filter_trusted)
                else UiText.Resource(R.string.filter_untrusted),
            )
        }
    }

    /** Download/refresh one subscription. Cheap: HTTP + file write, the core does the rest. */
    fun refreshSubscription(id: String) {
        scope.launch {
            val list = _filterLists.value.firstOrNull { it.id == id } ?: return@launch
            if (list.subscriptionUrl.isNullOrBlank()) {
                showTransientStatus(UiText.Resource(R.string.filter_no_url))
                return@launch
            }
            _loadingMessage.value = UiText.Formatted(R.string.filter_downloading, list.name)
            val result = withContext(Dispatchers.IO) { engine.downloadList(list) }
            showTransientStatus(downloadMessage(result, list.name))
            if (result.ok) {
                applyDownloadResult(list.id, result)
                pushListsToEngine()
            } else {
                applyFailure(list.id, downloadMessage(result, list.name))
            }
        }
    }

    /** Refreshes every enabled list that has a URL, in catalogue order. */
    fun refreshAllSubscriptions() {
        scope.launch {
            val targets = _filterLists.value.filter {
                it.isEnabled && !it.isCustom && !it.subscriptionUrl.isNullOrBlank()
            }
            if (targets.isEmpty()) {
                showTransientStatus(UiText.Resource(R.string.filter_none_to_update))
                return@launch
            }
            _loadingMessage.value = UiText.Formatted(R.string.filter_updating_count, targets.size)
            var failures = 0
            for (list in targets) {
                val result = withContext(Dispatchers.IO) { engine.downloadList(list) }
                if (result.ok) {
                    applyDownloadResult(list.id, result)
                } else {
                    failures++
                    applyFailure(list.id, downloadMessage(result, list.name))
                }
            }
            showTransientStatus(
                when (failures) {
                    0 -> UiText.Formatted(R.string.filter_updated_count, targets.size)
                    else -> UiText.Formatted(R.string.filter_update_finished_failures, failures)
                }
            )
            pushListsToEngine()
        }
    }

    /** Adds a filter list from a URL the user pasted. */
    fun addCustomFilter(name: String, url: String) {
        scope.launch {
            val trimmedUrl = url.trim()
            // Validate like the core would: syntax, scheme, host. A bad URL
            // used to become a permanent broken row before the first byte
            // was ever checked.
            filterUrlError(trimmedUrl)?.let {
                showTransientStatus(CoreText.filterUrlError(it))
                return@launch
            }
            if (_filterLists.value.any {
                    it.subscriptionUrl?.equals(trimmedUrl, ignoreCase = true) == true
                }
            ) {
                showTransientStatus(UiText.Resource(R.string.filter_url_duplicate))
                return@launch
            }
            val list = FilterList(
                id = "sub_${System.currentTimeMillis()}",
                name = name.ifBlank { trimmedUrl.substringAfter("//").take(40) },
                description = context.getString(R.string.filter_custom_description),
                ruleCount = 0,
                isEnabled = false,
                category = "custom",
                version = "",
                isOnlineSubscription = true,
                subscriptionUrl = trimmedUrl,
                groupId = "custom",
                isUserAdded = true,
            )
            _filterLists.update { it + list }
            _loadingMessage.value = UiText.Formatted(R.string.filter_downloading, list.name)
            val result = withContext(Dispatchers.IO) { engine.downloadList(list) }
            showTransientStatus(downloadMessage(result, list.name))
            if (result.ok) {
                applyDownloadResult(list.id, result)
                _filterLists.update { lists ->
                    lists.map { if (it.id == list.id) it.copy(isEnabled = true) else it }
                }
            } else {
                // Keep the (now disabled) row with its reason so the list can
                // be retried/edited without guessing what went wrong.
                applyFailure(list.id, downloadMessage(result, list.name))
            }
            saveFilterChoices()
            pushListsToEngine()
        }
    }

    /** Adds a `.txt` the user picked through the system file chooser. */
    fun importLocalFilter(uriText: String) {
        scope.launch {
            val uri = android.net.Uri.parse(uriText)
            val resolver = context.contentResolver
            val text = withContext(Dispatchers.IO) {
                runCatching {
                    resolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
                }.getOrNull()
            }
            if (text.isNullOrBlank()) {
                showTransientStatus(UiText.Resource(R.string.filter_file_unreadable))
                return@launch
            }
            val displayName = withContext(Dispatchers.IO) {
                runCatching {
                    resolver.query(uri, null, null, null, null)?.use { cursor ->
                        if (cursor.moveToFirst()) {
                            val index = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                            if (index >= 0) cursor.getString(index) else null
                        } else null
                    }
                }.getOrNull()
            }
            val list = FilterList(
                id = "local_${System.currentTimeMillis()}",
                name = displayName?.take(60)?.takeIf { it.isNotBlank() }
                    ?: context.getString(R.string.filter_from_file_name),
                description = context.getString(R.string.filter_from_file_description),
                ruleCount = 0,
                isEnabled = true,
                category = "custom",
                version = "standard",
                groupId = "custom",
                isUserAdded = true,
            )
            val state = withContext(Dispatchers.IO) { engine.saveListText(list.id, text) }
            if (state == null) {
                showTransientStatus(UiText.Resource(R.string.filter_save_failed))
                return@launch
            }
            _filterLists.update {
                it + list.copy(
                    ruleCount = state.lineCount.toInt(),
                    lastUpdatedText = context.getString(R.string.filter_imported_now),
                    version = state.version ?: "",
                    format = state.detectedFormat ?: list.format,
                )
            }
            saveFilterChoices()
            pushListsToEngine()
            showTransientStatus(
                UiText.Formatted(R.string.filter_created_name, list.name, state.lineCount),
            )
        }
    }

    /**
     * Writes settings + filter choices to a SAF document.
     *
     * The file is plain JSON on purpose: it can be inspected, moved to a
     * desktop port and restored without any Android-specific container.
     */
    suspend fun exportBackup(uriText: String): BackupResult {
        // Rust serializes the whole typed state (settings, firewall, DNS,
        // filters, scripts); Kotlin only moves the bytes to the SAF document.
        val payload = engine.backupExport()
        if (payload.isBlank()) {
            return BackupResult(false, UiText.Resource(R.string.backup_export_failed_read))
        }
        val ok = withContext(Dispatchers.IO) {
            runCatching {
                val uri = android.net.Uri.parse(uriText)
                context.contentResolver.openOutputStream(uri)
                    ?.bufferedWriter(Charsets.UTF_8)
                    ?.use { it.write(payload) }
                    ?: error("no output stream")
            }.isSuccess
        }
        return if (ok) {
            BackupResult(true, UiText.Resource(R.string.backup_export_done))
        } else {
            BackupResult(false, UiText.Resource(R.string.backup_export_write_failed))
        }
    }

    /**
     * Restores settings and filter choices from a SAF document.
     *
     * Settings are written first and rolled back if the filter blob is
     * rejected, so a failed restore never leaves a half-applied pair. Filter
     * bodies and userscripts are device-local: enabled lists without a body
     * are downloaded again by [loadFilterState], and current scripts stay.
     */
    suspend fun importBackup(uriText: String): BackupResult {
        val bytes = withContext(Dispatchers.IO) {
            runCatching {
                val uri = android.net.Uri.parse(uriText)
                context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
            }.getOrNull()
        } ?: return BackupResult(false, UiText.Resource(R.string.backup_import_file_unreadable))
        if (bytes.size > MAX_BACKUP_BYTES) {
            return BackupResult(false, UiText.Resource(R.string.backup_import_too_large))
        }
        val raw = String(bytes, Charsets.UTF_8)
        // Rust replaces every collection in one transaction, so a rejected
        // file leaves the current state untouched.
        val outcome = engine.backupImport(raw)
        if (!outcome.ok) {
            return BackupResult(
                false,
                CoreText.backupError(outcome.error)
                    ?: UiText.Resource(R.string.backup_error_malformed),
            )
        }
        reloadAfterRestore()
        return BackupResult(true, UiText.Resource(R.string.backup_import_done))
    }

    /** Rebuilds every in-memory flow after a restore replaced the state. */
    private fun reloadAfterRestore() {
        hydrateState()
        onConfigApplied()
    }

    /** Removes a user-added list (catalogue entries are toggled off, not deleted). */
    fun deleteFilterList(id: String) {
        val target = _filterLists.value.firstOrNull { it.id == id } ?: return
        if (!target.isUserAdded) return
        _filterLists.update { lists -> lists.filter { it.id != id } }
        scope.launch {
            withContext(Dispatchers.IO) { runCatching { engine.filterRemove(target.id) } }
            saveFilterChoices()
            pushListsToEngine()
        }
    }

    /**
     * Edits a user-added list's name and/or source URL. Validation and the
     * duplicate check run before the list model moves (same rules as
     * [addCustomFilter]); a URL change immediately refetches, so a failure
     * lands on the row instead of silently keeping stale content.
     */
    fun updateCustomFilter(id: String, rawName: String, rawUrl: String) {
        scope.launch {
            val list = _filterLists.value.firstOrNull { it.id == id } ?: return@launch
            if (!list.isUserAdded) return@launch
            val url = rawUrl.trim()
            if (url.isNotBlank()) {
                filterUrlError(url)?.let {
                    showTransientStatus(CoreText.filterUrlError(it))
                    return@launch
                }
                if (_filterLists.value.any {
                        it.id != id && it.subscriptionUrl?.equals(url, ignoreCase = true) == true
                    }
                ) {
                    showTransientStatus(UiText.Resource(R.string.filter_url_duplicate))
                    return@launch
                }
            }
            val name = rawName.trim().let { if (it.isBlank()) url.substringAfter("//").take(40) else it }
            val urlChanged = list.subscriptionUrl != url.ifBlank { null }
            _filterLists.update { lists ->
                lists.map {
                    if (it.id == id) {
                        // The old "Lỗi: …" belongs to the previous source.
                        it.copy(name = name, subscriptionUrl = url.ifBlank { null }, lastError = "")
                    } else it
                }
            }
            saveFilterChoices()
            pushListsToEngine()
            showTransientStatus(UiText.Formatted(R.string.filter_name_updated, name))
            if (urlChanged && url.isNotBlank()) refreshSubscription(id)
        }
    }

    /** AdGuard's "Khôi phục mặc định": the catalogue back to factory state. */
    fun restoreDefaultFilters() {
        scope.launch {
            _filterLists.update { lists ->
                lists.map { list ->
                    val catalog = list.catalogId?.let { FilterCatalog.byId(it) }
                    if (catalog != null) list.copy(isEnabled = catalog.defaultEnabled) else list
                }
            }
            val missing = _filterLists.value.filter {
                it.isEnabled && !it.isCustom && !it.subscriptionUrl.isNullOrBlank() &&
                    engine.filterState(it.id, withMeta = false) == null
            }
            for (list in missing) {
                _loadingMessage.value = UiText.Formatted(R.string.filter_downloading, list.name)
                val result = withContext(Dispatchers.IO) { engine.downloadList(list) }
                if (result.ok) applyDownloadResult(list.id, result)
            }
            saveFilterChoices()
            pushListsToEngine()
            showTransientStatus(UiText.Resource(R.string.filter_restored_defaults))
        }
    }

    /** Persists the user's choices: enabled catalogue ids, custom lists, user rules. */
    private fun saveFilterChoices() {
        val lists = _filterLists.value
        engine.saveFilters(
            FilterState(
                // Saving is a user action: from now on the saved set wins,
                // even when it is empty.
                catalogConfigured = true,
                enabledCatalogIds = lists
                    .filter { it.catalogId != null && it.isEnabled }
                    .mapNotNull { it.catalogId },
                trustedIds = lists.filter { it.isUserAdded && it.trusted }.map { it.id },
                custom = lists.filter { it.isUserAdded }.map {
                    FilterChoice(
                        id = it.id,
                        name = it.name,
                        url = it.subscriptionUrl.orEmpty(),
                        format = it.format,
                        homepage = it.homepage.orEmpty(),
                        enabled = it.isEnabled,
                        trusted = it.trusted,
                    )
                },
                userRules = lists.firstOrNull { it.isCustom }?.customRules.orEmpty(),
                userRulesConfigured = true,
            )
        )
    }

    fun updateAllCustomRules(newRules: List<String>) {
        scope.launch {
            // The UI already parses, but this is the last gate before the core:
            // keep cosmetic markers (#@#, ##, #%#) while dropping comments.
            val cleaned = parseUserRulesText(newRules.joinToString("\n"))
            _filterLists.update { lists ->
                lists.map {
                    if (it.isCustom) it.copy(ruleCount = cleaned.size, customRules = cleaned, isEnabled = cleaned.isNotEmpty()) else it
                }
            }
            saveFilterChoices()
            pushListsToEngine()
        }
    }

    fun addCustomRule(rawRule: String) {
        val rule = parseUserRulesText(rawRule).firstOrNull() ?: return
        scope.launch {
            _filterLists.update { lists ->
                lists.map {
                    if (it.isCustom) {
                        val updated = (it.customRules + rule).distinct()
                        it.copy(ruleCount = updated.size, customRules = updated, isEnabled = true)
                    } else it
                }
            }
            saveFilterChoices()
            pushListsToEngine()
        }
    }

    fun removeCustomRule(ruleStr: String) {
        scope.launch {
            _filterLists.update { lists ->
                lists.map {
                    if (it.isCustom) {
                        val updated = it.customRules.filter { r -> r != ruleStr }
                        it.copy(ruleCount = updated.size, customRules = updated)
                    } else it
                }
            }
            saveFilterChoices()
            pushListsToEngine()
        }
    }

    fun addDomainToWhitelist(domain: String) {
        val host = domain.trim().trimEnd('.')
        if (host.isBlank()) return
        addCustomRule("@@||$host^")
    }

    fun addDomainToBlacklist(domain: String) {
        val host = domain.trim().trimEnd('.')
        if (host.isBlank()) return
        addCustomRule("||$host^")
    }

    fun checkHost(host: String): Triple<Boolean, String, String> {
        val verdict = engine.checkHost(host)
        return Triple(verdict.blocked, verdict.rule, verdict.listName)
    }

    fun clearLogs() {
        logWindow = LOG_PAGE_SIZE
        lastLogCount = 0
        _logTotal.value = 0
        _logs.value = emptyList()
        // DELETE may touch 200k rows; keep it off the caller's thread.
        scope.launch { engine.logClear() }
    }

    fun resetStats() {
        engine.resetStats()
        clearLogs()
    }

    /**
     * Pushes the whole filter state (enabled lists + user rules) to the core in
     * one rebuild.
     *
     * The core replaces *both* at once, so they must be sent together —
     * pushing lists and rules separately makes them wipe each other.
     */
    private fun pushListsToEngine() {
        val lists = _filterLists.value
        val bindings = lists.filter { it.isEnabled && !it.isCustom }.mapNotNull { list ->
            val state = engine.filterState(list.id, withMeta = false) ?: return@mapNotNull null
            FilterListBinding(
                id = list.stableId(),
                name = list.name,
                url = list.subscriptionUrl.orEmpty(),
                enabled = true,
                path = state.path,
                format = if (list.format.equals("hosts", ignoreCase = true)) 1 else 0,
                category = list.categoryIndex(),
                ruleCount = list.ruleCount.toLong(),
                lastError = list.lastError,
                // Catalogue entries are trusted by construction; a custom list
                // only when the user said so.
                trusted = list.trusted || list.catalogId != null,
            )
        }
        val userRules = lists.firstOrNull { it.isCustom }?.customRules.orEmpty()
        engine.setListsAsync(bindings, userRules)
        watchFilterBuildErrors()
    }

    /**
     * Waits for the background compile to finish and mirrors its per-list
     * failures onto the rows. Until now an enabled list whose body could not
     * be read contributed zero rules with no explanation; the engine's own
     * reason ("Permission denied", "invalid UTF-8") is the only honest one.
     *
     * One watcher at a time: every toggle calls [pushListsToEngine], and only
     * the newest build's errors matter.
     */
    private fun watchFilterBuildErrors() {
        filterBuildJob?.cancel()
        filterBuildJob = scope.launch {
            val deadline = System.currentTimeMillis() + FILTER_BUILD_WATCH_MS
            while (System.currentTimeMillis() < deadline) {
                delay(300)
                val building = withContext(Dispatchers.IO) { runCatching { engine.stats().isBuilding }.getOrDefault(false) }
                if (!building) break
            }
            val errors = withContext(Dispatchers.IO) { engine.filterBuildErrors() }
            if (errors.isEmpty()) return@launch
            _filterLists.update { lists ->
                lists.map { list ->
                    val message = errors[list.stableId()] ?: return@map list
                    list.copy(
                lastError = context.getString(R.string.filter_file_unreadable_detail, message),
            )
                }
            }
        }
    }

    // ------------------------------------------------------------ app firewall

    /** Read installed apps through PackageManager and overlay the persisted rows. */
    private fun readInstalledApps(
        overrides: List<git.shin.adfree.core.AppFirewallRule>,
    ): List<AppFirewallRule> {
        val saved = overrides.associateBy { it.packageName }
        val pm = context.packageManager
        val installed = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0L))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledApplications(0)
        }
        return installed
            .asSequence()
            .filter { (it.flags and ApplicationInfo.FLAG_SYSTEM) == 0 || it.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0 }
            .map { info ->
                val override = saved[info.packageName]
                if (override != null) {
                    override.toModel(pm.getApplicationLabel(info).toString(), appCategory(info))
                } else {
                    AppFirewallRule(
                        packageName = info.packageName,
                        appName = pm.getApplicationLabel(info).toString(),
                        category = appCategory(info),
                    )
                }
            }
            .sortedBy { it.appName.lowercase() }
            .take(MAX_APPS_SHOWN)
            .toList()
    }

    private fun appCategory(info: ApplicationInfo): String {
        // PackageManager has no browser category; without this list the
        // "Browsers" chip could never match anything.
        if (info.packageName in BROWSER_PACKAGES) return AppCategory.BROWSER
        val pm = context.packageManager
        return try {
            val category = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                pm.getApplicationInfo(info.packageName, 0).category
            } else {
                ApplicationInfo.CATEGORY_UNDEFINED
            }
            when (category) {
                ApplicationInfo.CATEGORY_GAME -> AppCategory.GAME
                ApplicationInfo.CATEGORY_SOCIAL -> AppCategory.SOCIAL
                ApplicationInfo.CATEGORY_VIDEO -> AppCategory.VIDEO
                ApplicationInfo.CATEGORY_AUDIO -> AppCategory.AUDIO
                ApplicationInfo.CATEGORY_NEWS -> AppCategory.NEWS
                ApplicationInfo.CATEGORY_MAPS -> AppCategory.MAPS
                ApplicationInfo.CATEGORY_PRODUCTIVITY -> AppCategory.PRODUCTIVITY
                ApplicationInfo.CATEGORY_IMAGE -> AppCategory.IMAGE
                else -> AppCategory.OTHER
            }
        } catch (_: Exception) {
            AppCategory.OTHER
        }
    }

    fun updateAppFirewall(
        packageName: String,
        isCellularAllowed: Boolean? = null,
        isWifiAllowed: Boolean? = null,
        isFilterRouted: Boolean? = null,
        blockWhenScreenOff: Boolean? = null,
        isHttpsFiltered: Boolean? = null,
    ) {
        _appFirewallRules.update { list ->
            list.map { app ->
                if (app.packageName == packageName) {
                    app.copy(
                        isCellularAllowed = isCellularAllowed ?: app.isCellularAllowed,
                        isWifiAllowed = isWifiAllowed ?: app.isWifiAllowed,
                        isFilterRouted = isFilterRouted ?: app.isFilterRouted,
                        blockWhenScreenOff = blockWhenScreenOff ?: app.blockWhenScreenOff,
                        isHttpsFiltered = isHttpsFiltered ?: app.isHttpsFiltered,
                    )
                } else app
            }
        }
        saveAppFirewallRules()
    }

    /**
     * Persists only the non-default choices. An absent package is all-default
     * when the list is rebuilt after a restart, so the stored rows stay small.
     */
    private fun saveAppFirewallRules() {
        val overrides = _appFirewallRules.value
            .filter { it.hasOverrides() }
            .map { it.toCoreRule() }
        engine.saveFirewall(overrides)
        // Policy, HTTPS exclusions and tunnel exclusions all derive from this.
        onConfigApplied()
    }

    /**
     * Loads the userscript list: catalogue entries first, then anything the
     * user added. Bodies live under `filesDir/scripts/`, so nothing is ever
     * re-downloaded on a restart.
     */
    fun loadScriptsState(saved: ScriptState = engine.stateLoad().scripts) {
        scope.launch {
            val stored = saved.scripts
            val scripts = mutableListOf<UserScriptInfo>()
            // The shipped scripts live in the store like downloaded ones; this
            // refreshes the body when an app update changes it.
            withContext(Dispatchers.IO) { engine.installBuiltinScripts() }
            for (entry in UserScriptCatalog.scripts) {
                val state = stored.firstOrNull { it.id == entry.id }
                val asset = withContext(Dispatchers.IO) { engine.scriptState(entry.id) }
                scripts += UserScriptInfo(
                    id = entry.id,
                    name = entry.name,
                    description = "",
                    nameRes = entry.nameRes,
                    descriptionRes = entry.descriptionRes,
                    url = entry.url,
                    // Built-in scripts run unless the user turned them off;
                    // catalogue downloads wait to be asked for.
                    isEnabled = state?.enabled ?: entry.builtin,
                    sizeBytes = asset?.sizeBytes ?: 0,
                    lastUpdatedText = asset?.let { engine.dateText(it.modifiedMs) }
                        ?: context.getString(R.string.filter_not_loaded),
                    isBuiltin = entry.builtin,
                    metadata = scriptMetadata(entry.id, asset),
                )
            }
            for (state in stored.filter { s -> UserScriptCatalog.scripts.none { it.id == s.id } }) {
                val asset = withContext(Dispatchers.IO) { engine.scriptState(state.id) }
                scripts += UserScriptInfo(
                    id = state.id,
                    name = state.name,
                    description = state.description,
                    url = state.url,
                    isEnabled = state.enabled,
                    sizeBytes = asset?.sizeBytes ?: 0,
                    lastUpdatedText = asset?.let { engine.dateText(it.modifiedMs) }
                        ?: context.getString(R.string.filter_not_loaded),
                    isUserAdded = true,
                    metadata = scriptMetadata(state.id, asset),
                )
            }
            _userscripts.value = scripts
            _scriptsMasterEnabled.value = saved.master
            pushScriptsToCore()
        }
    }

    /**
     * Reads the header fields the detail sheet explains ("Phiên bản", "Trang
     * áp dụng", "Quyền"). Bodies are small and this runs on IO, once per
     * refresh; a missing body simply has no metadata.
     */
    private suspend fun scriptMetadata(id: String, asset: AssetState?): UserScriptMetadata {
        if (asset == null) return UserScriptMetadata()
        val body = withContext(Dispatchers.IO) { engine.scriptText(id) } ?: return UserScriptMetadata()
        return parseUserScriptMetadata(body)
    }

    fun toggleScriptsMaster(enabled: Boolean) {
        _scriptsMasterEnabled.value = enabled
        saveScripts()
        pushScriptsToCore()
    }

    /**
     * Enables a script only after its body exists. Catalogue entries start
     * without one, so the download must finish first; a failed fetch leaves
     * the switch off instead of claiming a script is running.
     */
    fun toggleScript(id: String, enabled: Boolean) {
        scope.launch {
            val script = _userscripts.value.firstOrNull { it.id == id } ?: return@launch
            var nextEnabled = enabled
            if (enabled) {
                val missingBody = withContext(Dispatchers.IO) { engine.scriptState(id) == null }
                if (missingBody) {
                    if (script.url.isBlank()) {
                        showTransientStatus(
                            UiText.Formatted(R.string.script_missing_body, script.name),
                        )
                        nextEnabled = false
                    } else {
                        _loadingMessage.value =
                            UiText.Formatted(R.string.script_loading, script.name)
                        val result = downloadScriptBody(script)
                        showTransientStatus(result.message)
                        nextEnabled = result.ok
                    }
                }
            }
            _userscripts.update { list ->
                list.map { if (it.id == id) it.copy(isEnabled = nextEnabled) else it }
            }
            saveScripts()
            pushScriptsToCore()
        }
    }

    /** Loads the first page of the store when the sheet opens. */
    fun openScriptStore() {
        if (_scriptStore.value.items.isEmpty() && !_scriptStore.value.loading) {
            searchScriptStore(_scriptStore.value.query)
        }
    }

    /**
     * Searches Greasy Fork with a small debounce. The query is trimmed and
     * capped so a paste cannot turn into an unbounded request URL. A new
     * query always starts from page 1; the current sort is preserved.
     */
    fun searchScriptStore(
        query: String,
        sort: UserScriptStoreSort = _scriptStore.value.sort,
    ) {
        val trimmed = query.trim().take(80)
        _scriptStore.update {
            it.copy(
                query = trimmed,
                sort = sort,
                loading = true,
                loadingMore = false,
                page = 1,
                hasMore = false,
                error = null,
            )
        }
        scriptStoreJob?.cancel()
        scriptStoreJob = scope.launch {
            try {
                if (trimmed.isNotEmpty()) delay(350)
                val items = withContext(Dispatchers.IO) { fetchGreasyFork(trimmed, 1, sort) }
                _scriptStore.update {
                    it.copy(
                        items = items,
                        loading = false,
                        page = 1,
                        hasMore = items.size >= GREASY_FORK_LIMIT,
                    )
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                _scriptStore.update {
                    it.copy(
                        loading = false,
                        error = e.message?.take(160)
                            ?: context.getString(R.string.script_store_load_failed),
                    )
                }
            }
        }
    }

    /** Applies a different Greasy Fork ordering and repeats the search. */
    fun setScriptStoreSort(sort: UserScriptStoreSort) {
        if (sort == _scriptStore.value.sort) return
        searchScriptStore(_scriptStore.value.query, sort)
    }

    /** Fetches the next page without dropping the rows already on screen. */
    fun loadMoreScriptStore() {
        val snapshot = _scriptStore.value
        if (snapshot.loading || snapshot.loadingMore || !snapshot.hasMore) return
        val nextPage = snapshot.page + 1
        _scriptStore.update { it.copy(loadingMore = true, error = null) }
        scriptStoreJob = scope.launch {
            try {
                val more = withContext(Dispatchers.IO) {
                    fetchGreasyFork(snapshot.query, nextPage, snapshot.sort)
                }
                _scriptStore.update {
                    it.copy(
                        items = mergeGreasyForkItems(it.items, more),
                        loadingMore = false,
                        page = nextPage,
                        hasMore = more.size >= GREASY_FORK_LIMIT,
                    )
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                _scriptStore.update {
                    it.copy(
                        loadingMore = false,
                        error = e.message?.take(160)
                            ?: context.getString(R.string.script_store_more_failed),
                    )
                }
            }
        }
    }

    private fun fetchGreasyFork(
        query: String,
        page: Int,
        sort: UserScriptStoreSort,
    ): List<UserScriptStoreItem> {
        val request = Request.Builder()
            .url(greasyForkUrl(query, page, sort))
            .header("Accept", "application/json")
            .header("User-Agent", "AdFree/1.0 (Android)")
            .build()
        scriptStoreClient.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                throw IOException("Greasy Fork HTTP ${response.code}")
            }
            val body = response.body?.string().orEmpty()
            if (body.isBlank()) return emptyList()
            return parseGreasyForkScripts(
                body,
                context.getString(R.string.script_greasy_fork_name),
            )
        }
    }

    /** Adds a userscript by URL and fetches its body right away. */
    fun addScript(
        name: String,
        url: String,
        description: String = context.getString(R.string.script_custom_description),
    ) {
        scope.launch {
            val trimmed = url.trim()
            if (trimmed.isEmpty()) return@launch
            val existing = _userscripts.value.firstOrNull { it.url == trimmed }
            if (existing != null) {
                // A second tap on a store row must not create a duplicate; it
                // only needs to make the script active again (or retry a body
                // that never downloaded).
                if (!existing.isEnabled || existing.sizeBytes == 0L) {
                    toggleScript(existing.id, true)
                } else {
                    showTransientStatus(
                        UiText.Formatted(R.string.script_duplicate, existing.name),
                    )
                }
                return@launch
            }
            val id = "script_${System.currentTimeMillis()}"
            val script = UserScriptInfo(
                id = id,
                name = name.ifBlank {
                    trimmed.substringAfterLast('/').take(40)
                        .ifBlank { context.getString(R.string.script_default_name) }
                },
                description = description.trim().take(300)
                    .ifEmpty { context.getString(R.string.script_custom_description) },
                url = trimmed,
                isEnabled = false,
                isUserAdded = true,
            )
            // Another tap can pass the check above before this coroutine runs;
            // merge on the flow so the list still gains exactly one row.
            val updated = _userscripts.updateAndGet { list ->
                if (list.any { it.url == trimmed }) list else list + script
            }
            if (updated.none { it.id == id }) {
                val winner = updated.firstOrNull { it.url == trimmed }
                if (winner != null && (!winner.isEnabled || winner.sizeBytes == 0L)) {
                    toggleScript(winner.id, true)
                } else {
                    showTransientStatus(
                        UiText.Formatted(R.string.script_duplicate, script.name),
                    )
                }
                return@launch
            }
            _loadingMessage.value = UiText.Formatted(R.string.script_loading, script.name)
            val result = downloadScriptBody(script)
            showTransientStatus(result.message)
            if (result.ok) {
                _userscripts.update { list ->
                    list.map { if (it.id == script.id) it.copy(isEnabled = true) else it }
                }
            }
            saveScripts()
            pushScriptsToCore()
        }
    }

    fun refreshScript(id: String) {
        scope.launch {
            val script = _userscripts.value.firstOrNull { it.id == id } ?: return@launch
            _loadingMessage.value = UiText.Formatted(R.string.script_loading, script.name)
            val result = downloadScriptBody(script)
            showTransientStatus(result.message)
            saveScripts()
            pushScriptsToCore()
        }
    }

    private data class ScriptDownloadResult(val ok: Boolean, val message: UiText)

    /** Downloads one script body to the store and reports whether it is usable. */
    private suspend fun downloadScriptBody(script: UserScriptInfo): ScriptDownloadResult {
        if (script.url.isBlank()) {
            return ScriptDownloadResult(false, UiText.Resource(R.string.script_no_url))
        }
        val outcome = withContext(Dispatchers.IO) { engine.scriptFetch(script.id, script.url) }
        if (!outcome.ok) {
            return ScriptDownloadResult(
                false,
                CoreText.downloadError(outcome.error)
                    ?: UiText.Formatted(
                        R.string.script_download_failed,
                        script.name,
                        outcome.message,
                    ),
            )
        }
        val body = withContext(Dispatchers.IO) { engine.scriptText(script.id) }
        val metadata = body?.let(::parseUserScriptMetadata) ?: UserScriptMetadata()
        _userscripts.update { list ->
            list.map {
                if (it.id == script.id) {
                    it.copy(
                        sizeBytes = outcome.sizeBytes,
                        lastUpdatedText = engine.dateText(outcome.modifiedMs),
                        metadata = metadata,
                    )
                } else it
            }
        }
        return ScriptDownloadResult(
            true,
            UiText.Formatted(
                R.string.script_downloaded,
                script.name,
                outcome.sizeBytes / 1024,
            ),
        )
    }

    /** Removes a user-added script (catalogue entries are toggled off, not deleted). */
    fun deleteScript(id: String) {
        val target = _userscripts.value.firstOrNull { it.id == id } ?: return
        if (!target.isUserAdded) return
        _userscripts.update { list -> list.filter { it.id != id } }
        scope.launch {
            withContext(Dispatchers.IO) { runCatching { engine.scriptRemove(id) } }
            saveScripts()
            pushScriptsToCore()
        }
    }

    /** Imports a userscript body from a local file and enables it. */
    fun importLocalScript(uriText: String) {
        scope.launch {
            val uri = android.net.Uri.parse(uriText)
            val resolver = context.contentResolver
            val text = withContext(Dispatchers.IO) {
                runCatching { resolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() } }
                    .getOrNull()
            }
            if (text.isNullOrBlank()) {
                showTransientStatus(UiText.Resource(R.string.script_file_unreadable))
                return@launch
            }
            val displayName = withContext(Dispatchers.IO) {
                runCatching {
                    resolver.query(uri, null, null, null, null)?.use { cursor ->
                        if (cursor.moveToFirst()) {
                            val index = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                            if (index >= 0) cursor.getString(index) else null
                        } else null
                    }
                }.getOrNull()
            }
            val base = scriptNameFromFile(displayName)
                .ifBlank { context.getString(R.string.script_from_file_name) }
            val id = "script_local_${System.currentTimeMillis()}"
            val script = UserScriptInfo(
                id = id,
                name = base,
                description = context.getString(R.string.script_from_file_description),
                url = "",
                isEnabled = false,
                isUserAdded = true,
            )
            val updated = _userscripts.updateAndGet { list -> if (list.any { it.id == id }) list else list + script }
            if (updated.none { it.id == id }) {
                showTransientStatus(UiText.Formatted(R.string.script_duplicate, base))
                return@launch
            }
            val state = withContext(Dispatchers.IO) { engine.scriptSave(id, text) }
            if (state == null) {
                showTransientStatus(UiText.Resource(R.string.script_save_failed))
                return@launch
            }
            _userscripts.update { list ->
                list.map {
                    if (it.id == id) {
                        it.copy(
                            sizeBytes = state.sizeBytes,
                            lastUpdatedText = context.getString(R.string.script_imported_now),
                            isEnabled = true,
                            metadata = parseUserScriptMetadata(text),
                        )
                    } else it
                }
            }
            saveScripts()
            pushScriptsToCore()
            showTransientStatus(UiText.Formatted(R.string.script_added, base))
        }
    }

    /** Creates a new userscript from pasted text (no URL). */
    fun createScript(name: String, text: String) {
        scope.launch {
            val trimmed = text.trim()
            if (trimmed.isBlank()) {
                showTransientStatus(UiText.Resource(R.string.script_empty_content))
                return@launch
            }
            val displayName = name.trim()
                .ifBlank { context.getString(R.string.script_default_custom_name) }
                .take(60)
            val id = "script_custom_${System.currentTimeMillis()}"
            val script = UserScriptInfo(
                id = id,
                name = displayName,
                description = context.getString(R.string.script_editor_description),
                url = "",
                isEnabled = false,
                isUserAdded = true,
            )
            _userscripts.update { list -> list + script }
            val state = withContext(Dispatchers.IO) { engine.scriptSave(id, trimmed) }
            if (state == null) {
                showTransientStatus(UiText.Resource(R.string.script_save_error))
                _userscripts.update { list -> list.filter { it.id != id } }
                return@launch
            }
            _userscripts.update { list ->
                list.map {
                    if (it.id == id) {
                        it.copy(
                            sizeBytes = state.sizeBytes,
                            lastUpdatedText = context.getString(R.string.script_created_now),
                            isEnabled = true,
                            metadata = parseUserScriptMetadata(trimmed),
                        )
                    } else it
                }
            }
            saveScripts()
            pushScriptsToCore()
            showTransientStatus(UiText.Formatted(R.string.script_created, displayName))
        }
    }

    /** Overwrites an existing user-added script body (edit source). */
    fun updateScriptText(id: String, name: String, text: String) {
        scope.launch {
            val script = _userscripts.value.firstOrNull { it.id == id } ?: return@launch
            if (!script.isUserAdded) return@launch
            val trimmed = text.trim()
            if (trimmed.isBlank()) {
                showTransientStatus(UiText.Resource(R.string.script_empty_content))
                return@launch
            }
            val displayName = name.trim().ifBlank { script.name }.take(60)
            val state = withContext(Dispatchers.IO) { engine.scriptSave(id, trimmed) }
            if (state == null) {
                showTransientStatus(UiText.Resource(R.string.script_save_error))
                return@launch
            }
            _userscripts.update { list ->
                list.map {
                    if (it.id == id) {
                        // Editing the source never flips the enable switch: a
                        // script the user turned off stays off until asked.
                        it.copy(
                            name = displayName,
                            sizeBytes = state.sizeBytes,
                            lastUpdatedText = context.getString(R.string.script_edited_now),
                            metadata = parseUserScriptMetadata(trimmed),
                        )
                    } else it
                }
            }
            saveScripts()
            pushScriptsToCore()
            showTransientStatus(UiText.Formatted(R.string.script_updated, displayName))
        }
    }

    private fun saveScripts() {
        engine.saveScripts(
            ScriptState(
                master = _scriptsMasterEnabled.value,
                scripts = _userscripts.value.map {
                    ScriptRecord(
                        id = it.id,
                        name = it.name,
                        description = it.description,
                        url = it.url,
                        enabled = it.isEnabled,
                    )
                },
            )
        )
    }

    /** Hands the core every script with its body; the master switch rides along. */
    private fun pushScriptsToCore() {
        val bindings = _userscripts.value.mapNotNull { script ->
            val body = engine.scriptText(script.id) ?: return@mapNotNull null
            ScriptBinding(
                name = script.name,
                body = body,
                enabled = script.isEnabled,
            )
        }.filter { it.body.isNotBlank() }
        engine.setScripts(bindings, _scriptsMasterEnabled.value)
    }

    /** Apps kept out of the tunnel (read by VpnService during establish). */
    fun excludedPackages(): List<String> = engine.excludedPackages()

    fun dismissLoading() {
        _loadingMessage.value = null
    }

    private companion object {
        private const val TAG = "AdFreeRepo"

        /** Rows fetched per page; the log screen loads more on demand. */
        private const val LOG_PAGE_SIZE = 200

        /** Ceiling for the in-RAM window so paging cannot grow without bound. */
        private const val MAX_LOG_ROWS = 2_000
        private const val MAX_APPS_SHOWN = 250
        private const val BUILTIN_CUSTOM = "builtin_custom"

        /** Known browser packages; Android exposes no browser category. */
        private val BROWSER_PACKAGES = setOf(
            "com.android.chrome",
            "com.chrome.beta",
            "com.chrome.dev",
            "com.chrome.canary",
            "org.chromium.chrome",
            "com.google.android.apps.chrome",
            "org.mozilla.firefox",
            "org.mozilla.firefox_beta",
            "org.mozilla.fennec_fdroid",
            "com.brave.browser",
            "com.sec.android.app.sbrowser",
            "com.opera.browser",
            "com.opera.mini.native",
            "com.microsoft.emmx",
            "com.duckduckgo.mobile.android",
            "com.vivaldi.browser",
            "com.kiwibrowser.browser",
            "io.github.ungoogled_software.ungoogled_chromium",
        )

        /** A few starter rules so the user sees how they work. */
        private val starterRules = listOf(
            "@@||example.com^",
            "||ads.example.com^",
            "/^adserver-[0-9]+\\./",
        )

        /** Stable id for the core (must fit in u16). */
        fun FilterList.stableId(): Int =
            id.hashCode().toLong().let { it.and(0xFFFF).toInt() }.coerceAtLeast(1)

        /**
         * Maps a list to one of the core's fixed categories (u8, kept stable on
         * the Rust side): 0 ads, 1 privacy, 3 social, 4 annoyances, 5 security,
         * 6 other. Legacy lists from older builds have an empty `groupId`, so
         * the old `category` text is still honoured.
         */
        fun FilterList.categoryIndex(): Int = when (groupId.lowercase()) {
            "ads", "language" -> 0
            "privacy" -> 1
            "social" -> 3
            "annoyances" -> 4
            "security" -> 5
            "custom", "user", "other" -> 6
            else -> when (category.lowercase()) {
                "ad blocking", "ad" -> 0
                "privacy", "tracker" -> 1
                "analytics" -> 2
                "social" -> 3
                "annoyances" -> 4
                "malware", "phishing" -> 5
                else -> 6
            }
        }
    }
}

/**
 * Greasy Fork only returns 50 rows per page. `page` starts at 1 and is omitted
 * for the first page so the default request stays byte-for-byte compatible.
 */
internal fun greasyForkUrl(
    query: String,
    page: Int,
    sort: UserScriptStoreSort,
): String {
    val params = ArrayList<String>(3)
    if (query.isNotEmpty()) params += "q=${URLEncoder.encode(query, "UTF-8")}"
    if (page > 1) params += "page=$page"
    sort.apiValue?.let { params += "sort=$it" }
    return if (params.isEmpty()) GREASY_FORK_API else "$GREASY_FORK_API?${params.joinToString("&")}"
}

/** Appends the next page, dropping rows that point at the same `.user.js`. */
internal fun mergeGreasyForkItems(
    existing: List<UserScriptStoreItem>,
    incoming: List<UserScriptStoreItem>,
): List<UserScriptStoreItem> {
    val seen = existing.mapTo(HashSet(existing.size)) { it.url }
    val merged = ArrayList<UserScriptStoreItem>(existing.size + incoming.size)
    merged += existing
    incoming.forEach { item ->
        if (item.url.isNotBlank() && seen.add(item.url)) merged += item
    }
    return merged
}

/**
 * Parse Greasy Fork's JSON list. Kept top-level and free of Android state so a
 * JVM test can feed it a fixture without a network call.
 */
internal fun parseGreasyForkScripts(
    json: String,
    fallbackName: String = "Greasy Fork userscript",
): List<UserScriptStoreItem> {
    val array = JSONArray(json)
    val count = minOf(array.length(), GREASY_FORK_LIMIT)
    val items = ArrayList<UserScriptStoreItem>(count)
    for (i in 0 until count) {
        val obj = array.optJSONObject(i) ?: continue
        val codeUrl = obj.cleanString("code_url")
        if (codeUrl.isEmpty()) continue
        if (!codeUrl.startsWith("https://") && !codeUrl.startsWith("http://")) continue
        val pageUrl = obj.cleanString("url")
            .takeIf { it.startsWith("https://") || it.startsWith("http://") }
            .orEmpty()
        items += UserScriptStoreItem(
            id = obj.optLong("id"),
            name = obj.cleanString("name").ifEmpty { fallbackName },
            description = obj.cleanString("description").take(300),
            url = codeUrl,
            pageUrl = pageUrl,
            version = obj.cleanString("version"),
            dailyInstalls = obj.optInt("daily_installs"),
            totalInstalls = obj.optInt("total_installs"),
            license = obj.cleanString("license"),
            codeSizeBytes = obj.optLong("code_size"),
        )
    }
    return items
}

/** `optString` returns the literal "null" for JSON null; hide that from the UI. */
private fun JSONObject.cleanString(key: String): String =
    optString(key).trim().let { if (it == "null") "" else it }
