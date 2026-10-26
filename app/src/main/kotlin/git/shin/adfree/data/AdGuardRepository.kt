package git.shin.adfree.data

import android.content.Context
import android.util.Log
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import git.shin.adfree.core.AssetState
import git.shin.adfree.core.CoreEngine
import git.shin.adfree.core.DownloadResult
import git.shin.adfree.core.FilterListBinding
import git.shin.adfree.core.ScriptBinding
import git.shin.adfree.core.StatsSnapshot
import git.shin.adfree.model.AppFirewallRule
import git.shin.adfree.model.DnsBlockMode
import git.shin.adfree.model.DnsProvider
import git.shin.adfree.model.FilterList
import git.shin.adfree.model.FilterStatus
import git.shin.adfree.model.filterUpdateDue
import git.shin.adfree.model.filterUrlError
import git.shin.adfree.model.normalizeHttpsHost
import git.shin.adfree.model.scriptNameFromFile
import git.shin.adfree.model.UserScriptInfo
import git.shin.adfree.model.UserScriptMetadata
import git.shin.adfree.model.parseUserScriptMetadata
import git.shin.adfree.model.parseUserRulesText
import git.shin.adfree.model.parseDnsEndpoint
import git.shin.adfree.model.UserScriptStoreItem
import git.shin.adfree.model.UserScriptStoreSort
import git.shin.adfree.model.UserScriptStoreState
import git.shin.adfree.model.NetworkRequestLog
import git.shin.adfree.model.ProtectionStats
import git.shin.adfree.model.ProtectionSettings
import git.shin.adfree.model.ProtocolType
import java.io.IOException
import java.net.URLEncoder
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.drop
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

    private val _dnsProviders = MutableStateFlow<List<DnsProvider>>(defaultDnsProviders())
    val dnsProviders: StateFlow<List<DnsProvider>> = _dnsProviders.asStateFlow()

    private val _loadingMessage = MutableStateFlow<String?>(null)
    val loadingMessage: StateFlow<String?> = _loadingMessage.asStateFlow()

    /**
     * Shows a one-shot result message ("đã tải…", download errors) and clears it
     * a few seconds later, so the header cannot stay stuck on "Đang tải…".
     * The equality check keeps a newer message from being cleared by an older
     * timer.
     */
    private fun showTransientStatus(message: String?) {
        _loadingMessage.value = message
        if (message == null) return
        scope.launch {
            delay(4_000)
            if (_loadingMessage.value == message) _loadingMessage.value = null
        }
    }

    /**
     * User choices that outlive a restart: which lists are on, custom filters,
     * scripts. Lazy so a JVM test can build a repository without a real
     * Android context (SharedPreferences are only reachable through one).
     */
    private val prefs by lazy { FilterPreferences(context) }

    /** The protection switches; without this the app came back with all of them off. */
    private val settingsPrefs by lazy { SettingsPreferences(context) }

    private val _userscripts = MutableStateFlow<List<UserScriptInfo>>(emptyList())
    val userscripts: StateFlow<List<UserScriptInfo>> = _userscripts.asStateFlow()

    private val _scriptsMasterEnabled = MutableStateFlow(false)
    val scriptsMasterEnabled: StateFlow<Boolean> = _scriptsMasterEnabled.asStateFlow()

    private val _scriptStore = MutableStateFlow(UserScriptStoreState())
    val scriptStore: StateFlow<UserScriptStoreState> = _scriptStore.asStateFlow()
    private var scriptStoreJob: Job? = null

    /** Coalesces the post-build error checks started by [pushListsToEngine]. */
    private var filterBuildJob: Job? = null

    /** Guards the launch/resume subscription refresh against a double start. */
    private var autoUpdateRunning = false

    /** Last time a stale-list scan ran; throttles ON_RESUME checks. */
    private var lastAutoUpdateCheckMs = 0L

    private val scriptStoreClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .build()
    }

    init {
        startStatsPoller()
        // Every change to the switches lands on disk, so the VPN and HTTPS
        // filtering survive a restart instead of coming back off. StateFlow
        // conflates, so this writes once per real change, not per emission.
        scope.launch {
            _settings.drop(1).collect { settingsPrefs.save(it) }
        }
    }

    /**
     * Restores the switches saved by an earlier run; called once at startup,
     * before the configuration is pushed down to the core.
     */
    fun loadSettings() {
        // Custom resolvers live in the settings blob; merge them before the
        // selected id is resolved, otherwise a restart would point at a
        // provider that only exists in memory.
        val customDns = settingsPrefs.customDnsProviders()
        if (customDns.isNotEmpty()) {
            _dnsProviders.update { current ->
                val ids = current.mapTo(HashSet(current.size)) { it.id }
                current + customDns.filter { ids.add(it.id) }
            }
        }
        val stored = settingsPrefs.settings()
        // Never assign an intermediate default here: the settings collector
        // writes every emission, and after a backup restore that would race
        // with (and possibly overwrite) the blob just read from disk.
        _settings.value = if (stored == null) {
            ProtectionSettings()
        } else {
            // Terminating TLS with a certificate the device no longer trusts
            // would break every page it touches, so that switch only comes
            // back when the CA is still installed.
            val https = stored.isHttpsFilteringEnabled && engine.isCaTrusted()
            stored.copy(isHttpsFilteringEnabled = https)
        }
    }

    /**
     * True when protection was on the last time the app ran: it is then
     * switched back on at launch instead of waiting for the user. A first run
     * has nothing saved and stays off.
     */
    fun protectionWasOn(): Boolean = settingsPrefs.settings()?.isProtectionActive == true

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

    fun toggleProtection(enabled: Boolean) {
        _settings.update { it.copy(isProtectionActive = enabled) }
        if (enabled) engine.markWantsStart() else engine.markWantsStop()
    }

    fun toggleAdBlocking(enabled: Boolean) = _settings.update { it.copy(isAdBlockingEnabled = enabled) }
    fun toggleTrackingProtection(enabled: Boolean) =
        _settings.update { it.copy(isTrackingProtectionEnabled = enabled) }

    fun toggleDnsProtection(enabled: Boolean) =
        _settings.update { it.copy(isDnsProtectionEnabled = enabled) }

    fun toggleSmartFiltering(enabled: Boolean) =
        _settings.update { it.copy(isSmartFilteringEnabled = enabled) }

    fun toggleHttpsFiltering(enabled: Boolean) =
        _settings.update { it.copy(isHttpsFilteringEnabled = enabled) }

    fun toggleFullEch(enabled: Boolean) =
        _settings.update { it.copy(isFullEchEnabled = enabled) }

    /** Adds a host pattern to the HTTPS allowlist (sites left undecrypted). */
    fun addHttpsSkipHost(raw: String) {
        val host = normalizeHttpsHost(raw) ?: return
        _settings.update { settings ->
            if (settings.httpsSkipHosts.any { it.equals(host, ignoreCase = true) }) settings
            else settings.copy(httpsSkipHosts = settings.httpsSkipHosts + host)
        }
    }

    fun removeHttpsSkipHost(host: String) {
        _settings.update { it.copy(httpsSkipHosts = it.httpsSkipHosts - host) }
    }

    /** Adds a host to the list used when [setHttpsOnlyMode] is on. */
    fun addHttpsOnlyHost(raw: String) {
        val host = normalizeHttpsHost(raw) ?: return
        _settings.update { settings ->
            if (settings.httpsOnlyHosts.any { it.equals(host, ignoreCase = true) }) settings
            else settings.copy(httpsOnlyHosts = settings.httpsOnlyHosts + host)
        }
    }

    fun removeHttpsOnlyHost(host: String) {
        _settings.update { it.copy(httpsOnlyHosts = it.httpsOnlyHosts - host) }
    }

    /** Inverts HTTPS filtering: decrypt only the hosts in the blocklist. */
    fun setHttpsOnlyMode(enabled: Boolean) {
        _settings.update { it.copy(httpsOnlyMode = enabled) }
    }

    fun toggleFirewall(enabled: Boolean) = _settings.update { it.copy(isFirewallEnabled = enabled) }
    fun toggleEcoBatteryMode(enabled: Boolean) =
        _settings.update { it.copy(isEcoBatteryModeEnabled = enabled) }

    fun toggleStealthMode(enabled: Boolean) =
        _settings.update { it.copy(isStealthModeEnabled = enabled) }

    fun updateStealthSetting(
        stripUtm: Boolean? = null,
        blockWebRtc: Boolean? = null,
        disguiseUa: Boolean? = null,
        blockCookies: Boolean? = null,
    ) = _settings.update { cur ->
        cur.copy(
            stripUtmTracking = stripUtm ?: cur.stripUtmTracking,
            blockWebRtcLeaks = blockWebRtc ?: cur.blockWebRtcLeaks,
            disguiseUserAgent = disguiseUa ?: cur.disguiseUserAgent,
            blockThirdPartyCookies = blockCookies ?: cur.blockThirdPartyCookies,
        )
    }

    fun toggleBlockQuic(enabled: Boolean) = _settings.update { it.copy(blockQuic = enabled) }

    /**
     * One switch covers both encrypted-DNS transports, matching the settings
     * label: leaving DoT enabled while DoH is off would let clients bypass the
     * filter through the other port.
     */
    fun toggleBlockDoh(enabled: Boolean) =
        _settings.update { it.copy(blockDoh = enabled, blockDot = enabled) }

    /** Refresh interval for subscriptions, in hours; 0 turns it off. */
    fun setFilterAutoUpdate(hours: Int) {
        val clamped = hours.coerceIn(0, 168)
        _settings.update { it.copy(filterAutoUpdateHours = clamped) }
        showTransientStatus(
            if (clamped == 0) "Đã tắt tự động cập nhật bộ lọc"
            else "Tự động cập nhật bộ lọc mỗi $clamped giờ",
        )
    }

    fun toggleLogAllowed(enabled: Boolean) = _settings.update { it.copy(logAllowedRequests = enabled) }
    fun setBlockMode(mode: DnsBlockMode) = _settings.update { it.copy(blockMode = mode) }

    fun selectDnsProvider(id: String) {
        val provider = _dnsProviders.value.firstOrNull { it.id == id } ?: return
        val endpoint = parseDnsEndpoint(provider.address)
        if (endpoint == null) {
            showTransientStatus("Resolver chỉ hỗ trợ DNS UDP dạng IP (ví dụ 1.1.1.1)")
            return
        }
        _settings.update { it.copy(selectedDnsProviderId = id) }
        engine.setResolver(endpoint.host, endpoint.port)
    }

    /** Adds/selects a resolver and returns the line the Settings snackbar shows. */
    fun addCustomDnsProvider(name: String, address: String): String {
        val trimmed = address.trim()
        if (trimmed.isEmpty()) return "Địa chỉ DNS trống"
        val endpoint = parseDnsEndpoint(trimmed)
            ?: return "Chỉ hỗ trợ DNS UDP dạng IP (ví dụ 1.1.1.1 hoặc 1.1.1.1:53)"
        val existing = _dnsProviders.value.firstOrNull { it.address == trimmed }
        if (existing != null) {
            selectDnsProvider(existing.id)
            return "Đã chọn ${existing.name}"
        }
        val provider = DnsProvider(
            id = "custom_" + System.currentTimeMillis(),
            name = name.trim().ifBlank { trimmed },
            address = trimmed,
            // The forwarder sends plain UDP; DoH/DoT need a different
            // transport and are rejected above rather than silently ignored.
            type = ProtocolType.DNS_UDP,
            description = "Tùy chỉnh",
            isCustom = true,
        )
        _dnsProviders.update { it + provider }
        settingsPrefs.saveCustomDnsProviders(_dnsProviders.value.filter { it.isCustom })
        engine.setResolver(endpoint.host, endpoint.port)
        _settings.update { it.copy(selectedDnsProviderId = provider.id) }
        return "Đã thêm DNS tùy chỉnh: ${provider.name}"
    }

    // ----------------------------------------------------------- filter lists

    /**
     * Seeds the catalogue, merges the user's saved choices and downloads what
     * is enabled but missing.
     *
     * Only enabled lists cost a download: a fresh install fetches the four
     * defaults and nothing else.
     */
    fun loadFilterState() {
        scope.launch {
            val savedIds = prefs.enabledCatalogIds()
            val lists = mutableListOf<FilterList>()
            for (entry in FilterCatalog.filters) {
                val enabled = savedIds?.contains(entry.id) ?: entry.defaultEnabled
                lists += FilterList(
                    id = entry.listId ?: "cat_${entry.id}",
                    name = entry.name,
                    description = entry.description,
                    ruleCount = 0,
                    isEnabled = enabled,
                    category = entry.group.id,
                    // Only a downloaded list has a real version: seeding it with
                    // the syntax made the detail sheet print "Phiên bản
                    // standard" before the first byte had arrived.
                    version = "",
                    isOnlineSubscription = true,
                    subscriptionUrl = entry.url,
                    lastUpdatedText = "Chưa tải",
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
            for (stored in prefs.customFilters()) {
                lists += FilterList(
                    id = stored.id,
                    name = stored.name,
                    description = "Bộ lọc tùy chỉnh của bạn",
                    ruleCount = 0,
                    isEnabled = stored.enabled,
                    category = "custom",
                    version = "",
                    isOnlineSubscription = stored.url.isNotBlank(),
                    subscriptionUrl = stored.url.ifBlank { null },
                    lastUpdatedText = "Chưa tải",
                    groupId = "custom",
                    format = stored.format,
                    homepage = stored.homepage,
                    isUserAdded = true,
                    trusted = stored.trusted,
                )
            }
            val rules = prefs.userRules() ?: starterRules
            lists += FilterList(
                id = BUILTIN_CUSTOM,
                name = "Quy tắc của bạn",
                description = "Quy tắc chặn và cho phép do bạn tự viết, áp dụng cho mọi trang",
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
            autoUpdateStaleLists()
        }
    }

    /**
     * Re-checks stale subscriptions when the activity comes back to the
     * foreground (for example after a long session or a day in Recents).
     *
     * There is still no worker, alarm or wake lock: the check only runs while
     * the user is already looking at the app. The 30-minute throttle keeps a
     * failed download from retrying on every tab switch or dialog dismissal.
     */
    fun autoUpdateIfStale() {
        val now = System.currentTimeMillis()
        if (now - lastAutoUpdateCheckMs < AUTO_UPDATE_RESUME_MIN_INTERVAL_MS) return
        lastAutoUpdateCheckMs = now
        scope.launch { autoUpdateStaleLists() }
    }

    /**
     * Refreshes enabled subscriptions older than `filterAutoUpdateHours`.
     *
     * There is no periodic worker, no wake lock and no radio wake-up while the
     * phone is idle. A stale list catches up on launch/resume instead.
     */
    private suspend fun autoUpdateStaleLists() {
        lastAutoUpdateCheckMs = System.currentTimeMillis()
        if (autoUpdateRunning) return
        val hours = settingsPrefs.settings()?.filterAutoUpdateHours
            ?: _settings.value.filterAutoUpdateHours
        if (hours <= 0) return
        val now = System.currentTimeMillis()
        val stale = _filterLists.value.filter {
            it.isEnabled && !it.isCustom && !it.subscriptionUrl.isNullOrBlank() &&
                filterUpdateDue(it.lastUpdatedMs, now, hours)
        }
        if (stale.isEmpty()) return

        autoUpdateRunning = true
        try {
            _loadingMessage.value = "Đang tự động cập nhật ${stale.size} bộ lọc…"
            var updated = 0
            for (list in stale) {
                val result = withContext(Dispatchers.IO) { engine.downloadList(list) }
                if (result.ok) {
                    applyDownloadResult(list.id, result)
                    updated++
                } else {
                    applyFailure(list.id, result.message)
                }
            }
            if (updated > 0) pushListsToEngine()
            showTransientStatus(
                if (updated == stale.size) {
                    "Đã tự động cập nhật ${stale.size} bộ lọc"
                } else {
                    "Tự động cập nhật: $updated/${stale.size} bộ lọc thành công"
                },
            )
        } finally {
            autoUpdateRunning = false
            _loadingMessage.value = null
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
            _loadingMessage.value = "Đang tải ${list.name}…"
            val result = withContext(Dispatchers.IO) { engine.downloadList(list) }
            if (result.ok) {
                applyDownloadResult(list.id, result)
            } else {
                // Startup download failures used to vanish: the list stayed
                // "on" with zero rules and no trace of why. Persist the
                // reason on the list (row + detail sheet show it) and echo
                // the usual transient toast.
                applyFailure(list.id, result.message)
                showTransientStatus(result.message)
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
                        lastUpdatedText = result.updatedText ?: "Vừa tải",
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
    private fun applyFailure(listId: String, message: String) {
        _filterLists.update { current ->
            current.map {
                if (it.id == listId) {
                    it.copy(lastError = message.ifBlank { "Tải thất bại" })
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
                            "Không có nội dung ${list.name}; hãy thêm lại hoặc chọn tệp khác",
                        )
                    }
                    else -> {
                        // Keep the switch off while the fetch is in flight; only
                        // a successful download may turn it on.
                        _filterLists.update { lists ->
                            lists.map { if (it.id == listId) it.copy(isEnabled = false) else it }
                        }
                        _loadingMessage.value = "Đang tải ${list.name}…"
                        val result = withContext(Dispatchers.IO) { engine.downloadList(list) }
                        showTransientStatus(result.message)
                        if (result.ok) {
                            applyDownloadResult(list.id, result)
                            _filterLists.update { lists ->
                                lists.map {
                                    if (it.id == listId) it.copy(isEnabled = true) else it
                                }
                            }
                        } else {
                            applyFailure(list.id, result.message)
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
                if (trusted) "Đã tin cậy bộ lọc: scriptlet và JavaScript rule của list được phép chạy"
                else "Đã bỏ tin cậy: rule nguy hiểm của bộ lọc bị bỏ qua",
            )
        }
    }

    /** Download/refresh one subscription. Cheap: HTTP + file write, the core does the rest. */
    fun refreshSubscription(id: String) {
        scope.launch {
            val list = _filterLists.value.firstOrNull { it.id == id } ?: return@launch
            if (list.subscriptionUrl.isNullOrBlank()) {
                showTransientStatus("Bộ lọc này không có URL để cập nhật")
                return@launch
            }
            _loadingMessage.value = "Đang tải ${list.name}…"
            val result = withContext(Dispatchers.IO) { engine.downloadList(list) }
            showTransientStatus(result.message)
            if (result.ok) {
                applyDownloadResult(list.id, result)
                pushListsToEngine()
            } else {
                applyFailure(list.id, result.message)
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
                showTransientStatus("Không có bộ lọc nào để cập nhật")
                return@launch
            }
            _loadingMessage.value = "Đang cập nhật ${targets.size} bộ lọc…"
            var failures = 0
            for (list in targets) {
                val result = withContext(Dispatchers.IO) { engine.downloadList(list) }
                if (result.ok) {
                    applyDownloadResult(list.id, result)
                } else {
                    failures++
                    applyFailure(list.id, result.message)
                }
            }
            showTransientStatus(
                when (failures) {
                    0 -> "Đã cập nhật ${targets.size} bộ lọc"
                    else -> "Cập nhật xong, $failures danh sách bị lỗi"
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
                showTransientStatus(it)
                return@launch
            }
            if (_filterLists.value.any {
                    it.subscriptionUrl?.equals(trimmedUrl, ignoreCase = true) == true
                }
            ) {
                showTransientStatus("URL này đã có trong danh sách bộ lọc")
                return@launch
            }
            val list = FilterList(
                id = "sub_${System.currentTimeMillis()}",
                name = name.ifBlank { trimmedUrl.substringAfter("//").take(40) },
                description = "Bộ lọc tùy chỉnh của bạn",
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
            _loadingMessage.value = "Đang tải ${list.name}…"
            val result = withContext(Dispatchers.IO) { engine.downloadList(list) }
            showTransientStatus(result.message)
            if (result.ok) {
                applyDownloadResult(list.id, result)
                _filterLists.update { lists ->
                    lists.map { if (it.id == list.id) it.copy(isEnabled = true) else it }
                }
            } else {
                // Keep the (now disabled) row with its reason so the list can
                // be retried/edited without guessing what went wrong.
                applyFailure(list.id, result.message)
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
                showTransientStatus("Không đọc được tệp đã chọn")
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
                name = displayName?.take(60)?.takeIf { it.isNotBlank() } ?: "Bộ lọc từ tệp",
                description = "Bộ lọc tùy chỉnh từ tệp trong máy",
                ruleCount = 0,
                isEnabled = true,
                category = "custom",
                version = "standard",
                groupId = "custom",
                isUserAdded = true,
            )
            val state = withContext(Dispatchers.IO) { engine.saveListText(list.id, text) }
            if (state == null) {
                showTransientStatus("Lỗi ghi tệp: không lưu được bộ lọc")
                return@launch
            }
            _filterLists.update {
                it + list.copy(
                    ruleCount = state.lineCount.toInt(),
                    lastUpdatedText = "Vừa nhập",
                    version = state.version ?: "",
                    format = state.detectedFormat ?: list.format,
                )
            }
            saveFilterChoices()
            pushListsToEngine()
            showTransientStatus("Đã thêm ${list.name} (${state.lineCount} quy tắc)")
        }
    }

    /**
     * Writes settings + filter choices to a SAF document.
     *
     * The file is plain JSON on purpose: it can be inspected, moved to a
     * desktop port and restored without any Android-specific container.
     */
    suspend fun exportBackup(uriText: String): BackupResult {
        val payload = BackupCodec.encode(
            settings = settingsPrefs.backupJson(),
            filters = prefs.backupJson(),
        )
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
            BackupResult(true, "Đã xuất bản sao lưu")
        } else {
            BackupResult(false, "Không ghi được tệp sao lưu")
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
        } ?: return BackupResult(false, "Không đọc được tệp đã chọn")
        if (bytes.size > MAX_BACKUP_BYTES) {
            return BackupResult(false, "Tệp quá lớn để là bản sao lưu AdFree")
        }
        val raw = String(bytes, Charsets.UTF_8)
        val payload = BackupCodec.decode(raw)
            ?: return BackupResult(false, "Tệp không phải bản sao lưu AdFree hợp lệ")

        val previousSettings = settingsPrefs.backupJson()
        if (!settingsPrefs.restoreBackup(payload.settings)) {
            return BackupResult(false, "Không lưu được cài đặt; bản sao lưu chưa được áp dụng")
        }
        if (!prefs.restoreBackup(payload.filters)) {
            if (previousSettings != null) {
                settingsPrefs.restoreBackup(previousSettings)
            } else {
                settingsPrefs.restoreBackup(JSONObject())
            }
            return BackupResult(false, "Không lưu được bộ lọc; đã giữ cài đặt cũ")
        }
        reloadAfterRestore()
        return BackupResult(
            true,
            "Đã khôi phục cài đặt và bộ lọc; bật lại VPN nếu cần áp dụng bộ lọc app",
        )
    }

    /** Rebuilds every in-memory flow after a restore wrote new blobs. */
    private fun reloadAfterRestore() {
        _dnsProviders.value = defaultDnsProviders()
        loadSettings()
        loadFilterState()
        loadInstalledApps()
        loadScriptsState()
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
                    showTransientStatus(it)
                    return@launch
                }
                if (_filterLists.value.any {
                        it.id != id && it.subscriptionUrl?.equals(url, ignoreCase = true) == true
                    }
                ) {
                    showTransientStatus("URL này đã có trong danh sách bộ lọc")
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
            showTransientStatus("Đã cập nhật $name")
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
                _loadingMessage.value = "Đang tải ${list.name}…"
                val result = withContext(Dispatchers.IO) { engine.downloadList(list) }
                if (result.ok) applyDownloadResult(list.id, result)
            }
            saveFilterChoices()
            pushListsToEngine()
            showTransientStatus("Đã khôi phục bộ lọc mặc định")
        }
    }

    /** Persists the user's choices: enabled catalogue ids, custom lists, user rules. */
    private fun saveFilterChoices() {
        val lists = _filterLists.value
        prefs.saveEnabledCatalogIds(
            lists.filter { it.catalogId != null && it.isEnabled }.mapNotNull { it.catalogId }.toSet()
        )
        prefs.saveCustomFilters(
            lists.filter { it.isUserAdded }.map {
                StoredFilter(
                    id = it.id,
                    name = it.name,
                    url = it.subscriptionUrl.orEmpty(),
                    format = it.format,
                    enabled = it.isEnabled,
                    homepage = it.homepage,
                    trusted = it.trusted,
                )
            }
        )
        lists.firstOrNull { it.isCustom }?.let { prefs.saveUserRules(it.customRules) }
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
                    list.copy(lastError = "Máy không đọc được tệp — $message")
                }
            }
        }
    }

    // ------------------------------------------------------------ app firewall

    /** Read installed apps through PackageManager: the firewall is real data now. */
    fun loadInstalledApps() {
        scope.launch {
            val apps = withContext(Dispatchers.IO) { readInstalledApps() }
            _appFirewallRules.value = apps
            // The persisted exclusions must reach the tunnel before the user
            // opens the Apps tab; otherwise a restart silently re-enables
            // filtering for every excluded app.
            pushAppRouting()
        }
    }

    private fun readInstalledApps(): List<AppFirewallRule> {
        val overrides = settingsPrefs.appFirewall().associateBy { it.packageName }
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
                val saved = overrides[info.packageName]
                AppFirewallRule(
                    packageName = info.packageName,
                    appName = pm.getApplicationLabel(info).toString(),
                    isCellularAllowed = saved?.cellular ?: true,
                    isWifiAllowed = saved?.wifi ?: true,
                    isFilterRouted = saved?.filtered ?: true,
                    isHttpsFiltered = saved?.https ?: true,
                    blockWhenScreenOff = saved?.screenOff ?: false,
                    category = appCategory(info),
                )
            }
            .sortedBy { it.appName.lowercase() }
            .take(MAX_APPS_SHOWN)
            .toList()
    }

    private fun appCategory(info: ApplicationInfo): String {
        val pm = context.packageManager
        return try {
            val category = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                pm.getApplicationInfo(info.packageName, 0).category
            } else {
                ApplicationInfo.CATEGORY_UNDEFINED
            }
            when (category) {
                ApplicationInfo.CATEGORY_GAME -> "Trò chơi"
                ApplicationInfo.CATEGORY_SOCIAL -> "Mạng xã hội"
                ApplicationInfo.CATEGORY_VIDEO -> "Đa phương tiện"
                ApplicationInfo.CATEGORY_AUDIO -> "Âm thanh"
                ApplicationInfo.CATEGORY_NEWS -> "Tin tức"
                ApplicationInfo.CATEGORY_MAPS -> "Bản đồ"
                ApplicationInfo.CATEGORY_PRODUCTIVITY -> "Năng suất"
                ApplicationInfo.CATEGORY_IMAGE -> "Hình ảnh"
                else -> "Ứng dụng cài đặt"
            }
        } catch (_: Exception) {
            "Ứng dụng cài đặt"
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
     * when the list is rebuilt after a restart, so the blob stays small.
     */
    private fun saveAppFirewallRules() {
        val overrides = _appFirewallRules.value.mapNotNull { app ->
            if (app.isCellularAllowed && app.isWifiAllowed &&
                app.isFilterRouted && app.isHttpsFiltered && !app.blockWhenScreenOff
            ) {
                null
            } else {
                StoredAppFirewall(
                    packageName = app.packageName,
                    cellular = app.isCellularAllowed,
                    wifi = app.isWifiAllowed,
                    filtered = app.isFilterRouted,
                    screenOff = app.blockWhenScreenOff,
                    https = app.isHttpsFiltered,
                )
            }
        }
        settingsPrefs.saveAppFirewall(overrides)
    }

    /**
     * Loads the userscript list: catalogue entries first, then anything the
     * user added. Bodies live under `filesDir/scripts/`, so nothing is ever
     * re-downloaded on a restart.
     */
    fun loadScriptsState() {
        scope.launch {
            val stored = prefs.scripts()
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
                    description = entry.description,
                    url = entry.url,
                    // Built-in scripts run unless the user turned them off;
                    // catalogue downloads wait to be asked for.
                    isEnabled = state?.enabled ?: entry.builtin,
                    sizeBytes = asset?.sizeBytes ?: 0,
                    lastUpdatedText = asset?.let { engine.dateText(it.modifiedMs) } ?: "Chưa tải",
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
                    lastUpdatedText = asset?.let { engine.dateText(it.modifiedMs) } ?: "Chưa tải",
                    isUserAdded = true,
                    metadata = scriptMetadata(state.id, asset),
                )
            }
            _userscripts.value = scripts
            _scriptsMasterEnabled.value = prefs.scriptsMasterEnabled()
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
        prefs.saveScriptsMasterEnabled(enabled)
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
                        showTransientStatus("Không tìm thấy nội dung ${script.name}")
                        nextEnabled = false
                    } else {
                        _loadingMessage.value = "Đang tải ${script.name}…"
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
                        error = e.message?.take(160) ?: "Không tải được kho tiện ích",
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
                        error = e.message?.take(160) ?: "Không tải thêm được tiện ích",
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
            return parseGreasyForkScripts(body)
        }
    }

    /** Adds a userscript by URL and fetches its body right away. */
    fun addScript(
        name: String,
        url: String,
        description: String = "Tiện ích tùy chỉnh của bạn",
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
                    showTransientStatus("${existing.name} đã có trong danh sách")
                }
                return@launch
            }
            val id = "script_${System.currentTimeMillis()}"
            val script = UserScriptInfo(
                id = id,
                name = name.ifBlank {
                    trimmed.substringAfterLast('/').take(40).ifBlank { "Tiện ích" }
                },
                description = description.trim().take(300).ifEmpty { "Tiện ích tùy chỉnh của bạn" },
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
                    showTransientStatus("${script.name} đã có trong danh sách")
                }
                return@launch
            }
            _loadingMessage.value = "Đang tải ${script.name}…"
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
            _loadingMessage.value = "Đang tải ${script.name}…"
            val result = downloadScriptBody(script)
            showTransientStatus(result.message)
            saveScripts()
            pushScriptsToCore()
        }
    }

    private data class ScriptDownloadResult(val ok: Boolean, val message: String)

    /** Downloads one script body to the store and reports whether it is usable. */
    private suspend fun downloadScriptBody(script: UserScriptInfo): ScriptDownloadResult {
        if (script.url.isBlank()) {
            return ScriptDownloadResult(false, "Tiện ích này không có URL")
        }
        val outcome = withContext(Dispatchers.IO) { engine.scriptFetch(script.id, script.url) }
        if (!outcome.ok) {
            return ScriptDownloadResult(
                false,
                "Không tải được ${script.name}: ${outcome.message}",
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
            "Đã tải ${script.name} (${outcome.sizeBytes / 1024} KB)",
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
                showTransientStatus("Không đọc được tệp đã chọn")
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
            val id = "script_local_${System.currentTimeMillis()}"
            val script = UserScriptInfo(
                id = id,
                name = base,
                description = "Tiện ích tùy chỉnh từ tệp trong máy",
                url = "",
                isEnabled = false,
                isUserAdded = true,
            )
            val updated = _userscripts.updateAndGet { list -> if (list.any { it.id == id }) list else list + script }
            if (updated.none { it.id == id }) {
                showTransientStatus("$base đã có trong danh sách")
                return@launch
            }
            val state = withContext(Dispatchers.IO) { engine.scriptSave(id, text) }
            if (state == null) {
                showTransientStatus("Lỗi ghi tệp: không lưu được tiện ích")
                return@launch
            }
            _userscripts.update { list ->
                list.map {
                    if (it.id == id) {
                        it.copy(
                            sizeBytes = state.sizeBytes,
                            lastUpdatedText = "Vừa nhập",
                            isEnabled = true,
                            metadata = parseUserScriptMetadata(text),
                        )
                    } else it
                }
            }
            saveScripts()
            pushScriptsToCore()
            showTransientStatus("Đã thêm ${base}")
        }
    }

    /** Creates a new userscript from pasted text (no URL). */
    fun createScript(name: String, text: String) {
        scope.launch {
            val trimmed = text.trim()
            if (trimmed.isBlank()) {
                showTransientStatus("Nội dung không được trống")
                return@launch
            }
            val displayName = name.trim().ifBlank { "Tiện ích tùy chỉnh" }.take(60)
            val id = "script_custom_${System.currentTimeMillis()}"
            val script = UserScriptInfo(
                id = id,
                name = displayName,
                description = "Tiện ích tạo từ trình soạn thảo",
                url = "",
                isEnabled = false,
                isUserAdded = true,
            )
            _userscripts.update { list -> list + script }
            val state = withContext(Dispatchers.IO) { engine.scriptSave(id, trimmed) }
            if (state == null) {
                showTransientStatus("Lỗi lưu tiện ích")
                _userscripts.update { list -> list.filter { it.id != id } }
                return@launch
            }
            _userscripts.update { list ->
                list.map {
                    if (it.id == id) {
                        it.copy(
                            sizeBytes = state.sizeBytes,
                            lastUpdatedText = "Vừa tạo",
                            isEnabled = true,
                            metadata = parseUserScriptMetadata(trimmed),
                        )
                    } else it
                }
            }
            saveScripts()
            pushScriptsToCore()
            showTransientStatus("Đã tạo $displayName")
        }
    }

    /** Overwrites an existing user-added script body (edit source). */
    fun updateScriptText(id: String, name: String, text: String) {
        scope.launch {
            val script = _userscripts.value.firstOrNull { it.id == id } ?: return@launch
            if (!script.isUserAdded) return@launch
            val trimmed = text.trim()
            if (trimmed.isBlank()) {
                showTransientStatus("Nội dung không được trống")
                return@launch
            }
            val displayName = name.trim().ifBlank { script.name }.take(60)
            val state = withContext(Dispatchers.IO) { engine.scriptSave(id, trimmed) }
            if (state == null) {
                showTransientStatus("Lỗi lưu tiện ích")
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
                            lastUpdatedText = "Vừa sửa",
                            metadata = parseUserScriptMetadata(trimmed),
                        )
                    } else it
                }
            }
            saveScripts()
            pushScriptsToCore()
            showTransientStatus("Đã cập nhật $displayName")
        }
    }

    private fun saveScripts() {
        prefs.saveScripts(
            _userscripts.value.map {
                StoredScript(it.id, it.name, it.description, it.url, it.isEnabled)
            }
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

    /**
     * Push the excluded-app list to the core. VpnService re-reads it when
     * it builds the tunnel next time.
     */
    fun pushAppRouting() {
        val rules = _appFirewallRules.value
        routedExclusions.clear()
        routedExclusions += rules
            .filterNot { it.isFilterRouted }
            .map { it.packageName }
        // Per-app HTTPS filtering is read at connection time, so this applies
        // to new flows without rebuilding the tunnel.
        engine.setHttpsSkipApps(
            rules.filterNot { it.isHttpsFiltered }.map { it.packageName }
        )
        // The network/screen-off restrictions are enforced by the core: apps
        // outside the tunnel are not seen there, but the lists are harmless
        // for them and keep the mapping in one place.
        engine.setAppNetworkPolicy(
            cellularBlocked = rules.filterNot { it.isCellularAllowed }.map { it.packageName },
            wifiBlocked = rules.filterNot { it.isWifiAllowed }.map { it.packageName },
            screenOffBlocked = rules.filter { it.blockWhenScreenOff }.map { it.packageName },
        )
    }

    /** Apps kept out of the tunnel (read by VpnService during establish). */
    fun excludedPackages(): List<String> = routedExclusions

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

        /** Apps excluded from the tunnel (set before establish). */
        private val routedExclusions: MutableList<String> = mutableListOf()

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

        private fun defaultDnsProviders() = listOf(
            DnsProvider("adguard_default", "AdGuard DNS", "94.140.14.14", ProtocolType.DNS_UDP, "Chặn quảng cáo & tracker mặc định của AdGuard", pingMs = 12),
            DnsProvider("adguard_family", "AdGuard Family", "94.140.15.16", ProtocolType.DNS_UDP, "Chặn nội dung người lớn, bật SafeSearch", pingMs = 14),
            DnsProvider("cloudflare", "Cloudflare 1.1.1.1", "1.1.1.1", ProtocolType.DNS_UDP, "Nhanh, riêng tư, không ghi log", pingMs = 8),
            DnsProvider("quad9", "Quad9", "9.9.9.9", ProtocolType.DNS_UDP, "Chặn domain độc hại theo dữ liệu IBM X-Force", pingMs = 16),
            DnsProvider("google", "Google DNS", "8.8.8.8", ProtocolType.DNS_UDP, "Resolver toàn cầu", pingMs = 11),
        )
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
internal fun parseGreasyForkScripts(json: String): List<UserScriptStoreItem> {
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
            name = obj.cleanString("name").ifEmpty { "Tiện ích Greasy Fork" },
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
