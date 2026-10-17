package git.shin.adfree.data

import android.content.Context
import android.util.Log
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
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
import git.shin.adfree.model.UserScriptInfo
import git.shin.adfree.model.NetworkRequestLog
import git.shin.adfree.model.ProtectionStats
import git.shin.adfree.model.ProtectionSettings
import git.shin.adfree.model.ProtocolType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.atomic.AtomicLong

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
    private val logIds = AtomicLong(0)

    private val _settings = MutableStateFlow(ProtectionSettings())
    val settings: StateFlow<ProtectionSettings> = _settings.asStateFlow()

    private val _stats = MutableStateFlow(ProtectionStats())
    val stats: StateFlow<ProtectionStats> = _stats.asStateFlow()

    private val _logs = MutableStateFlow<List<NetworkRequestLog>>(emptyList())
    val logs: StateFlow<List<NetworkRequestLog>> = _logs.asStateFlow()

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

    /** User choices that outlive a restart: which lists are on, custom filters, scripts. */
    private val prefs = FilterPreferences(context)

    private val _userscripts = MutableStateFlow<List<UserScriptInfo>>(emptyList())
    val userscripts: StateFlow<List<UserScriptInfo>> = _userscripts.asStateFlow()

    private val _scriptsMasterEnabled = MutableStateFlow(false)
    val scriptsMasterEnabled: StateFlow<Boolean> = _scriptsMasterEnabled.asStateFlow()

    init {
        startStatsPoller()
    }

    // ------------------------------------------------------ polling the engine

    /**
     * One tick every 500ms with the screen on, 2s when off. This is the
     * app's entire UI cost: two atomic reads plus one log decode.
     */
    private fun startStatsPoller() {
        scope.launch {
            var lastLogTs = 0L
            while (true) {
                val snapshot = engine.stats()
                _stats.value = snapshot.toUiStats(engine.isBuilding())
                // Native warnings are buffered natively so the packet threads
                // never do I/O; drain them here or they are lost.
                engine.flushNativeLogLines()
                val events = engine.drainEvents(256)
                if (events.isNotEmpty()) {
                    val entries = mutableListOf<NetworkRequestLog>()
                    for (event in events) {
                        if (event.tsMs == lastLogTs) continue
                        lastLogTs = event.tsMs
                        entries += NetworkRequestLog.from(event, logIds.getAndIncrement())
                    }
                    if (entries.isNotEmpty()) {
                        // Newest first, capped at 300 entries in RAM.
                        _logs.update { current ->
                            (entries.reversed() + current).take(MAX_LOG_ENTRIES)
                        }
                    }
                }
                delay(if (engine.isScreenOff()) 2_000 else 500)
            }
        }
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

    fun toggleHttpsFiltering(enabled: Boolean) =
        _settings.update { it.copy(isHttpsFilteringEnabled = enabled) }

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
    fun toggleBlockDoh(enabled: Boolean) = _settings.update { it.copy(blockDoh = enabled) }
    fun toggleLogAllowed(enabled: Boolean) = _settings.update { it.copy(logAllowedRequests = enabled) }
    fun setBlockMode(mode: DnsBlockMode) = _settings.update { it.copy(blockMode = mode) }

    fun selectDnsProvider(id: String) {
        val provider = _dnsProviders.value.firstOrNull { it.id == id } ?: return
        _settings.update { it.copy(selectedDnsProviderId = id) }
        val (host, port) = provider.hostAndPort() ?: return
        engine.setResolver(host, port)
    }

    fun addCustomDnsProvider(name: String, address: String) {
        val id = "custom_" + System.currentTimeMillis()
        val provider = DnsProvider(
            id = id,
            name = name.ifBlank { address },
            address = address,
            type = if (address.startsWith("https://")) ProtocolType.DNS_DOH else ProtocolType.DNS_UDP,
            description = "Tùy chỉnh",
            isCustom = true,
        )
        _dnsProviders.update { it + provider }
        provider.hostAndPort()?.let { (host, port) -> engine.setResolver(host, port) }
        _settings.update { it.copy(selectedDnsProviderId = id) }
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
                    version = entry.format,
                    isOnlineSubscription = true,
                    subscriptionUrl = entry.url,
                    lastUpdatedText = "Chưa tải",
                    groupId = entry.group.id,
                    format = entry.format,
                    catalogId = entry.id,
                    defaultEnabled = entry.defaultEnabled,
                    homepage = entry.homepage,
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
                    version = stored.format,
                    isOnlineSubscription = stored.url.isNotBlank(),
                    subscriptionUrl = stored.url.ifBlank { null },
                    lastUpdatedText = "Chưa tải",
                    groupId = "custom",
                    format = stored.format,
                    homepage = stored.homepage,
                    isUserAdded = true,
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
                version = "user",
                isCustom = true,
                customRules = rules,
            )

            _filterLists.value = lists
            refreshFilesAndDownload(lists.filterNot { it.isCustom })
            pushListsToEngine()
            saveFilterChoices()
            _loadingMessage.value = null
        }
    }

    /** Recounts files already on disk and downloads the enabled lists without one. */
    private suspend fun refreshFilesAndDownload(lists: List<FilterList>) {
        for (list in lists) {
            val file = engine.listFileFor(list)
            if (file.exists()) {
                applyFileStats(list.id, file)
                continue
            }
            if (!list.isEnabled || list.subscriptionUrl.isNullOrBlank()) continue
            _loadingMessage.value = "Đang tải ${list.name}…"
            val result = withContext(Dispatchers.IO) { engine.downloadList(list) }
            if (result.ok) applyDownloadResult(list.id, result)
        }
    }

    /** Refreshes count/date/version of one list from its file on disk (no network). */
    private suspend fun applyFileStats(listId: String, file: File) {
        val count = withContext(Dispatchers.IO) { engine.countRules(file) }
        val meta = withContext(Dispatchers.IO) { engine.readListMeta(file) }
        _filterLists.update { current ->
            current.map {
                if (it.id == listId) {
                    it.copy(
                        ruleCount = count,
                        lastUpdatedText = meta.updatedText ?: engine.fileDateText(file),
                        version = meta.version ?: it.version,
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
                        version = result.version ?: it.version,
                        format = result.detectedFormat ?: it.format,
                    )
                } else it
            }
        }
    }

    /** Turns one list on or off; enabling downloads it when the file is missing. */
    fun toggleFilterList(listId: String, enabled: Boolean) {
        scope.launch {
            _filterLists.update { lists ->
                lists.map { if (it.id == listId) it.copy(isEnabled = enabled) else it }
            }
            val list = _filterLists.value.firstOrNull { it.id == listId }
            if (enabled && list != null && !list.isCustom && !engine.listFileFor(list).exists() &&
                !list.subscriptionUrl.isNullOrBlank()
            ) {
                _loadingMessage.value = "Đang tải ${list.name}…"
                val result = withContext(Dispatchers.IO) { engine.downloadList(list) }
                showTransientStatus(result.message)
                if (result.ok) applyDownloadResult(list.id, result)
            }
            saveFilterChoices()
            pushListsToEngine()
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
                if (result.ok) applyDownloadResult(list.id, result) else failures++
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
            if (trimmedUrl.isEmpty()) return@launch
            val list = FilterList(
                id = "sub_${System.currentTimeMillis()}",
                name = name.ifBlank { trimmedUrl.substringAfter("//").take(40) },
                description = "Bộ lọc tùy chỉnh của bạn",
                ruleCount = 0,
                isEnabled = true,
                category = "custom",
                version = "standard",
                isOnlineSubscription = true,
                subscriptionUrl = trimmedUrl,
                groupId = "custom",
                isUserAdded = true,
            )
            _filterLists.update { it + list }
            _loadingMessage.value = "Đang tải ${list.name}…"
            val result = withContext(Dispatchers.IO) { engine.downloadList(list) }
            showTransientStatus(result.message)
            if (result.ok) applyDownloadResult(list.id, result)
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
            val file = engine.listFileFor(list)
            val writeFailure = withContext(Dispatchers.IO) {
                runCatching { file.writeText(text) }.exceptionOrNull()
            }
            if (writeFailure != null) {
                showTransientStatus("Lỗi ghi tệp: ${writeFailure.javaClass.simpleName}")
                return@launch
            }
            val meta = engine.parseListMeta(text)
            val count = withContext(Dispatchers.IO) { engine.countRules(file) }
            _filterLists.update {
                it + list.copy(
                    ruleCount = count,
                    lastUpdatedText = "Vừa nhập",
                    version = meta.version ?: "standard",
                    format = meta.format ?: list.format,
                )
            }
            saveFilterChoices()
            pushListsToEngine()
            showTransientStatus("Đã thêm ${list.name} ($count quy tắc)")
        }
    }

    /** Removes a user-added list (catalogue entries are toggled off, not deleted). */
    fun deleteFilterList(id: String) {
        val target = _filterLists.value.firstOrNull { it.id == id } ?: return
        if (!target.isUserAdded) return
        _filterLists.update { lists -> lists.filter { it.id != id } }
        scope.launch {
            withContext(Dispatchers.IO) { runCatching { engine.listFileFor(target).delete() } }
            saveFilterChoices()
            pushListsToEngine()
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
                    !engine.listFileFor(it).exists()
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
                )
            }
        )
        lists.firstOrNull { it.isCustom }?.let { prefs.saveUserRules(it.customRules) }
    }

    fun updateAllCustomRules(newRules: List<String>) {
        scope.launch {
            val cleaned = newRules.map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("!") && !it.startsWith("#") && !it.startsWith("[") }
                .distinct()
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
        val rule = rawRule.trim()
        if (rule.isEmpty() || rule.startsWith("!")) return
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
        _logs.value = emptyList()
        engine.clearEvents()
    }

    fun resetStats() {
        engine.resetStats()
        _logs.value = emptyList()
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
            val file = engine.listFileFor(list)
            if (!file.exists()) return@mapNotNull null
            FilterListBinding(
                id = list.stableId(),
                name = list.name,
                url = list.subscriptionUrl.orEmpty(),
                enabled = true,
                path = file.absolutePath,
                format = if (list.format.equals("hosts", ignoreCase = true)) 1 else 0,
                category = list.categoryIndex(),
                ruleCount = list.ruleCount.toLong(),
                lastError = "",
            )
        }
        val userRules = lists.firstOrNull { it.isCustom }?.customRules.orEmpty()
        engine.setListsAsync(bindings, userRules)
    }

    // ------------------------------------------------------------ app firewall

    /** Read installed apps through PackageManager: the firewall is real data now. */
    fun loadInstalledApps() {
        scope.launch {
            val apps = withContext(Dispatchers.IO) { readInstalledApps() }
            _appFirewallRules.value = apps
        }
    }

    private fun readInstalledApps(): List<AppFirewallRule> {
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
                AppFirewallRule(
                    packageName = info.packageName,
                    appName = pm.getApplicationLabel(info).toString(),
                    isCellularAllowed = true,
                    isWifiAllowed = true,
                    isFilterRouted = true,
                    blockWhenScreenOff = false,
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
    ) {
        _appFirewallRules.update { list ->
            list.map { app ->
                if (app.packageName == packageName) {
                    app.copy(
                        isCellularAllowed = isCellularAllowed ?: app.isCellularAllowed,
                        isWifiAllowed = isWifiAllowed ?: app.isWifiAllowed,
                        isFilterRouted = isFilterRouted ?: app.isFilterRouted,
                        blockWhenScreenOff = blockWhenScreenOff ?: app.blockWhenScreenOff,
                    )
                } else app
            }
        }
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
            for (entry in UserScriptCatalog.scripts) {
                val state = stored.firstOrNull { it.id == entry.id }
                val file = engine.scriptFileFor(entry.id)
                scripts += UserScriptInfo(
                    id = entry.id,
                    name = entry.name,
                    description = entry.description,
                    url = entry.url,
                    isEnabled = state?.enabled ?: false,
                    sizeBytes = file.length(),
                    lastUpdatedText = if (file.exists()) engine.fileDateText(file) else "Chưa tải",
                )
            }
            for (state in stored.filter { s -> UserScriptCatalog.scripts.none { it.id == s.id } }) {
                val file = engine.scriptFileFor(state.id)
                scripts += UserScriptInfo(
                    id = state.id,
                    name = state.name,
                    description = state.description,
                    url = state.url,
                    isEnabled = state.enabled,
                    sizeBytes = file.length(),
                    lastUpdatedText = if (file.exists()) engine.fileDateText(file) else "Chưa tải",
                    isUserAdded = true,
                )
            }
            _userscripts.value = scripts
            _scriptsMasterEnabled.value = prefs.scriptsMasterEnabled()
            pushScriptsToCore()
        }
    }

    fun toggleScriptsMaster(enabled: Boolean) {
        _scriptsMasterEnabled.value = enabled
        prefs.saveScriptsMasterEnabled(enabled)
        pushScriptsToCore()
    }

    fun toggleScript(id: String, enabled: Boolean) {
        scope.launch {
            _userscripts.update { list ->
                list.map { if (it.id == id) it.copy(isEnabled = enabled) else it }
            }
            val script = _userscripts.value.firstOrNull { it.id == id }
            // Catalogue scripts start without a body: enabling one fetches it.
            if (enabled && script != null && script.url.isNotBlank() &&
                !engine.scriptFileFor(script.id).exists()
            ) {
                _loadingMessage.value = "Đang tải ${script.name}…"
                showTransientStatus(downloadScriptBody(script))
            }
            saveScripts()
            pushScriptsToCore()
        }
    }

    /** Adds a userscript by URL and fetches its body right away. */
    fun addScript(name: String, url: String) {
        scope.launch {
            val trimmed = url.trim()
            if (trimmed.isEmpty()) return@launch
            val id = "script_${System.currentTimeMillis()}"
            val script = UserScriptInfo(
                id = id,
                name = name.ifBlank {
                    trimmed.substringAfterLast('/').take(40).ifBlank { "Tiện ích" }
                },
                description = "Tiện ích tùy chỉnh của bạn",
                url = trimmed,
                isEnabled = true,
                isUserAdded = true,
            )
            _userscripts.update { it + script }
            _loadingMessage.value = "Đang tải ${script.name}…"
            showTransientStatus(downloadScriptBody(script))
            saveScripts()
            pushScriptsToCore()
        }
    }

    fun refreshScript(id: String) {
        scope.launch {
            val script = _userscripts.value.firstOrNull { it.id == id } ?: return@launch
            _loadingMessage.value = "Đang tải ${script.name}…"
            showTransientStatus(downloadScriptBody(script))
            saveScripts()
            pushScriptsToCore()
        }
    }

    /** Downloads one script body to disk; returns the result line for the UI. */
    private suspend fun downloadScriptBody(script: UserScriptInfo): String {
        if (script.url.isBlank()) return "Tiện ích này không có URL"
        val fetched = withContext(Dispatchers.IO) { engine.fetchUrl(script.url) }
        if (!fetched.ok || fetched.body == null) {
            return "Không tải được ${script.name}: ${fetched.message}"
        }
        val file = engine.scriptFileFor(script.id)
        val writeFailure = withContext(Dispatchers.IO) {
            runCatching { file.writeText(fetched.body) }.exceptionOrNull()
        }
        if (writeFailure != null) return "Lỗi ghi tệp: ${writeFailure.javaClass.simpleName}"
        _userscripts.update { list ->
            list.map {
                if (it.id == script.id) {
                    it.copy(sizeBytes = file.length(), lastUpdatedText = engine.fileDateText(file))
                } else it
            }
        }
        return "Đã tải ${script.name} (${file.length() / 1024} KB)"
    }

    /** Removes a user-added script (catalogue entries are toggled off, not deleted). */
    fun deleteScript(id: String) {
        val target = _userscripts.value.firstOrNull { it.id == id } ?: return
        if (!target.isUserAdded) return
        _userscripts.update { list -> list.filter { it.id != id } }
        scope.launch {
            withContext(Dispatchers.IO) { runCatching { engine.scriptFileFor(id).delete() } }
            saveScripts()
            pushScriptsToCore()
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
            val file = engine.scriptFileFor(script.id)
            if (!file.exists()) return@mapNotNull null
            ScriptBinding(
                name = script.name,
                body = runCatching { file.readText() }.getOrDefault(""),
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
        routedExclusions.clear()
        routedExclusions += _appFirewallRules.value
            .filterNot { it.isFilterRouted }
            .map { it.packageName }
    }

    /** Apps kept out of the tunnel (read by VpnService during establish). */
    fun excludedPackages(): List<String> = routedExclusions

    fun dismissLoading() {
        _loadingMessage.value = null
    }

    /** The engine's log now lives in memory; there are no fake files. */
    fun filterListsDir(): File = File(context.filesDir, "filters").apply { mkdirs() }

    private companion object {
        private const val TAG = "AdFreeRepo"
        private const val MAX_LOG_ENTRIES = 300
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

        private fun DnsProvider.hostAndPort(): Pair<String, Int>? {
            val address = address.trim()
            val hostPort = when {
                address.startsWith("https://") -> address.removePrefix("https://")
                address.startsWith("http://") -> address.removePrefix("http://")
                address.startsWith("tls://") -> address.removePrefix("tls://")
                else -> address
            }.substringBefore('/').substringAfter('@')
            val host = hostPort.substringBefore(':').substringBefore(']')
            val port = hostPort.substringAfter(':', "").toIntOrNull()
                ?: if (address.startsWith("https")) 443 else 53
            if (host.isBlank()) return null
            return Pair(host, port)
        }

        fun defaultDnsProviders() = listOf(
            DnsProvider("adguard_default", "AdGuard DNS", "94.140.14.14", ProtocolType.DNS_UDP, "Chặn quảng cáo & tracker mặc định của AdGuard", pingMs = 12),
            DnsProvider("adguard_family", "AdGuard Family", "94.140.15.16", ProtocolType.DNS_UDP, "Chặn nội dung người lớn, bật SafeSearch", pingMs = 14),
            DnsProvider("cloudflare", "Cloudflare 1.1.1.1", "1.1.1.1", ProtocolType.DNS_UDP, "Nhanh, riêng tư, không ghi log", pingMs = 8),
            DnsProvider("quad9", "Quad9", "9.9.9.9", ProtocolType.DNS_UDP, "Chặn domain độc hại theo dữ liệu IBM X-Force", pingMs = 16),
            DnsProvider("google", "Google DNS", "8.8.8.8", ProtocolType.DNS_UDP, "Resolver toàn cầu", pingMs = 11),
        )
    }
}
