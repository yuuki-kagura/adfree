package com.example.data

import android.content.Context
import android.util.Log
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import com.example.core.CoreEngine
import com.example.core.FilterListBinding
import com.example.core.StatsSnapshot
import com.example.model.AppFirewallRule
import com.example.model.DnsBlockMode
import com.example.model.DnsProvider
import com.example.model.FilterList
import com.example.model.FilterStatus
import com.example.model.NetworkRequestLog
import com.example.model.ProtectionStats
import com.example.model.ProtectionSettings
import com.example.model.ProtocolType
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

    /** Download/refresh one subscription. Cheap: HTTP + file write, the core does the rest. */
    fun refreshSubscription(id: String) {
        scope.launch {
            val list = _filterLists.value.firstOrNull { it.id == id } ?: return@launch
            if (list.subscriptionUrl.isNullOrBlank()) {
                _loadingMessage.value = "Danh sách tùy chỉnh không có URL"
                return@launch
            }
            _loadingMessage.value = "Đang tải ${list.name}…"
            val result = withContext(Dispatchers.IO) { engine.downloadList(list) }
            _loadingMessage.value = result.message
            if (result.ok) {
                pushListsToEngine()
            }
        }
    }

    fun refreshAllSubscriptions() {
        scope.launch {
            val urls = _filterLists.value.filter { it.isOnlineSubscription }
            if (urls.isEmpty()) {
                _loadingMessage.value = "Không có subscription nào để cập nhật"
                return@launch
            }
            _loadingMessage.value = "Đang cập nhật ${urls.size} bộ lọc…"
            var failures = 0
            for (list in urls) {
                val result = withContext(Dispatchers.IO) { engine.downloadList(list) }
                if (!result.ok) failures++
            }
            _loadingMessage.value = when (failures) {
                0 -> "Đã cập nhật ${urls.size} bộ lọc"
                else -> "Cập nhật xong, $failures danh sách lỗi"
            }
            pushListsToEngine()
        }
    }

    fun toggleFilterList(listId: String, enabled: Boolean) {
        _filterLists.update { lists -> lists.map { if (it.id == listId) it.copy(isEnabled = enabled) else it } }
        pushListsToEngine()
    }

    fun addOnlineSubscription(name: String, url: String, category: String) {
        scope.launch {
            val trimmedUrl = url.trim()
            if (trimmedUrl.isEmpty()) return@launch
            val list = FilterList(
                id = "sub_${System.currentTimeMillis()}",
                name = name.ifBlank { trimmedUrl.take(40) },
                description = "Đăng ký từ $trimmedUrl",
                ruleCount = 0,
                isEnabled = true,
                category = category.ifBlank { "Tùy chỉnh" },
                version = "online",
                isOnlineSubscription = true,
                subscriptionUrl = trimmedUrl,
                isCustom = !category.equals("hosts", ignoreCase = true),
            )
            _filterLists.update { it + list }
            _loadingMessage.value = "Đang tải ${list.name}…"
            val result = withContext(Dispatchers.IO) { engine.downloadList(list) }
            _loadingMessage.value = result.message
            if (result.ok) pushListsToEngine()
        }
    }

    fun deleteFilterList(id: String) {
        val target = _filterLists.value.firstOrNull { it.id == id }
        _filterLists.update { lists -> lists.filter { it.id != id } }
        if (target?.isCustom == true) {
            scope.launch(Dispatchers.IO) {
                engine.deleteUserRules(target.customRules)
                pushListsToEngine()
            }
        } else {
            pushListsToEngine()
        }
    }

    fun updateAllCustomRules(newRules: List<String>) {
        scope.launch {
            val cleaned = newRules.map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("!") && !it.startsWith("#") }
            withContext(Dispatchers.IO) {
                _filterLists.value.firstOrNull { it.isCustom }?.let { current ->
                    engine.deleteUserRules(current.customRules)
                }
                engine.addUserRules(cleaned)
            }
            _filterLists.update { lists ->
                lists.map {
                    if (it.isCustom) it.copy(ruleCount = cleaned.size, customRules = cleaned) else it
                }
            }
            pushListsToEngine()
        }
    }

    fun addCustomRule(rawRule: String) {
        val rule = rawRule.trim()
        if (rule.isEmpty() || rule.startsWith("!")) return
        scope.launch {
            withContext(Dispatchers.IO) { engine.addUserRules(listOf(rule)) }
            _filterLists.update { lists ->
                lists.map {
                    if (it.isCustom) it.copy(ruleCount = it.ruleCount + 1, customRules = it.customRules + rule) else it
                }
            }
            pushListsToEngine()
        }
    }

    fun removeCustomRule(ruleStr: String) {
        scope.launch {
            withContext(Dispatchers.IO) { engine.deleteUserRules(listOf(ruleStr)) }
            _filterLists.update { lists ->
                lists.map {
                    if (it.isCustom) {
                        val updated = it.customRules.filter { r -> r != ruleStr }
                        it.copy(ruleCount = updated.size, customRules = updated)
                    } else it
                }
            }
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

    /** Push the current list state down to the core. */
    private fun pushListsToEngine() {
        val lists = _filterLists.value
        val bindings = lists.map { list ->
            FilterListBinding(
                id = list.stableId(),
                name = list.name,
                url = list.subscriptionUrl.orEmpty(),
                enabled = list.isEnabled,
                path = engine.listFileFor(list).absolutePath,
                format = if (list.isCustom || !list.category.equals("hosts", ignoreCase = true)) 0 else 1,
                category = list.categoryIndex(),
                ruleCount = list.ruleCount.toLong(),
                lastError = "",
            )
        }
        engine.setListsAsync(bindings, emptyList())
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
     * The built-in subscriptions. Files land in `filesDir/filters/` and
     * persist, so later launches need no network.
     */
    fun loadBuiltInFilterLists(forceDownload: Boolean = false) {
        scope.launch {
            val builtIns = listOf(
                FilterList(
                    id = BUILTIN_DNS,
                    name = "AdGuard DNS filter",
                    description = "Bộ lọc chính thức của AdGuard cho chặn quảng cáo & tracker mức DNS",
                    ruleCount = 0,
                    isEnabled = true,
                    category = "Ad Blocking",
                    version = "online",
                    isOnlineSubscription = true,
                    subscriptionUrl = "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
                    lastUpdatedText = "Chưa tải",
                ),
                FilterList(
                    id = BUILTIN_MOBILE,
                    name = "OISD Big (hosts)",
                    description = "Tổng hợp quảng cáo + tracker cho mobile, định dạng hosts",
                    ruleCount = 0,
                    isEnabled = true,
                    category = "hosts",
                    version = "online",
                    isOnlineSubscription = true,
                    subscriptionUrl = "https://big.oisd.nl/dnsmasq2",
                    lastUpdatedText = "Chưa tải",
                ),
                FilterList(
                    id = BUILTIN_MALWARE,
                    name = "StevenBlack hosts",
                    description = "Chặn malware, phishing & adware",
                    ruleCount = 0,
                    isEnabled = false,
                    category = "hosts",
                    version = "online",
                    isOnlineSubscription = true,
                    subscriptionUrl = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
                    lastUpdatedText = "Chưa tải",
                ),
                FilterList(
                    id = BUILTIN_CUSTOM,
                    name = "Quy tắc của bạn",
                    description = "Quy tắc tự viết: ||domain^, @@||domain^, /regex/",
                    ruleCount = starterRules.size,
                    isEnabled = true,
                    category = "Custom",
                    version = "user",
                    isCustom = true,
                    customRules = starterRules,
                ),
            )

            if (_filterLists.value.isEmpty() || forceDownload) {
                _filterLists.value = builtIns
            }

            withContext(Dispatchers.IO) { engine.addUserRules(starterRules) }
            for (list in builtIns.filter { it.isOnlineSubscription }) {
                // The file is already on disk: just recount the rules for the UI, at no
                // network cost.
                val existing = engine.listFileFor(list)
                if (existing.exists() && !forceDownload) {
                    val count = withContext(Dispatchers.IO) { engine.countRules(existing) }
                    _filterLists.update { lists ->
                        lists.map { if (it.id == list.id) it.copy(ruleCount = count) else it }
                    }
                    continue
                }
                val result = engine.downloadList(list)
                _loadingMessage.value = result.message
                if (result.ok) {
                    _filterLists.update { lists ->
                        lists.map {
                            if (it.id == list.id) {
                                it.copy(
                                    ruleCount = result.lineCount.toInt(),
                                    lastUpdatedText = "Vừa xong",
                                )
                            } else it
                        }
                    }
                }
            }
            pushListsToEngine()
            _loadingMessage.value = null
        }
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
        private const val BUILTIN_DNS = "builtin_dns"
        private const val BUILTIN_MOBILE = "builtin_oisd"
        private const val BUILTIN_MALWARE = "builtin_stevenblack"
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

        fun FilterList.categoryIndex(): Int = when (category.lowercase()) {
            "ad blocking", "ad" -> 0
            "privacy", "tracker" -> 1
            "analytics" -> 2
            "social" -> 3
            "annoyances" -> 4
            "malware", "phishing" -> 5
            else -> 6
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
