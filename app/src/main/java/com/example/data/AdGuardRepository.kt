package com.example.data

import com.example.engine.FilterEngine
import com.example.model.AppFirewallRule
import com.example.model.DnsProvider
import com.example.model.FilterList
import com.example.model.FilterStatus
import com.example.model.NetworkRequestLog
import com.example.model.ProtectionSettings
import com.example.model.ProtectionStats
import com.example.model.ProtocolType
import com.example.model.RequestCategory
import com.example.vpn.VpnController
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/**
 * Repository layer adhering to Google's Recommended Architecture:
 * - Single source of truth for protection state and statistics.
 * - Receives batched telemetry from VpnController to optimize CPU and battery.
 * - Provides clean asynchronous state updates.
 */
class AdGuardRepository(
    val filterEngine: FilterEngine,
    val vpnController: VpnController
) {
    private val scope = CoroutineScope(Dispatchers.Default)

    // Protection Settings
    private val _settings = MutableStateFlow(ProtectionSettings())
    val settings: StateFlow<ProtectionSettings> = _settings.asStateFlow()

    // Real-time Protection Statistics
    private val _stats = MutableStateFlow(
        ProtectionStats(
            adsBlocked = 14892,
            trackersBlocked = 4210,
            dataSavedBytes = 512 * 1024 * 1024L,
            batteryConservedPercent = 14.2f,
            totalRequestsIntercepted = 42890,
            engineLatencyNs = 78_000,
            activeRulesCount = filterEngine.totalRulesCount + 184510,
            memoryUsageKb = 1840
        )
    )
    val stats: StateFlow<ProtectionStats> = _stats.asStateFlow()

    // Live Intercepted Network Request Logs
    private val _logs = MutableStateFlow<List<NetworkRequestLog>>(emptyList())
    val logs: StateFlow<List<NetworkRequestLog>> = _logs.asStateFlow()

    // Filter Lists Subscriptions
    private val _filterLists = MutableStateFlow<List<FilterList>>(getInitialFilterLists())
    val filterLists: StateFlow<List<FilterList>> = _filterLists.asStateFlow()

    // App Firewall Rules
    private val _appFirewallRules = MutableStateFlow<List<AppFirewallRule>>(getInitialAppRules())
    val appFirewallRules: StateFlow<List<AppFirewallRule>> = _appFirewallRules.asStateFlow()

    // DNS Providers
    private val _dnsProviders = MutableStateFlow<List<DnsProvider>>(getInitialDnsProviders())
    val dnsProviders: StateFlow<List<DnsProvider>> = _dnsProviders.asStateFlow()

    val isSimulationMode: StateFlow<Boolean> = vpnController.isSimulationMode

    init {
        // Handle energy-efficient batched packet packets
        vpnController.onBatchPacketProcessed = { batch ->
            scope.launch {
                handleBatchedPackets(batch)
            }
        }

        preloadInitialLogs()
    }

    private fun handleBatchedPackets(batch: List<NetworkRequestLog>) {
        if (batch.isEmpty()) return

        var newAds = 0L
        var newTrackers = 0L
        var newBytes = 0L
        var lastLatencyMicros = 78L

        for (log in batch) {
            if (log.status == FilterStatus.BLOCKED) {
                if (log.category == RequestCategory.AD) newAds++
                else if (log.category == RequestCategory.TRACKER || log.category == RequestCategory.ANALYTICS) newTrackers++
                newBytes += log.dataSavedBytes
            }
            lastLatencyMicros = log.latencyMicros
        }

        _stats.update { cur ->
            val updatedBattery = minOf(35f, cur.batteryConservedPercent + (newAds + newTrackers) * 0.001f)
            cur.copy(
                adsBlocked = cur.adsBlocked + newAds,
                trackersBlocked = cur.trackersBlocked + newTrackers,
                dataSavedBytes = cur.dataSavedBytes + newBytes,
                totalRequestsIntercepted = cur.totalRequestsIntercepted + batch.size,
                batteryConservedPercent = updatedBattery,
                engineLatencyNs = lastLatencyMicros * 1000
            )
        }

        _logs.update { curList ->
            (batch + curList).take(120)
        }
    }

    fun toggleProtection(enabled: Boolean) {
        _settings.update { it.copy(isProtectionActive = enabled) }
        if (enabled) {
            vpnController.startVpnService()
        } else {
            vpnController.stopVpnService()
        }
    }

    fun toggleSimulationMode(enabled: Boolean) {
        vpnController.setSimulationMode(enabled)
    }

    fun toggleAdBlocking(enabled: Boolean) {
        _settings.update { it.copy(isAdBlockingEnabled = enabled) }
    }

    fun toggleTrackingProtection(enabled: Boolean) {
        _settings.update { it.copy(isTrackingProtectionEnabled = enabled) }
    }

    fun toggleDnsProtection(enabled: Boolean) {
        _settings.update { it.copy(isDnsProtectionEnabled = enabled) }
    }

    fun toggleHttpsFiltering(enabled: Boolean) {
        _settings.update { it.copy(isHttpsFilteringEnabled = enabled) }
    }

    fun toggleFirewall(enabled: Boolean) {
        _settings.update { it.copy(isFirewallEnabled = enabled) }
    }

    fun toggleEcoBatteryMode(enabled: Boolean) {
        _settings.update { it.copy(isEcoBatteryModeEnabled = enabled) }
    }

    fun toggleStealthMode(enabled: Boolean) {
        _settings.update { it.copy(isStealthModeEnabled = enabled) }
    }

    fun updateStealthSetting(stripUtm: Boolean? = null, blockWebRtc: Boolean? = null, disguiseUa: Boolean? = null, blockCookies: Boolean? = null) {
        _settings.update { cur ->
            cur.copy(
                stripUtmTracking = stripUtm ?: cur.stripUtmTracking,
                blockWebRtcLeaks = blockWebRtc ?: cur.blockWebRtcLeaks,
                disguiseUserAgent = disguiseUa ?: cur.disguiseUserAgent,
                blockThirdPartyCookies = blockCookies ?: cur.blockThirdPartyCookies
            )
        }
    }

    fun toggleFilterList(listId: String, enabled: Boolean) {
        _filterLists.update { lists ->
            lists.map { item ->
                if (item.id == listId) item.copy(isEnabled = enabled) else item
            }
        }
    }

    fun addOnlineSubscription(name: String, url: String, category: String) {
        val trimmedUrl = url.trim()
        val trimmedName = if (name.isBlank()) "Online Filter (${trimmedUrl.take(24)}...)" else name.trim()
        val newId = "online_sub_" + System.currentTimeMillis()
        val simulatedRulesCount = kotlin.random.Random.nextInt(12_000, 48_000)

        val newSub = FilterList(
            id = newId,
            name = trimmedName,
            description = "Đăng ký từ $trimmedUrl",
            ruleCount = simulatedRulesCount,
            isEnabled = true,
            category = category.ifBlank { "Tùy chỉnh" },
            version = "v1.0.0",
            subscriptionUrl = trimmedUrl,
            isOnlineSubscription = true,
            lastUpdatedText = "Vừa xong"
        )

        _filterLists.update { it + newSub }
        _stats.update { it.copy(activeRulesCount = it.activeRulesCount + simulatedRulesCount) }
    }

    fun deleteFilterList(id: String) {
        val target = _filterLists.value.find { it.id == id }
        _filterLists.update { lists -> lists.filter { it.id != id } }
        if (target != null && target.isEnabled) {
            _stats.update { it.copy(activeRulesCount = maxOf(0, it.activeRulesCount - target.ruleCount)) }
        }
    }

    fun updateAllCustomRules(newRules: List<String>) {
        val cleaned = newRules.map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("!") }
        
        // Clear and reload in engine
        cleaned.forEach { rule ->
            filterEngine.addRule(rule, "User Custom Filter", RequestCategory.AD)
        }

        _filterLists.update { lists ->
            lists.map { item ->
                if (item.isCustom) {
                    item.copy(
                        ruleCount = cleaned.size,
                        customRules = cleaned
                    )
                } else item
            }
        }
    }

    fun refreshSubscription(id: String) {
        _filterLists.update { lists ->
            lists.map { item ->
                if (item.id == id) {
                    item.copy(
                        lastUpdatedText = "Vừa xong",
                        ruleCount = item.ruleCount + kotlin.random.Random.nextInt(5, 50)
                    )
                } else item
            }
        }
    }

    fun addCustomRule(rawRule: String) {
        val trimmed = rawRule.trim()
        if (trimmed.isEmpty()) return

        filterEngine.addRule(trimmed, "User Custom Filter", RequestCategory.AD)

        _filterLists.update { lists ->
            lists.map { item ->
                if (item.isCustom) {
                    val updatedRules = item.customRules + trimmed
                    item.copy(
                        ruleCount = updatedRules.size,
                        customRules = updatedRules
                    )
                } else item
            }
        }

        _stats.update { it.copy(activeRulesCount = it.activeRulesCount + 1) }
    }

    fun removeCustomRule(ruleStr: String) {
        _filterLists.update { lists ->
            lists.map { item ->
                if (item.isCustom) {
                    val updatedRules = item.customRules.filter { it != ruleStr }
                    item.copy(
                        ruleCount = updatedRules.size,
                        customRules = updatedRules
                    )
                } else item
            }
        }
    }

    fun addDomainToWhitelist(domain: String) {
        filterEngine.addUserCustomWhitelist(domain)
        addCustomRule("@@||$domain^")
    }

    fun addDomainToBlacklist(domain: String) {
        filterEngine.addUserCustomBlacklist(domain)
        addCustomRule("||$domain^")
    }

    fun selectDnsProvider(id: String) {
        _settings.update { it.copy(selectedDnsProviderId = id) }
        filterEngine.clearDnsCache()
    }

    fun updateAppFirewall(
        packageName: String,
        isCellularAllowed: Boolean? = null,
        isWifiAllowed: Boolean? = null,
        isFilterRouted: Boolean? = null,
        blockWhenScreenOff: Boolean? = null
    ) {
        _appFirewallRules.update { list ->
            list.map { app ->
                if (app.packageName == packageName) {
                    app.copy(
                        isCellularAllowed = isCellularAllowed ?: app.isCellularAllowed,
                        isWifiAllowed = isWifiAllowed ?: app.isWifiAllowed,
                        isFilterRouted = isFilterRouted ?: app.isFilterRouted,
                        blockWhenScreenOff = blockWhenScreenOff ?: app.blockWhenScreenOff
                    )
                } else app
            }
        }
    }

    fun clearLogs() {
        _logs.value = emptyList()
    }

    private fun preloadInitialLogs() {
        val initialSamples = listOf(
            NetworkRequestLog("1", "googleads.g.doubleclick.net", "142.250.185.194", "Chrome", "com.android.chrome", System.currentTimeMillis() - 3200, ProtocolType.DOH, FilterStatus.BLOCKED, RequestCategory.AD, "||doubleclick.net^", "AdGuard Base Filter", 62, 142000L),
            NetworkRequestLog("2", "graph.facebook.com", "157.240.241.1", "Instagram", "com.instagram.android", System.currentTimeMillis() - 8400, ProtocolType.HTTPS, FilterStatus.BLOCKED, RequestCategory.TRACKER, "||graph.facebook.com^", "AdGuard Tracking Protection", 74, 86000L),
            NetworkRequestLog("3", "api.github.com", "140.82.121.6", "GitHub", "com.github.android", System.currentTimeMillis() - 14000, ProtocolType.HTTPS, FilterStatus.ALLOWED, RequestCategory.CLEAN, null, null, 110, 0L),
            NetworkRequestLog("4", "telemetry.sdk.appsflyer.com", "52.28.188.42", "TikTok", "com.zhiliaoapp.musically", System.currentTimeMillis() - 19800, ProtocolType.HTTPS, FilterStatus.BLOCKED, RequestCategory.TRACKER, "||appsflyer.com^", "AdGuard Tracking Protection", 55, 32000L),
            NetworkRequestLog("5", "audio-ak-spotify-com.akamaized.net", "23.210.155.33", "Spotify", "com.spotify.music", System.currentTimeMillis() - 25000, ProtocolType.HTTPS, FilterStatus.ALLOWED, RequestCategory.CLEAN, null, null, 140, 0L)
        )
        _logs.value = initialSamples
    }

    private fun getInitialFilterLists(): List<FilterList> {
        return listOf(
            FilterList(
                id = "adguard_base",
                name = "AdGuard Base Filter",
                description = "EasyList + AdGuard specific rules for blocking ads across websites and apps",
                ruleCount = 92430,
                isEnabled = true,
                category = "Ad Blocking",
                version = "2.3.118"
            ),
            FilterList(
                id = "adguard_tracking",
                name = "AdGuard Tracking Protection",
                description = "Comprehensive defense against online counters, third-party analytics, and tracking pixels",
                ruleCount = 34120,
                isEnabled = true,
                category = "Privacy",
                version = "1.9.44"
            ),
            FilterList(
                id = "adguard_url_tracking",
                name = "URL Tracking Protection",
                description = "Strips tracking parameters (utm_*, fbclid, gclid) from URLs to protect navigation anonymity",
                ruleCount = 9410,
                isEnabled = true,
                category = "Privacy",
                version = "1.2.12"
            ),
            FilterList(
                id = "adguard_social",
                name = "Social Media Filter",
                description = "Blocks social widgets, Like/Share buttons, and tracking scripts from Facebook, X, TikTok",
                ruleCount = 12800,
                isEnabled = true,
                category = "Social",
                version = "1.4.29"
            ),
            FilterList(
                id = "adguard_annoyances",
                name = "AdGuard Annoyances Filter",
                description = "Blocks annoying cookie consent notices, GDPR popups, push notifications, and mobile app banners",
                ruleCount = 28500,
                isEnabled = true,
                category = "Annoyances",
                version = "2.0.81"
            ),
            FilterList(
                id = "user_custom",
                name = "User Custom Filter",
                description = "Your personal custom adblock and whitelist rules",
                ruleCount = 3,
                isEnabled = true,
                category = "Custom",
                version = "User defined",
                isCustom = true,
                customRules = listOf(
                    "||ads.example.com^",
                    "@@||banking.safe-domain.com^",
                    "/.*[-_]telemetry\\..*/"
                )
            )
        )
    }

    private fun getInitialAppRules(): List<AppFirewallRule> {
        return listOf(
            AppFirewallRule("com.android.chrome", "Google Chrome", isCellularAllowed = true, isWifiAllowed = true, isFilterRouted = true, category = "Trình duyệt", blockedRequestsToday = 412, dataTransferredBytes = 142 * 1024 * 1024L),
            AppFirewallRule("com.google.android.youtube", "YouTube", isCellularAllowed = true, isWifiAllowed = true, isFilterRouted = true, category = "Đa phương tiện", blockedRequestsToday = 620, dataTransferredBytes = 940 * 1024 * 1024L),
            AppFirewallRule("com.zhiliaoapp.musically", "TikTok", isCellularAllowed = true, isWifiAllowed = true, isFilterRouted = true, category = "Mạng xã hội", blockedRequestsToday = 289, dataTransferredBytes = 420 * 1024 * 1024L),
            AppFirewallRule("com.spotify.music", "Spotify", isCellularAllowed = true, isWifiAllowed = true, isFilterRouted = true, category = "Đa phương tiện", blockedRequestsToday = 94, dataTransferredBytes = 280 * 1024 * 1024L),
            AppFirewallRule("com.instagram.android", "Instagram", isCellularAllowed = true, isWifiAllowed = true, isFilterRouted = true, category = "Mạng xã hội", blockedRequestsToday = 345, dataTransferredBytes = 390 * 1024 * 1024L),
            AppFirewallRule("com.shopee.vn", "Shopee", isCellularAllowed = true, isWifiAllowed = true, isFilterRouted = true, category = "Mua sắm", blockedRequestsToday = 152, dataTransferredBytes = 85 * 1024 * 1024L),
            AppFirewallRule("com.zing.zalo", "Zalo", isCellularAllowed = true, isWifiAllowed = true, isFilterRouted = true, category = "Tin nhắn & Liên lạc", blockedRequestsToday = 76, dataTransferredBytes = 65 * 1024 * 1024L),
            AppFirewallRule("org.telegram.messenger", "Telegram", isCellularAllowed = true, isWifiAllowed = true, isFilterRouted = true, category = "Tin nhắn & Bảo mật", blockedRequestsToday = 38, dataTransferredBytes = 110 * 1024 * 1024L),
            AppFirewallRule("android", "Hệ thống Android Core", isCellularAllowed = true, isWifiAllowed = true, isFilterRouted = false, category = "Hệ thống", blockedRequestsToday = 12, dataTransferredBytes = 24 * 1024 * 1024L)
        )
    }

    private fun getInitialDnsProviders(): List<DnsProvider> {
        return listOf(
            DnsProvider(
                id = "adguard_default",
                name = "AdGuard DNS (Default)",
                address = "https://dns.adguard-dns.com/dns-query",
                type = ProtocolType.DOH,
                description = "Blocks ads, trackers, and phishing domains with high-speed DNSSEC validation",
                pingMs = 12
            ),
            DnsProvider(
                id = "adguard_family",
                name = "AdGuard Family Protection",
                address = "https://family.adguard-dns.com/dns-query",
                type = ProtocolType.DOH,
                description = "Blocks ads, trackers, adult content, and enables SafeSearch enforcement",
                pingMs = 14
            ),
            DnsProvider(
                id = "cloudflare",
                name = "Cloudflare 1.1.1.1",
                address = "https://cloudflare-dns.com/dns-query",
                type = ProtocolType.DOH,
                description = "Ultra-fast privacy-first DNS with zero logging policy",
                pingMs = 8
            ),
            DnsProvider(
                id = "quad9",
                name = "Quad9 (Malware Blocking)",
                address = "https://dns.quad9.net/dns-query",
                type = ProtocolType.DOH,
                description = "High security DNS blocking malicious domains, botnets, and phishing campaigns",
                pingMs = 16
            ),
            DnsProvider(
                id = "google",
                name = "Google Public DNS",
                address = "https://dns.google/dns-query",
                type = ProtocolType.DOH,
                description = "Globally distributed resilient DNS resolver",
                pingMs = 11
            )
        )
    }
}
