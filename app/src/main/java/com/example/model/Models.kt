package com.example.model

enum class FilterStatus {
    BLOCKED,
    ALLOWED,
    WHITELISTED
}

enum class RequestCategory(val label: String) {
    AD("Advertising"),
    TRACKER("Tracker & Telemetry"),
    ANALYTICS("Analytics"),
    SOCIAL("Social Widget"),
    CLEAN("Legitimate Traffic"),
    SUSPICIOUS("Suspicious / Threat")
}

enum class ProtocolType(val label: String) {
    DOH("DNS-over-HTTPS"),
    DOT("DNS-over-TLS"),
    DNS_UDP("DNS UDP/53"),
    HTTPS("HTTPS / 443"),
    QUIC("QUIC / HTTP3")
}

data class NetworkRequestLog(
    val id: String,
    val domain: String,
    val ipAddress: String,
    val appName: String,
    val appPackage: String,
    val timestampMs: Long,
    val protocol: ProtocolType,
    val status: FilterStatus,
    val category: RequestCategory,
    val matchedRule: String?,
    val filterListName: String?,
    val latencyMicros: Long, // Rust-level sub-millisecond measurement
    val dataSavedBytes: Long = 0L
)

data class FilterList(
    val id: String,
    val name: String,
    val description: String,
    val ruleCount: Int,
    val isEnabled: Boolean,
    val category: String,
    val version: String,
    val isCustom: Boolean = false,
    val customRules: List<String> = emptyList(),
    val subscriptionUrl: String? = null,
    val isOnlineSubscription: Boolean = false,
    val lastUpdatedText: String = "Vừa xong"
)

data class AppFirewallRule(
    val packageName: String,
    val appName: String,
    val isCellularAllowed: Boolean = true,
    val isWifiAllowed: Boolean = true,
    val isFilterRouted: Boolean = true, // Routed through AdGuard engine
    val blockWhenScreenOff: Boolean = false,
    val category: String = "Ứng dụng cài đặt",
    val blockedRequestsToday: Int = 0,
    val dataTransferredBytes: Long = 0L
)

data class DnsProvider(
    val id: String,
    val name: String,
    val address: String,
    val type: ProtocolType,
    val description: String,
    val isCustom: Boolean = false,
    val pingMs: Int = 12
)

data class ProtectionStats(
    val adsBlocked: Long = 14892,
    val trackersBlocked: Long = 4210,
    val dataSavedBytes: Long = 512 * 1024 * 1024L, // 512 MB
    val batteryConservedPercent: Float = 14.2f, // Estimated battery saved by blocking video ads & background pollers
    val totalRequestsIntercepted: Long = 42890,
    val engineLatencyNs: Long = 85_000, // 0.085ms fast trie lookup
    val activeRulesCount: Int = 184510,
    val memoryUsageKb: Long = 1840 // Ultra light footprint
)

data class ProtectionSettings(
    val isProtectionActive: Boolean = true,
    val isAdBlockingEnabled: Boolean = true,
    val isTrackingProtectionEnabled: Boolean = true,
    val isDnsProtectionEnabled: Boolean = true,
    val isHttpsFilteringEnabled: Boolean = true,
    val isFirewallEnabled: Boolean = true,
    val isEcoBatteryModeEnabled: Boolean = true, // Low power wakeups & TCP fast-drop
    val isStealthModeEnabled: Boolean = true,
    // Stealth mode details
    val stripUtmTracking: Boolean = true,
    val blockWebRtcLeaks: Boolean = true,
    val disguiseUserAgent: Boolean = false,
    val blockThirdPartyCookies: Boolean = true,
    val selectedDnsProviderId: String = "adguard_default"
)

data class ThreatAnalysisResult(
    val domain: String,
    val riskScore: Int, // 0 to 100
    val riskLevel: String, // Safe, Low, Moderate, High, Critical
    val category: String,
    val summary: String,
    val suggestedRules: List<String>,
    val searchGroundedSources: List<String> = emptyList(),
    val thinkingTraceSummary: String? = null
)
