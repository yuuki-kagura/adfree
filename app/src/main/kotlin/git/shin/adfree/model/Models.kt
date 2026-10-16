package git.shin.adfree.model

/** Engine decision for one request. */
enum class FilterStatus {
    BLOCKED,
    ALLOWED,
    WHITELISTED,
}

/** Display label for a rule group — the order matches the Rust core enum. */
enum class RequestCategory(val label: String, val index: Int) {
    AD("Advertising", 0),
    TRACKER("Tracker & Telemetry", 1),
    ANALYTICS("Analytics", 2),
    SOCIAL("Social Widget", 3),
    ANNOYANCE("Annoyances", 4),
    MALWARE("Malware & Phishing", 5),
    CUSTOM("Custom Rule", 6);

    companion object {
        fun fromIndex(index: Int): RequestCategory =
            entries.firstOrNull { it.index == index } ?: AD
    }
}

enum class ProtocolType(val label: String) {
    DNS_UDP("DNS UDP/53"),
    DNS_DOT("DNS-over-TLS"),
    DNS_DOH("DNS-over-HTTPS"),
    HTTPS("HTTPS / 443"),
    QUIC("QUIC / HTTP3"),
    TCP("TCP"),
    UDP("UDP"),
}

/**
 * One Activity log row. This is REAL data pushed up by the Rust core now,
 * not `Random.nextLong()` any more.
 */
data class NetworkRequestLog(
    val id: Long,
    val timestampMs: Long,
    val domain: String,
    val ipAddress: String,
    val protocol: ProtocolType,
    val status: FilterStatus,
    val category: RequestCategory,
    val matchedRule: String?,
    val filterListName: String?,
    val latencyMicros: Long,
    val dataSavedBytes: Long,
) {
    companion object {
        /** Convert a [git.shin.adfree.core.LogEvent] into a UI model. */
        fun from(event: git.shin.adfree.core.LogEvent, id: Long): NetworkRequestLog {
            val action = event.action
            val status = when (action) {
                CoreActions.ALLOWED.toInt() -> FilterStatus.ALLOWED
                CoreActions.BLOCKED.toInt() -> FilterStatus.BLOCKED
                else -> FilterStatus.BLOCKED
            }
            val protocol = when (action) {
                CoreActions.BLOCKED.toInt() -> ProtocolType.DNS_UDP
                CoreActions.TCP_RESET.toInt() -> ProtocolType.TCP
                CoreActions.QUIC_DROP.toInt() -> ProtocolType.QUIC
                CoreActions.UDP_DROP.toInt() -> ProtocolType.UDP
                else -> ProtocolType.UDP
            }
            val latencyMicros = event.latencyNs.toLong() / 1_000L
            return NetworkRequestLog(
                id = id,
                timestampMs = event.tsMs,
                domain = event.domain,
                ipAddress = event.ip,
                protocol = protocol,
                status = status,
                category = RequestCategory.fromIndex(event.category),
                matchedRule = event.rule.ifBlank { null },
                filterListName = event.listName.ifBlank { null },
                latencyMicros = latencyMicros,
                dataSavedBytes = event.bytesSaved.toLong(),
            )
        }
    }
}

/** Constants mirrored from the Rust core, renamed for Kotlin readability. */
object CoreActions {
    const val ALLOWED = 0u
    const val BLOCKED = 1u
    const val TCP_RESET = 2u
    const val UDP_DROP = 3u
    const val QUIC_DROP = 4u
}

// ---------------------------------------------------------------------------
// The remaining models.
// ---------------------------------------------------------------------------

/// How a blocked domain is answered.
enum class DnsBlockMode(val label: String, val code: UInt) {
    NXDOMAIN("NXDOMAIN (không tồn tại)", 0u),
    ZERO_IP("0.0.0.0", 1u),
    REFUSED("REFUSED", 2u),
}

/**
 * The user's filter lists. Real data: `ruleCount` is what the core counted
 * after compiling, and subscriptions are downloaded over real HTTP.
 */
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
    val lastUpdatedText: String = "Chưa cập nhật",
)

data class AppFirewallRule(
    val packageName: String,
    val appName: String,
    val isCellularAllowed: Boolean = true,
    val isWifiAllowed: Boolean = true,
    val isFilterRouted: Boolean = true,
    val blockWhenScreenOff: Boolean = false,
    val category: String = "Ứng dụng cài đặt",
    val blockedRequestsToday: Int = 0,
    val dataTransferredBytes: Long = 0L,
)

data class DnsProvider(
    val id: String,
    val name: String,
    val address: String,
    val type: ProtocolType,
    val description: String,
    val isCustom: Boolean = false,
    val pingMs: Int = 12,
)

/**
 * All figures come from the Rust engine.
 *
 * Fields used to be hardcoded ("batteryConservedPercent = 14.2f"). Now
 * `estimatedBatterySavedPercent` is derived from actually blocked traffic, and
 * the `engineLatency*` fields are measured inside Rust.
 */
data class ProtectionStats(
    val adsBlocked: Long = 0,
    val trackersBlocked: Long = 0,
    val dataSavedBytes: Long = 0,
    val totalRequestsIntercepted: Long = 0,
    val activeRulesCount: Int = 0,
    val engineLatencyNs: Long = 0,
    val engineLatencyPeakNs: Long = 0,
    val memoryUsageKb: Long = 0,
    val cpuUsagePermille: Int = 0,
    val packetsTotal: Long = 0,
    val dnsQueries: Long = 0,
    val cacheHitRatio: Float = 0f,
    val isFilterBuilding: Boolean = false,
    val conntrackEntries: Int = 0,
    val uptimeMs: Long = 0,
    /** How long compiling the filter lists took (ms). */
    val filterBuildMs: Long = 0,
) {
    /** Share of packets blocked, used by the Home chart. */
    val blockedRatio: Float
        get() = if (totalRequestsIntercepted <= 0L) 0f
        else ((adsBlocked + trackersBlocked).toFloat() / totalRequestsIntercepted.toFloat())
            .coerceIn(0f, 1f) * 100f

    /** Estimated battery saved by the blocked traffic (radio sleeps earlier). */
    val estimatedBatterySavedPercent: Float
        get() {
            val savedMb = dataSavedBytes / (1024.0 * 1024.0)
            return (savedMb * 0.0025).coerceIn(0.0, 35.0).toFloat()
        }

    val engineMemoryMb: Float get() = memoryUsageKb / 1024f
    val dataSavedMb: Float get() = dataSavedBytes / (1024f * 1024f)
}

data class ProtectionSettings(
    val isProtectionActive: Boolean = true,
    val isAdBlockingEnabled: Boolean = true,
    val isTrackingProtectionEnabled: Boolean = true,
    val isDnsProtectionEnabled: Boolean = true,
    // Off until the CA is installed in the trust store and the user opts in:
    // terminating TLS without a trusted certificate would hand apps a leaf
    // they reject, breaking HTTPS instead of filtering it.
    val isHttpsFilteringEnabled: Boolean = false,
    val isFirewallEnabled: Boolean = true,
    val isEcoBatteryModeEnabled: Boolean = true,
    val isStealthModeEnabled: Boolean = true,
    val blockQuic: Boolean = true,
    val blockDoh: Boolean = true,
    val logAllowedRequests: Boolean = false,
    val blockMode: DnsBlockMode = DnsBlockMode.NXDOMAIN,
    val stripUtmTracking: Boolean = true,
    val blockWebRtcLeaks: Boolean = true,
    val disguiseUserAgent: Boolean = false,
    val blockThirdPartyCookies: Boolean = true,
    val selectedDnsProviderId: String = "adguard_default",
)

/** Result of scanning one domain on the Security Lab screen (no AI/API key). */
data class ThreatAnalysisResult(
    val domain: String,
    val riskScore: Int,
    val riskLevel: String,
    val category: String,
    val summary: String,
    val suggestedRules: List<String>,
    val isBlockedByFilters: Boolean = false,
    val matchedRule: String? = null,
    val matchedList: String? = null,
)
