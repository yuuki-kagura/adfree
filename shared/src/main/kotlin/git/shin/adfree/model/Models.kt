package git.shin.adfree.model

/** Engine decision for one request. */
enum class FilterStatus {
    BLOCKED,
    ALLOWED,
    WHITELISTED,
}

/** Rule group — the order matches the Rust core enum; the UI localizes it. */
enum class RequestCategory(val index: Int) {
    AD(0),
    TRACKER(1),
    ANALYTICS(2),
    SOCIAL(3),
    ANNOYANCE(4),
    MALWARE(5),
    CUSTOM(6);

    companion object {
        fun fromIndex(index: Int): RequestCategory =
            entries.firstOrNull { it.index == index } ?: AD
    }
}

enum class ProtocolType {
    DNS_UDP,
    DNS_DOT,
    DNS_DOH,
    HTTPS,
    QUIC,
    TCP,
    UDP,
}

/** Network the request travelled on; unknown for rows from older builds. */
enum class NetworkTransport(val code: Int) {
    UNKNOWN(0),
    WIFI(1),
    CELLULAR(2);

    companion object {
        fun fromCode(code: Int): NetworkTransport =
            entries.firstOrNull { it.code == code } ?: UNKNOWN
    }
}

/** Network the statistics window is restricted to. */
enum class AppUsageTransport(val code: Int) {
    ALL(-1),
    WIFI(1),
    CELLULAR(2),
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
    /** Package that owned the flow; null when the core could not attribute it. */
    val appPackage: String?,
    val latencyMicros: Long,
    val dataSavedBytes: Long,
    /** Network the decision was made on. */
    val transport: NetworkTransport = NetworkTransport.UNKNOWN,
    val roaming: Boolean = false,
    /** Core-assigned decision id; shown as the connection id. */
    val flowId: Long = 0L,
    /** Request URL when TLS termination saw one. */
    val url: String? = null,
    /** Address(es) the engine answered a DNS query with. */
    val dnsAnswer: String? = null,
    val bytesSent: Long = 0L,
    val bytesReceived: Long = 0L,
) {
    companion object {
        /** Convert a [git.shin.adfree.core.LogEvent] into a UI model. */
        fun from(event: git.shin.adfree.core.LogEvent): NetworkRequestLog {
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
                id = event.id,
                timestampMs = event.tsMs,
                domain = event.domain,
                ipAddress = event.ip,
                protocol = protocol,
                status = status,
                category = RequestCategory.fromIndex(event.category),
                matchedRule = event.rule.ifBlank { null },
                filterListName = event.listName.ifBlank { null },
                appPackage = event.app.ifBlank { null },
                latencyMicros = latencyMicros,
                dataSavedBytes = event.bytesSaved.toLong(),
                transport = NetworkTransport.fromCode(event.transport),
                roaming = event.roaming,
                flowId = event.flowId,
                url = event.url.ifBlank { null },
                dnsAnswer = event.dnsAnswer.ifBlank { null },
                bytesSent = event.bytesSent,
                bytesReceived = event.bytesRecv,
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

/// How a blocked domain is answered; the UI localizes the label.
enum class DnsBlockMode(val code: UInt) {
    NXDOMAIN(0u),
    ZERO_IP(1u),
    REFUSED(2u),
}

/**
 * The user's filter lists. Real data: `ruleCount` is what the core counted
 * after compiling, and subscriptions are downloaded over real HTTP.
 */
data class FilterList(
    val id: String,
    val name: String,
    val description: String,
    /** Set when the UI shows a localized catalogue name instead of [name]. */
    val nameKey: String? = null,
    /** Set when the UI shows a localized catalogue description. */
    val descriptionKey: String? = null,
    val ruleCount: Int,
    val isEnabled: Boolean,
    val category: String,
    val version: String,
    /** The user-rules list ("Quy tắc của bạn"); it is edited, never deleted. */
    val isCustom: Boolean = false,
    val customRules: List<String> = emptyList(),
    val subscriptionUrl: String? = null,
    val isOnlineSubscription: Boolean = false,
    /** Empty until the row has a timestamp; the UI supplies "not updated". */
    val lastUpdatedText: String = "",
    /** File timestamp of the body on disk, 0 while nothing has been downloaded. */
    val lastUpdatedMs: Long = 0,
    /** Body size reported by the core, 0 while nothing is on disk. */
    val sizeBytes: Long = 0,
    /**
     * Last download failure of this list, "" when the body is healthy.
     * The header toast disappears after a few seconds; this keeps the
     * reason visible on the row and in the detail sheet (AdGuard's honest
     * "filters aren't active" pattern).
     */
    val lastError: String = "",
    /** Catalog group id: ads/privacy/social/annoyances/security/other/language/custom. */
    val groupId: String = "other",
    /** "standard" (AdGuard/EasyList syntax) or "hosts". */
    val format: String = "standard",
    /** Catalogue entry id; null for lists the user added. */
    val catalogId: String? = null,
    /** Enabled state that "Khôi phục mặc định" restores. */
    val defaultEnabled: Boolean = false,
    val homepage: String? = null,
    /** Added by the user (URL or local file): deletable, not in the catalogue. */
    val isUserAdded: Boolean = false,
    /**
     * Trusted filter (KB §Trusted filters): only a trusted list may carry
     * JavaScript rules, scriptlets and the `$hls`/`$removeheader`/
     * `$removeparam`/`$replace`/`$urltransform` modifiers. Catalogue lists and
     * the user rules are trusted; a list the user added is not until they say
     * so.
     */
    val trusted: Boolean = false,
    /**
     * A DNS filter: its rules are consulted on name lookups only, never on
     * URLs or SNI. The core keeps them in a separate matcher.
     */
    val isDnsOnly: Boolean = false,
)

/**
 * Case-insensitive match of one filter list against the search field: name,
 * description, and the source URL (how users recognise a custom list). A
 * blank query matches everything.
 */
fun filterMatchesQuery(
    list: FilterList,
    query: String,
    name: String = list.name,
    description: String = list.description,
): Boolean {
    if (query.isBlank()) return true
    return name.contains(query, ignoreCase = true) ||
        description.contains(query, ignoreCase = true) ||
        list.subscriptionUrl?.contains(query, ignoreCase = true) == true
}

/**
 * Display name for a userscript imported from a file: the picker's
 * `DISPLAY_NAME` minus the `.user.js` / `.js` suffix. A nameless picker
 * answer still has to produce a row the user can recognise.
 */
fun scriptNameFromFile(displayName: String?): String =
    displayName
        ?.removeSuffix(".user.js")
        ?.removeSuffix(".js")
        ?.trim()
        ?.take(60)
        ?.takeIf { it.isNotBlank() }
        .orEmpty()

/**
 * "1.9 MB"-style label for a filter body. The decimal point is pinned to
 * `Locale.US` so the label (and its unit test) do not drift with the device
 * language; sub-1024 bodies show raw bytes, which never happens for real
 * subscriptions but keeps a half-written file readable.
 */
fun assetSizeLabel(bytes: Long): String = when {
    bytes <= 0L -> "0 B"
    bytes < 1024L -> "$bytes B"
    bytes < 1024L * 1024L -> "${bytes / 1024L} KB"
    else ->
        String.format(
            java.util.Locale.US,
            "%.1f MB",
            bytes / (1024.0 * 1024.0),
        )
}

/**
 * Why a pasted filter URL is unusable; the UI maps the code to wording.
 * Mirrors AdGuard's inline validation ("Enter a valid URL or file path"):
 * local files go through the file picker, so only `http(s)://` with a real
 * host counts here.
 */
enum class FilterUrlError {
    EMPTY,
    TOO_LONG,
    INVALID,
    UNSUPPORTED_SCHEME,
    NO_HOST,
}

fun filterUrlError(url: String): FilterUrlError? {
    val trimmed = url.trim()
    if (trimmed.isEmpty()) return FilterUrlError.EMPTY
    if (trimmed.length > 2048) return FilterUrlError.TOO_LONG
    val parsed = runCatching { java.net.URI(trimmed) }.getOrNull()
        ?: return FilterUrlError.INVALID
    val scheme = parsed.scheme?.lowercase()
    return when {
        scheme != "http" && scheme != "https" -> FilterUrlError.UNSUPPORTED_SCHEME
        parsed.host.isNullOrBlank() -> FilterUrlError.NO_HOST
        else -> null
    }
}

/** One userscript served to intercepted pages (the Extensions section). */
data class UserScriptInfo(
    val id: String,
    val name: String,
    val description: String,
    /** Set when the UI shows a localized catalogue name instead of [name]. */
    val nameKey: String? = null,
    /** Set when the UI shows a localized catalogue description. */
    val descriptionKey: String? = null,
    val url: String,
    val isEnabled: Boolean,
    val sizeBytes: Long = 0,
    /** Empty until the body is on disk; the UI supplies "not downloaded". */
    val lastUpdatedText: String = "",
    val isUserAdded: Boolean = false,
    /** Shipped with the app: no URL to refresh, cannot be deleted. */
    val isBuiltin: Boolean = false,
    /** Header fields read from the body, for the detail sheet. */
    val metadata: UserScriptMetadata = UserScriptMetadata(),
)

/** One userscript result from the Greasy Fork store. */
data class UserScriptStoreItem(
    val id: Long,
    val name: String,
    val description: String,
    /** Direct `.user.js` URL; this is what the core downloads. */
    val url: String,
    /** Human-facing Greasy Fork page, for the source link. */
    val pageUrl: String,
    val version: String,
    val dailyInstalls: Int,
    val totalInstalls: Int,
    val license: String,
    val codeSizeBytes: Long,
)

/** Greasy Fork's supported orderings; `null` keeps the API default. */
enum class UserScriptStoreSort(val apiValue: String?) {
    RELEVANCE(null),
    DAILY_INSTALLS("daily_installs"),
    TOTAL_INSTALLS("total_installs"),
    RATINGS("ratings"),
    UPDATED("updated"),
    NAME("name"),
}

/** Search state for the store sheet. */
data class UserScriptStoreState(
    val query: String = "",
    val items: List<UserScriptStoreItem> = emptyList(),
    val loading: Boolean = false,
    val loadingMore: Boolean = false,
    val page: Int = 1,
    val hasMore: Boolean = false,
    val sort: UserScriptStoreSort = UserScriptStoreSort.RELEVANCE,
    val error: String? = null,
)

/**
 * Stable codes stored in [AppFirewallRule.category]. The category comes from
 * PackageManager at read time, so the UI localizes the code instead of
 * receiving a display string.
 */
object AppCategory {
    const val BROWSER = "browser"
    const val GAME = "game"
    const val SOCIAL = "social"
    const val VIDEO = "video"
    const val AUDIO = "audio"
    const val NEWS = "news"
    const val MAPS = "maps"
    const val PRODUCTIVITY = "productivity"
    const val IMAGE = "image"
    const val OTHER = "other"
}

/** App-list chip filters that are not [AppCategory] values. */
object AppCategoryFilter {
    const val BLOCKED = "blocked"
    const val FILTERED = "filtered"
    const val UNFILTERED = "unfiltered"
}

/** Time window for the per-app usage totals shown on the Apps tab. */
enum class AppUsageRange { TODAY, WEEK, MONTH, ALL }

/** One per-app answer for a firewall dimension. */
enum class FirewallAccess {
    /** Follow the matching global default. */
    INHERIT,

    /** This app may use the dimension even when the global default blocks it. */
    ALLOW,

    /** This app may not use the dimension even when the global default allows it. */
    BLOCK,
}

/** One per-app answer for the SOCKS5 proxy. */
enum class ProxyAccess {
    /** Follow the global proxy switch. */
    INHERIT,

    /** Route this app's flows through the proxy even if it is not global. */
    THROUGH,

    /** Keep this app's flows off the proxy. */
    DIRECT,
}

data class AppFirewallRule(
    val packageName: String,
    val appName: String,
    val wifiAccess: FirewallAccess = FirewallAccess.INHERIT,
    val wifiScreenOffAccess: FirewallAccess = FirewallAccess.INHERIT,
    val cellularAccess: FirewallAccess = FirewallAccess.INHERIT,
    val cellularScreenOffAccess: FirewallAccess = FirewallAccess.INHERIT,
    val roamingAccess: FirewallAccess = FirewallAccess.INHERIT,
    val isFilterRouted: Boolean = true,
    /**
     * Whether this app's HTTPS payload is decrypted for content filtering.
     * Off keeps the flow in the tunnel (DNS stays filtered) but splices TLS
     * untouched, so ads inside HTTPS pages are not blocked.
     */
    val isHttpsFiltered: Boolean = true,
    /** Whether a firewall block may raise a notification for this app. */
    val notifyBlocked: Boolean = true,
    /** This app's routing answer for the global SOCKS5 proxy. */
    val proxyAccess: ProxyAccess = ProxyAccess.INHERIT,
    val category: String = AppCategory.OTHER,
    val blockedRequestsToday: Int = 0,
    val dataTransferredBytes: Long = 0L,
    /**
     * Bytes that actually crossed this app's connections in the selected
     * window, both directions. Counted per connection when it closed, so the
     * live traffic of a connection still open is not in it yet.
     */
    val dataUsedBytes: Long = 0L,
    /** Blocked requests from ad lists in the selected window. */
    val blockedAdsToday: Int = 0,
    /** Blocked requests from tracker, analytics and social lists. */
    val blockedTrackersToday: Int = 0,
    /** Every request in the selected window, allowed and blocked. */
    val requestsToday: Int = 0,
) {
    val hasNetworkRules: Boolean
        get() = wifiAccess != FirewallAccess.INHERIT ||
            wifiScreenOffAccess != FirewallAccess.INHERIT ||
            cellularAccess != FirewallAccess.INHERIT ||
            cellularScreenOffAccess != FirewallAccess.INHERIT ||
            roamingAccess != FirewallAccess.INHERIT
}

/** Installed app offered by the firewall app picker; system rows are grouped last. */
data class FirewallAppChoice(
    val packageName: String,
    val appName: String,
    val isSystem: Boolean,
)

data class DnsProvider(
    val id: String,
    val name: String,
    val address: String,
    val type: ProtocolType,
    val description: String,
    val isCustom: Boolean = false,
    val port: Int = 53,
    /**
     * String-resource key for built-ins (Rust owns the list); empty for
     * custom providers, whose [description] is user data.
     */
    val descriptionKey: String = "",
)

/**
 * The host is answered with [answer] before the filter lists run. A `*.`
 * prefix matches subdomains only; both strings are the canonical values the
 * core validator returned when the row was saved.
 */
data class DnsRewriteRule(
    val host: String,
    val answer: String,
)

/**
 * Plain UDP resolver the core retries once when the selected server stays
 * silent. Mirrors AdGuard's "fallback servers": it has to work when the
 * primary transport (including TLS) is what broke, so only UDP qualifies.
 */
data class DnsBackup(
    val address: String,
    val port: Int,
) {
    fun matches(provider: DnsProvider): Boolean =
        provider.type == ProtocolType.DNS_UDP &&
            provider.address == address &&
            provider.port == port
}

/** Where the one-shot fallback query goes; [SYSTEM] is the default. */
enum class DnsBackupMode { SYSTEM, OFF, FIXED }

/**
 * The address in the form the core validator accepts, including [DnsProvider.port].
 *
 * DoH already stores a complete URL; the other transports keep the port in a
 * separate field, so it has to be appended (with brackets around IPv6).
 */
fun DnsProvider.probeAddress(): String = when (type) {
    ProtocolType.DNS_UDP, ProtocolType.DNS_DOT ->
        if (address.contains(':')) "[$address]:$port" else "$address:$port"
    else -> address
}

/**
 * Whole-window counters for the Statistics header. Unattributed rows are
 * included, unlike the per-app list.
 */
data class LogWindowTotals(
    val ads: Long = 0L,
    val trackers: Long = 0L,
    val requests: Long = 0L,
    val bytesSaved: Long = 0L,
    val bytesSent: Long = 0L,
    val bytesReceived: Long = 0L,
)

/**
 * One domain in the services breakdown. [company] is empty when the services
 * table has no row for the domain, and then [label] is the name itself — the
 * section never claims a company it does not know.
 *
 * [category] is the third label a subscribed dataset can carry: what kind of
 * service the domain is. It is empty for a table written before the column,
 * which is the two-column form this project authored.
 *
 * No bytes on the wire: the flow table records a package and an address, not a
 * name, so a per-domain figure there would be a guess.
 */
data class ServiceUsage(
    val domain: String = "",
    val company: String = "",
    val category: String = "",
    val blocked: Int = 0,
    val requests: Int = 0,
    val bytesSaved: Long = 0L,
) {
    val label: String get() = company.ifBlank { domain }
}

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
    // Off until the user asks for it: the remembered intent that decides
    // whether the tunnel comes back up at launch. The running state is the
    // VPN's, not this flag's.
    val isProtectionActive: Boolean = false,
    val isAdBlockingEnabled: Boolean = true,
    // Cookie notices, popups and in-page widgets; its own switch so turning
    // ads off does not silence the annoyance lists (and vice versa).
    val isAnnoyancesEnabled: Boolean = true,
    // Malware and phishing lookups against the downloaded security lists,
    // matched on-device. On by default like AdGuard's "Bảo vệ Duyệt web".
    val isBrowsingSecurityEnabled: Boolean = true,
    val isTrackingProtectionEnabled: Boolean = true,
    val isDnsProtectionEnabled: Boolean = true,
    // Off by default: the retry window lets a host the lists refuse connect,
    // so it is a hole in the blocking an app has to ask for.
    val isSmartFilteringEnabled: Boolean = false,
    // Off until the CA is installed in the trust store and the user opts in:
    // terminating TLS without a trusted certificate would hand apps a leaf
    // they reject, breaking HTTPS instead of filtering it.
    val isHttpsFilteringEnabled: Boolean = false,
    // Off by default: AdGuard keeps QUIC blocked until the user opts in. When
    // on, UDP/443 is terminated and filtered like HTTPS instead of dropped;
    // needs HTTPS filtering for the same certificate and decision layer.
    val filterHttp3: Boolean = false,
    // Off by default, matching AdGuard's "Block ECH": with it off a host that
    // negotiates ECH is connected through (spliced) instead of broken. On, the
    // DNS answer loses its ECH config so every host stays decryptable.
    val isEchBlockingEnabled: Boolean = false,
    val isFirewallEnabled: Boolean = true,
    /** Global and custom rule sets each have their own gate. */
    val firewallGlobalRules: Boolean = true,
    val firewallCustomRules: Boolean = true,
    val firewallNotifications: Boolean = true,
    /** Default access for dimensions an app leaves on [FirewallAccess.INHERIT]. */
    val firewallAllowWifi: Boolean = true,
    val firewallAllowWifiScreenOff: Boolean = true,
    val firewallAllowCellular: Boolean = true,
    val firewallAllowCellularScreenOff: Boolean = true,
    val firewallAllowRoaming: Boolean = true,
    val isEcoBatteryModeEnabled: Boolean = true,
    // Stealth effects are opt-in; the sub-switches remember the choice.
    val isStealthModeEnabled: Boolean = false,
    val blockQuic: Boolean = true,
    // Off by default: browsers configured with a custom secure DNS provider
    // (Chrome's DoH) have no insecure fallback, so a reset here leaves them
    // with no DNS at all. Filtering then rides the SNI/TLS path instead.
    val blockDoh: Boolean = false,
    val blockDot: Boolean = true,
    /**
     * Refresh enabled subscriptions older than this many hours when the app
     * opens. 0 disables it. No background worker: a stale list is refreshed
     * on the next launch, so the radio is never woken just to check a file.
     */
    val filterAutoUpdateHours: Int = 24,
    val logAllowedRequests: Boolean = false,
    val blockMode: DnsBlockMode = DnsBlockMode.NXDOMAIN,
    val stripUtmTracking: Boolean = true,
    val blockWebRtcLeaks: Boolean = false,
    val disguiseUserAgent: Boolean = false,
    val blockThirdPartyCookies: Boolean = true,
    /**
     * The switches the tracking-protection list documents, all off until the
     * user asks: each one is a site that stops working in some way, and the
     * privacy levels are what turns them on as a set.
     */
    val blockAllCookies: Boolean = false,
    val stripEtag: Boolean = false,
    val stripThirdPartyAuthorization: Boolean = false,
    val hideThirdPartyReferer: Boolean = false,
    val injectGpcDnt: Boolean = false,
    val hideSearchQuery: Boolean = false,
    val blockPushApi: Boolean = false,
    val blockGeolocationApi: Boolean = false,
    /**
     * Split the first TLS handshake segment so a device doing deep packet
     * inspection cannot read the server name out of one packet. AdGuard's
     * `Anti-DPI`. Costs one extra write per new connection, so it is not part
     * of the privacy levels: those promise what a site sees, not what a
     * middlebox sees.
     */
    val antiDpi: Boolean = false,
    /**
     * The address a site is told the request came through, as AdGuard's
     * `Địa chỉ IP mặt nạ`: `X-Forwarded-For` is set to it on every filtered
     * request. It is what the page reads, not where the traffic goes — hiding
     * the real address needs an exit through somebody else's machine, and this
     * app makes no outbound connection the user did not ask for. Empty, or text
     * that is not an address, adds no header.
     */
    val maskIp: String = "",
    val selectedDnsProviderId: String = "adguard_default",
    /** HTTPS allowlist: hosts never decrypted (banking, client-cert sites). */
    val httpsSkipHosts: List<String> = emptyList(),
    /** HTTPS blocklist: used only when [httpsOnlyMode] is on. */
    val httpsOnlyHosts: List<String> = emptyList(),
    /** Decrypt only [httpsOnlyHosts] instead of everything but [httpsSkipHosts]. */
    val httpsOnlyMode: Boolean = false,
    /** Routing mode: send new TCP flows through a SOCKS5 proxy instead of direct. */
    val proxy: ProxySettings = ProxySettings(),
    /** In-app language; `SYSTEM` follows the device. */
    val appLanguage: AppLanguage = AppLanguage.SYSTEM,
    /** Light/dark choice; `SYSTEM` follows the device. */
    val themeMode: ThemeMode = ThemeMode.SYSTEM,
    /** Bring the tunnel back after a reboot (only when it was on). */
    val autoStart: Boolean = false,
    /** Hide ad placeholders with cosmetic rules; needs HTTPS filtering. */
    val cosmeticFiltering: Boolean = true,
    /** Force Safe Search on the major engines (CNAME rewrites). */
    val safeSearch: Boolean = false,
    /**
     * Group the request log by domain on the Statistics tab and label each
     * group with the company that owns it. Off by default: the grouping is a
     * query over the whole window on every refresh, and the labels are read
     * from disk.
     */
    val showServicesBreakdown: Boolean = false,
    /**
     * Optional subscription for the services table, refreshed with the filter
     * lists. Empty means the table this build ships, so no extra request.
     */
    val servicesTableUrl: String = "",
    /**
     * How much of the core's own diagnostics is kept for Android to forward to
     * logcat. `WARN` is what every install has buffered all along: failures plus
     * the lines that explain a fallback. `DEBUG` adds the chatter that repeats
     * for every request, and it pushes older lines out of the 200-deep ring.
     */
    val logLevel: LogLevel = LogLevel.WARN,
)

/** In-app language selection. */
enum class AppLanguage {
    SYSTEM,
    ENGLISH,
    VIETNAMESE,
}

/** Light/dark selection. */
enum class ThemeMode {
    SYSTEM,
    DARK,
    LIGHT,
}

/** How verbose the core's own diagnostics ring is. */
enum class LogLevel {
    OFF,
    ERROR,
    WARN,
    DEBUG,
}

/** Risk band for a scanned host; the UI localizes the label. */
enum class ThreatRiskLevel {
    UNKNOWN,
    SAFE,
    LOW,
    MEDIUM,
    HIGH;

    companion object {
        fun fromScore(score: Int): ThreatRiskLevel = when {
            score >= 75 -> HIGH
            score >= 50 -> MEDIUM
            score >= 25 -> LOW
            else -> SAFE
        }
    }
}

/** How the analyzer described the host; the UI localizes the wording. */
enum class ThreatCategory {
    EMPTY,
    FILTER_BLOCKED,
    SUSPICIOUS,
    UNKNOWN,
}

/** Result of scanning one domain on the Security Lab screen (no AI/API key). */
data class ThreatAnalysisResult(
    val domain: String,
    val riskScore: Int,
    val riskLevel: ThreatRiskLevel,
    val category: ThreatCategory,
    val suggestedRules: List<String>,
    val isBlockedByFilters: Boolean = false,
    val matchedRule: String? = null,
    val matchedList: String? = null,
)
