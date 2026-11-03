package git.shin.adfree.data

import git.shin.adfree.core.AppFirewallRule as CoreFirewallRule
import git.shin.adfree.core.AppLanguage as CoreAppLanguage
import git.shin.adfree.core.DnsBackup as CoreDnsBackup
import git.shin.adfree.core.DnsBackupMode as CoreDnsBackupMode
import git.shin.adfree.core.DnsBlockMode as CoreDnsBlockMode
import git.shin.adfree.core.DnsProtocol as CoreDnsProtocol
import git.shin.adfree.core.DnsProviderRecord as CoreDnsProvider
import git.shin.adfree.core.DnsRewrite as CoreDnsRewrite
import git.shin.adfree.core.FirewallAccess as CoreFirewallAccess
import git.shin.adfree.core.LogLevel as CoreLogLevel
import git.shin.adfree.core.ProtectionState as CoreProtectionState
import git.shin.adfree.core.ProxyAccess as CoreProxyAccess
import git.shin.adfree.core.ProxyState as CoreProxyState
import git.shin.adfree.core.ThemeMode as CoreThemeMode
import git.shin.adfree.model.AppFirewallRule
import git.shin.adfree.model.AppLanguage
import git.shin.adfree.model.DnsBackup
import git.shin.adfree.model.DnsBackupMode
import git.shin.adfree.model.DnsBlockMode
import git.shin.adfree.model.DnsProvider
import git.shin.adfree.model.DnsRewriteRule
import git.shin.adfree.model.FirewallAccess
import git.shin.adfree.model.LogLevel
import git.shin.adfree.model.ProtectionSettings
import git.shin.adfree.model.ProtocolType
import git.shin.adfree.model.ProxyAccess
import git.shin.adfree.model.ProxySettings
import git.shin.adfree.model.ThemeMode

/**
 * Translation layer between the persisted Rust records and the Kotlin models
 * the Compose screens consume.
 *
 * Rust owns the schema and the defaults; every mapping here is one-to-one and
 * must not invent values. A field added on the Rust side should surface here
 * so a full-record save cannot silently drop it.
 */

// ------------------------------------------------------------------ settings

internal fun ProtectionSettings.toCoreState(): CoreProtectionState = CoreProtectionState(
    isProtectionActive = isProtectionActive,
    isAdBlockingEnabled = isAdBlockingEnabled,
    isAnnoyancesEnabled = isAnnoyancesEnabled,
    isBrowsingSecurityEnabled = isBrowsingSecurityEnabled,
    isTrackingProtectionEnabled = isTrackingProtectionEnabled,
    isDnsProtectionEnabled = isDnsProtectionEnabled,
    isSmartFilteringEnabled = isSmartFilteringEnabled,
    isHttpsFilteringEnabled = isHttpsFilteringEnabled,
    filterHttp3 = filterHttp3,
    isEchBlockingEnabled = isEchBlockingEnabled,
    isFirewallEnabled = isFirewallEnabled,
    firewallGlobalRules = firewallGlobalRules,
    firewallCustomRules = firewallCustomRules,
    firewallNotifications = firewallNotifications,
    firewallAllowWifi = firewallAllowWifi,
    firewallAllowWifiScreenOff = firewallAllowWifiScreenOff,
    firewallAllowCellular = firewallAllowCellular,
    firewallAllowCellularScreenOff = firewallAllowCellularScreenOff,
    firewallAllowRoaming = firewallAllowRoaming,
    isEcoBatteryModeEnabled = isEcoBatteryModeEnabled,
    isStealthModeEnabled = isStealthModeEnabled,
    blockQuic = blockQuic,
    blockDoh = blockDoh,
    blockDot = blockDot,
    filterAutoUpdateHours = filterAutoUpdateHours.coerceIn(0, 168).toUInt(),
    logAllowedRequests = logAllowedRequests,
    blockMode = blockMode.toCore(),
    stripUtmTracking = stripUtmTracking,
    blockWebRtcLeaks = blockWebRtcLeaks,
    disguiseUserAgent = disguiseUserAgent,
    blockThirdPartyCookies = blockThirdPartyCookies,
    blockAllCookies = blockAllCookies,
    stripEtag = stripEtag,
    stripThirdPartyAuthorization = stripThirdPartyAuthorization,
    hideThirdPartyReferer = hideThirdPartyReferer,
    injectGpcDnt = injectGpcDnt,
    hideSearchQuery = hideSearchQuery,
    blockPushApi = blockPushApi,
    blockGeolocationApi = blockGeolocationApi,
    antiDpi = antiDpi,
    maskIp = maskIp,
    selectedDnsProviderId = selectedDnsProviderId,
    httpsSkipHosts = httpsSkipHosts,
    httpsOnlyHosts = httpsOnlyHosts,
    httpsOnlyMode = httpsOnlyMode,
    proxy = proxy.toCore(),
    appLanguage = appLanguage.toCore(),
    themeMode = themeMode.toCore(),
    autoStart = autoStart,
    cosmeticFiltering = cosmeticFiltering,
    safeSearch = safeSearch,
    showServicesBreakdown = showServicesBreakdown,
    servicesTableUrl = servicesTableUrl,
    logLevel = logLevel.toCore(),
)

internal fun CoreProtectionState.toModel(): ProtectionSettings = ProtectionSettings(
    isProtectionActive = isProtectionActive,
    isAdBlockingEnabled = isAdBlockingEnabled,
    isAnnoyancesEnabled = isAnnoyancesEnabled,
    isBrowsingSecurityEnabled = isBrowsingSecurityEnabled,
    isTrackingProtectionEnabled = isTrackingProtectionEnabled,
    isDnsProtectionEnabled = isDnsProtectionEnabled,
    isSmartFilteringEnabled = isSmartFilteringEnabled,
    isHttpsFilteringEnabled = isHttpsFilteringEnabled,
    filterHttp3 = filterHttp3,
    isEchBlockingEnabled = isEchBlockingEnabled,
    isFirewallEnabled = isFirewallEnabled,
    firewallGlobalRules = firewallGlobalRules,
    firewallCustomRules = firewallCustomRules,
    firewallNotifications = firewallNotifications,
    firewallAllowWifi = firewallAllowWifi,
    firewallAllowWifiScreenOff = firewallAllowWifiScreenOff,
    firewallAllowCellular = firewallAllowCellular,
    firewallAllowCellularScreenOff = firewallAllowCellularScreenOff,
    firewallAllowRoaming = firewallAllowRoaming,
    isEcoBatteryModeEnabled = isEcoBatteryModeEnabled,
    isStealthModeEnabled = isStealthModeEnabled,
    blockQuic = blockQuic,
    blockDoh = blockDoh,
    blockDot = blockDot,
    filterAutoUpdateHours = filterAutoUpdateHours.toInt(),
    logAllowedRequests = logAllowedRequests,
    blockMode = blockMode.toModel(),
    stripUtmTracking = stripUtmTracking,
    blockWebRtcLeaks = blockWebRtcLeaks,
    disguiseUserAgent = disguiseUserAgent,
    blockThirdPartyCookies = blockThirdPartyCookies,
    blockAllCookies = blockAllCookies,
    stripEtag = stripEtag,
    stripThirdPartyAuthorization = stripThirdPartyAuthorization,
    hideThirdPartyReferer = hideThirdPartyReferer,
    injectGpcDnt = injectGpcDnt,
    hideSearchQuery = hideSearchQuery,
    blockPushApi = blockPushApi,
    blockGeolocationApi = blockGeolocationApi,
    antiDpi = antiDpi,
    maskIp = maskIp,
    selectedDnsProviderId = selectedDnsProviderId,
    httpsSkipHosts = httpsSkipHosts,
    httpsOnlyHosts = httpsOnlyHosts,
    httpsOnlyMode = httpsOnlyMode,
    proxy = proxy.toModel(),
    appLanguage = appLanguage.toModel(),
    themeMode = themeMode.toModel(),
    autoStart = autoStart,
    cosmeticFiltering = cosmeticFiltering,
    safeSearch = safeSearch,
    showServicesBreakdown = showServicesBreakdown,
    servicesTableUrl = servicesTableUrl,
    logLevel = logLevel.toModel(),
)

private fun ProxySettings.toCore(): CoreProxyState = CoreProxyState(
    enabled = enabled,
    automatic = automatic,
    host = host,
    port = port.coerceIn(0, 65535).toUShort(),
    username = username,
    password = password,
)

private fun CoreProxyState.toModel(): ProxySettings = ProxySettings(
    enabled = enabled,
    automatic = automatic,
    host = host,
    port = port.toInt(),
    username = username,
    password = password,
)

private fun DnsBlockMode.toCore(): CoreDnsBlockMode = when (this) {
    DnsBlockMode.NXDOMAIN -> CoreDnsBlockMode.NX_DOMAIN
    DnsBlockMode.ZERO_IP -> CoreDnsBlockMode.ZERO_IP
    DnsBlockMode.REFUSED -> CoreDnsBlockMode.REFUSED
}

private fun CoreDnsBlockMode.toModel(): DnsBlockMode = when (this) {
    CoreDnsBlockMode.NX_DOMAIN -> DnsBlockMode.NXDOMAIN
    CoreDnsBlockMode.ZERO_IP -> DnsBlockMode.ZERO_IP
    CoreDnsBlockMode.REFUSED -> DnsBlockMode.REFUSED
}

private fun AppLanguage.toCore(): CoreAppLanguage = when (this) {
    AppLanguage.SYSTEM -> CoreAppLanguage.SYSTEM
    AppLanguage.ENGLISH -> CoreAppLanguage.ENGLISH
    AppLanguage.VIETNAMESE -> CoreAppLanguage.VIETNAMESE
}

private fun CoreAppLanguage.toModel(): AppLanguage = when (this) {
    CoreAppLanguage.SYSTEM -> AppLanguage.SYSTEM
    CoreAppLanguage.ENGLISH -> AppLanguage.ENGLISH
    CoreAppLanguage.VIETNAMESE -> AppLanguage.VIETNAMESE
}

private fun ThemeMode.toCore(): CoreThemeMode = when (this) {
    ThemeMode.SYSTEM -> CoreThemeMode.SYSTEM
    ThemeMode.DARK -> CoreThemeMode.DARK
    ThemeMode.LIGHT -> CoreThemeMode.LIGHT
}

private fun CoreThemeMode.toModel(): ThemeMode = when (this) {
    CoreThemeMode.SYSTEM -> ThemeMode.SYSTEM
    CoreThemeMode.DARK -> ThemeMode.DARK
    CoreThemeMode.LIGHT -> ThemeMode.LIGHT
}

private fun LogLevel.toCore(): CoreLogLevel = when (this) {
    LogLevel.OFF -> CoreLogLevel.OFF
    LogLevel.ERROR -> CoreLogLevel.ERROR
    LogLevel.WARN -> CoreLogLevel.WARN
    LogLevel.DEBUG -> CoreLogLevel.DEBUG
}

private fun CoreLogLevel.toModel(): LogLevel = when (this) {
    CoreLogLevel.OFF -> LogLevel.OFF
    CoreLogLevel.ERROR -> LogLevel.ERROR
    CoreLogLevel.WARN -> LogLevel.WARN
    CoreLogLevel.DEBUG -> LogLevel.DEBUG
}

// ------------------------------------------------------------------ firewall

/** True when the row must be persisted: any rule, routing or notification choice. */
internal fun AppFirewallRule.hasOverrides(): Boolean =
    hasNetworkRules ||
        !isFilterRouted ||
        !isHttpsFiltered ||
        !notifyBlocked ||
        proxyAccess != ProxyAccess.INHERIT

internal fun FirewallAccess.toCore(): CoreFirewallAccess = when (this) {
    FirewallAccess.INHERIT -> CoreFirewallAccess.INHERIT
    FirewallAccess.ALLOW -> CoreFirewallAccess.ALLOW
    FirewallAccess.BLOCK -> CoreFirewallAccess.BLOCK
}

internal fun CoreFirewallAccess.toModel(): FirewallAccess = when (this) {
    CoreFirewallAccess.INHERIT -> FirewallAccess.INHERIT
    CoreFirewallAccess.ALLOW -> FirewallAccess.ALLOW
    CoreFirewallAccess.BLOCK -> FirewallAccess.BLOCK
}

internal fun ProxyAccess.toCore(): CoreProxyAccess = when (this) {
    ProxyAccess.INHERIT -> CoreProxyAccess.INHERIT
    ProxyAccess.THROUGH -> CoreProxyAccess.THROUGH
    ProxyAccess.DIRECT -> CoreProxyAccess.DIRECT
}

internal fun CoreProxyAccess.toModel(): ProxyAccess = when (this) {
    CoreProxyAccess.INHERIT -> ProxyAccess.INHERIT
    CoreProxyAccess.THROUGH -> ProxyAccess.THROUGH
    CoreProxyAccess.DIRECT -> ProxyAccess.DIRECT
}

internal fun AppFirewallRule.toCoreRule(): CoreFirewallRule = CoreFirewallRule(
    packageName = packageName,
    wifi = wifiAccess.toCore(),
    wifiScreenOff = wifiScreenOffAccess.toCore(),
    cellular = cellularAccess.toCore(),
    cellularScreenOff = cellularScreenOffAccess.toCore(),
    roaming = roamingAccess.toCore(),
    filtered = isFilterRouted,
    https = isHttpsFiltered,
    notify = notifyBlocked,
    proxy = proxyAccess.toCore(),
)

internal fun CoreFirewallRule.toModel(appName: String, category: String): AppFirewallRule =
    AppFirewallRule(
        packageName = packageName,
        appName = appName,
        wifiAccess = wifi.toModel(),
        wifiScreenOffAccess = wifiScreenOff.toModel(),
        cellularAccess = cellular.toModel(),
        cellularScreenOffAccess = cellularScreenOff.toModel(),
        roamingAccess = roaming.toModel(),
        isFilterRouted = filtered,
        isHttpsFiltered = https,
        notifyBlocked = notify,
        proxyAccess = proxy.toModel(),
        category = category,
    )

// ----------------------------------------------------------------------- DNS

internal fun DnsProvider.toCoreRecord(): CoreDnsProvider = CoreDnsProvider(
    id = id,
    name = name,
    address = address,
    port = port.coerceIn(0, 65535).toUShort(),
    protocol = type.toCore(),
    description = description,
    descriptionKey = descriptionKey,
    isCustom = isCustom,
)

internal fun CoreDnsProvider.toModel(): DnsProvider = DnsProvider(
    id = id,
    name = name,
    address = address,
    type = protocol.toModel(),
    description = description,
    isCustom = isCustom,
    port = port.toInt(),
    descriptionKey = descriptionKey,
)

private fun ProtocolType.toCore(): CoreDnsProtocol = when (this) {
    ProtocolType.DNS_DOT -> CoreDnsProtocol.DOT
    ProtocolType.DNS_DOH -> CoreDnsProtocol.DOH
    else -> CoreDnsProtocol.UDP
}

private fun CoreDnsProtocol.toModel(): ProtocolType = when (this) {
    CoreDnsProtocol.UDP -> ProtocolType.DNS_UDP
    CoreDnsProtocol.DOT -> ProtocolType.DNS_DOT
    CoreDnsProtocol.DOH -> ProtocolType.DNS_DOH
}

internal fun CoreDnsRewrite.toModel(): DnsRewriteRule = DnsRewriteRule(
    host = host,
    answer = answer,
)

internal fun DnsBackup.toCore(): CoreDnsBackup = CoreDnsBackup(
    address = address,
    port = port.coerceIn(0, 65535).toUShort(),
)

internal fun CoreDnsBackup.toModel(): DnsBackup = DnsBackup(
    address = address,
    port = port.toInt(),
)

internal fun DnsBackupMode.toCore(): CoreDnsBackupMode = when (this) {
    DnsBackupMode.SYSTEM -> CoreDnsBackupMode.SYSTEM
    DnsBackupMode.OFF -> CoreDnsBackupMode.OFF
    DnsBackupMode.FIXED -> CoreDnsBackupMode.FIXED
}

internal fun CoreDnsBackupMode.toModel(): DnsBackupMode = when (this) {
    CoreDnsBackupMode.SYSTEM -> DnsBackupMode.SYSTEM
    CoreDnsBackupMode.OFF -> DnsBackupMode.OFF
    CoreDnsBackupMode.FIXED -> DnsBackupMode.FIXED
}

internal fun DnsRewriteRule.toCore(): CoreDnsRewrite = CoreDnsRewrite(
    host = host,
    answer = answer,
)

/** The core protocol for a resolver form; only the DNS transports are valid. */
internal fun ProtocolType.toDnsProtocol(): CoreDnsProtocol = toCore()
