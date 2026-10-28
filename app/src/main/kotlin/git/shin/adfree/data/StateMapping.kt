package git.shin.adfree.data

import git.shin.adfree.core.AppFirewallRule as CoreFirewallRule
import git.shin.adfree.core.AppLanguage as CoreAppLanguage
import git.shin.adfree.core.DnsBlockMode as CoreDnsBlockMode
import git.shin.adfree.core.DnsProtocol as CoreDnsProtocol
import git.shin.adfree.core.DnsProviderRecord as CoreDnsProvider
import git.shin.adfree.core.DnsRewrite as CoreDnsRewrite
import git.shin.adfree.core.ProtectionState as CoreProtectionState
import git.shin.adfree.core.ProxyState as CoreProxyState
import git.shin.adfree.core.ThemeMode as CoreThemeMode
import git.shin.adfree.model.AppFirewallRule
import git.shin.adfree.model.AppLanguage
import git.shin.adfree.model.DnsBlockMode
import git.shin.adfree.model.DnsProvider
import git.shin.adfree.model.DnsRewriteRule
import git.shin.adfree.model.ProtectionSettings
import git.shin.adfree.model.ProtocolType
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
    isTrackingProtectionEnabled = isTrackingProtectionEnabled,
    isDnsProtectionEnabled = isDnsProtectionEnabled,
    isSmartFilteringEnabled = isSmartFilteringEnabled,
    isHttpsFilteringEnabled = isHttpsFilteringEnabled,
    filterHttp3 = filterHttp3,
    isFullEchEnabled = isFullEchEnabled,
    isFirewallEnabled = isFirewallEnabled,
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
)

internal fun CoreProtectionState.toModel(): ProtectionSettings = ProtectionSettings(
    isProtectionActive = isProtectionActive,
    isAdBlockingEnabled = isAdBlockingEnabled,
    isTrackingProtectionEnabled = isTrackingProtectionEnabled,
    isDnsProtectionEnabled = isDnsProtectionEnabled,
    isSmartFilteringEnabled = isSmartFilteringEnabled,
    isHttpsFilteringEnabled = isHttpsFilteringEnabled,
    filterHttp3 = filterHttp3,
    isFullEchEnabled = isFullEchEnabled,
    isFirewallEnabled = isFirewallEnabled,
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

// ------------------------------------------------------------------ firewall

/** True when at least one switch differs from the all-allowed default. */
internal fun AppFirewallRule.hasOverrides(): Boolean =
    !isCellularAllowed || !isWifiAllowed || !isFilterRouted ||
        !isHttpsFiltered || blockWhenScreenOff

internal fun AppFirewallRule.toCoreRule(): CoreFirewallRule = CoreFirewallRule(
    packageName = packageName,
    cellular = isCellularAllowed,
    wifi = isWifiAllowed,
    filtered = isFilterRouted,
    screenOff = blockWhenScreenOff,
    https = isHttpsFiltered,
)

internal fun CoreFirewallRule.toModel(appName: String, category: String): AppFirewallRule =
    AppFirewallRule(
        packageName = packageName,
        appName = appName,
        isCellularAllowed = cellular,
        isWifiAllowed = wifi,
        isFilterRouted = filtered,
        isHttpsFiltered = https,
        blockWhenScreenOff = screenOff,
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

internal fun DnsRewriteRule.toCore(): CoreDnsRewrite = CoreDnsRewrite(
    host = host,
    answer = answer,
)

/** The core protocol for a resolver form; only the DNS transports are valid. */
internal fun ProtocolType.toDnsProtocol(): CoreDnsProtocol = toCore()
