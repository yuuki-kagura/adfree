package git.shin.adfree.ui.screens

import git.shin.adfree.l10n.Strings
import git.shin.adfree.l10n.L10n
import git.shin.adfree.platform.BackHandler
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.BatteryChargingFull
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Extension
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Layers
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.NotificationsOff
import androidx.compose.material.icons.filled.RestartAlt
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.TrackChanges
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.draw.scale
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.model.AppFirewallRule
import git.shin.adfree.model.StealthPreset
import git.shin.adfree.model.normalizeMaskIp
import git.shin.adfree.ui.AdGuardIntent
import git.shin.adfree.ui.AdGuardViewModel
import git.shin.adfree.ui.ProtectionSection
import git.shin.adfree.ui.theme.AdGuardBlueDns
import git.shin.adfree.ui.theme.AdGuardDarkBg
import git.shin.adfree.ui.theme.AdGuardDarkOutline
import git.shin.adfree.ui.theme.AdGuardDarkSurface
import git.shin.adfree.ui.theme.AdGuardDarkSurfaceVariant
import git.shin.adfree.ui.theme.AdGuardGreenLight
import git.shin.adfree.ui.theme.AdGuardGreenPrimary
import git.shin.adfree.ui.theme.AdGuardOrangeWarning
import git.shin.adfree.ui.theme.AdGuardPurpleAI
import git.shin.adfree.ui.theme.AdGuardRedBlocked
import git.shin.adfree.ui.theme.AdGuardTextMuted
import git.shin.adfree.ui.theme.AdGuardTextPrimary
import git.shin.adfree.ui.theme.AdGuardTextSecondary
import git.shin.adfree.ui.theme.UiSize
import git.shin.adfree.ui.theme.isDesktopLayout
import git.shin.adfree.ui.theme.AdGuardOnAccent

/**
 * Where the Protection tab currently is. The list is the landing; everything
 * else is one module's options, the way the reference client nests them.
 */
private enum class ProtectionRoute {
    LIST, AD_BLOCKING, WEBSITE_ALLOWLIST, ANNOYANCES, TRACKING, DNS, HTTPS, FIREWALL, FIREWALL_GLOBAL, FIREWALL_CUSTOM,
    FIREWALL_APP, FIREWALL_QUICK, FIREWALL_NOTIFICATIONS, BROWSING_SECURITY, ECO, FILTERS, EXTENSIONS
}

private fun ProtectionSection.route(): ProtectionRoute = when (this) {
    ProtectionSection.AD_BLOCKING -> ProtectionRoute.AD_BLOCKING
    ProtectionSection.ANNOYANCES -> ProtectionRoute.ANNOYANCES
    ProtectionSection.TRACKING -> ProtectionRoute.TRACKING
    ProtectionSection.DNS -> ProtectionRoute.DNS
    ProtectionSection.HTTPS -> ProtectionRoute.HTTPS
    ProtectionSection.FIREWALL -> ProtectionRoute.FIREWALL
    ProtectionSection.BROWSING_SECURITY -> ProtectionRoute.BROWSING_SECURITY
    ProtectionSection.ECO -> ProtectionRoute.ECO
    ProtectionSection.FILTERS -> ProtectionRoute.FILTERS
    ProtectionSection.EXTENSIONS -> ProtectionRoute.EXTENSIONS
}

/**
 * The protection tab: every module with its own switch, and a detail screen
 * behind each row. Home stays a dashboard; this is the control panel.
 */
@Composable
fun ProtectionScreen(
    viewModel: AdGuardViewModel,
    modifier: Modifier = Modifier,
) {
    var route by rememberSaveable { mutableStateOf(ProtectionRoute.LIST) }
    var previous by rememberSaveable { mutableStateOf(ProtectionRoute.LIST) }
    var firewallAppPackage by rememberSaveable { mutableStateOf("") }

    fun navigate(next: ProtectionRoute) {
        if (next == route) return
        previous = route
        route = next
    }

    fun openFirewallApp(packageName: String) {
        firewallAppPackage = packageName
        navigate(ProtectionRoute.FIREWALL_APP)
    }

    fun back() {
        val target = if (previous == route) ProtectionRoute.LIST else previous
        previous = ProtectionRoute.LIST
        route = target
    }

    // The activity-level handler only sees the landing; deeper routes pop one
    // level here so the hub-style screens below keep working.
    BackHandler(enabled = route != ProtectionRoute.LIST) { back() }

    // Home's HTTPS bar and the Home switch (when the CA is missing) ask for a
    // detail page by name; consume the request so it cannot replay on return.
    val requestedSection by viewModel.requestedProtectionSection.collectAsState()
    LaunchedEffect(requestedSection) {
        val section = requestedSection ?: return@LaunchedEffect
        viewModel.consumeProtectionSection()
        navigate(section.route())
    }

    AnimatedContent(
        targetState = route,
        transitionSpec = {
            val direction = if (targetState.ordinal > initialState.ordinal) 1 else -1
            (fadeIn(tween(200)) +
                slideInHorizontally(tween(260)) { direction * it / 8 })
                .togetherWith(
                    fadeOut(tween(150)) +
                        slideOutHorizontally(tween(260)) { -direction * it / 8 }
                )
        },
        label = "protection-route",
    ) { current ->
        when (current) {
            ProtectionRoute.LIST -> ProtectionLanding(
                viewModel = viewModel,
                onOpen = ::navigate,
                modifier = modifier,
            )
            ProtectionRoute.AD_BLOCKING -> AdBlockingDetail(
                viewModel = viewModel,
                onBack = ::back,
                onFilters = { navigate(ProtectionRoute.FILTERS) },
                onAllowlist = { navigate(ProtectionRoute.WEBSITE_ALLOWLIST) },
                onExtensions = { navigate(ProtectionRoute.EXTENSIONS) },
                modifier = modifier,
            )
            ProtectionRoute.WEBSITE_ALLOWLIST -> WebsiteAllowlistScreen(
                viewModel = viewModel,
                onBack = ::back,
                modifier = modifier,
            )
            ProtectionRoute.ANNOYANCES -> AnnoyancesDetail(
                viewModel = viewModel,
                onBack = ::back,
                onFilters = { navigate(ProtectionRoute.FILTERS) },
                modifier = modifier,
            )
            ProtectionRoute.TRACKING -> TrackingDetail(
                viewModel = viewModel,
                onBack = ::back,
                modifier = modifier,
            )
            ProtectionRoute.DNS -> NetworkScreen(
                viewModel = viewModel,
                onBack = ::back,
                modifier = modifier,
            )
            ProtectionRoute.HTTPS -> HttpsDetail(
                viewModel = viewModel,
                onBack = ::back,
                onManageScripts = { navigate(ProtectionRoute.EXTENSIONS) },
                modifier = modifier,
            )
            ProtectionRoute.FIREWALL -> FirewallDetail(
                viewModel = viewModel,
                onBack = ::back,
                onGlobal = { navigate(ProtectionRoute.FIREWALL_GLOBAL) },
                onCustom = { navigate(ProtectionRoute.FIREWALL_CUSTOM) },
                onQuick = { navigate(ProtectionRoute.FIREWALL_QUICK) },
                onNotifications = { navigate(ProtectionRoute.FIREWALL_NOTIFICATIONS) },
                modifier = modifier,
            )
            ProtectionRoute.FIREWALL_GLOBAL -> FirewallGlobalDetail(
                viewModel = viewModel,
                onBack = ::back,
                modifier = modifier,
            )
            ProtectionRoute.FIREWALL_CUSTOM -> FirewallCustomDetail(
                viewModel = viewModel,
                onBack = ::back,
                onOpenApp = { pkg, _ -> openFirewallApp(pkg) },
                modifier = modifier,
            )
            ProtectionRoute.FIREWALL_APP -> FirewallAppRuleDetail(
                viewModel = viewModel,
                packageName = firewallAppPackage,
                onBack = ::back,
                modifier = modifier,
            )
            ProtectionRoute.FIREWALL_QUICK -> FirewallQuickActionsDetail(
                viewModel = viewModel,
                onBack = ::back,
                onOpenAppRule = { pkg, _ -> openFirewallApp(pkg) },
                modifier = modifier,
            )
            ProtectionRoute.FIREWALL_NOTIFICATIONS -> FirewallNotificationsDetail(
                viewModel = viewModel,
                onBack = ::back,
                modifier = modifier,
            )
            ProtectionRoute.BROWSING_SECURITY -> BrowsingSecurityDetail(
                viewModel = viewModel,
                onBack = ::back,
                modifier = modifier,
            )
            ProtectionRoute.ECO -> EcoDetail(
                viewModel = viewModel,
                onBack = ::back,
                modifier = modifier,
            )
            ProtectionRoute.FILTERS -> FiltersScreen(
                viewModel = viewModel,
                onBack = ::back,
                modifier = modifier,
            )
            ProtectionRoute.EXTENSIONS -> ExtensionsScreen(
                viewModel = viewModel,
                onBack = ::back,
                modifier = modifier,
            )
        }
    }
}

@Composable
private fun ProtectionLanding(
    viewModel: AdGuardViewModel,
    onOpen: (ProtectionRoute) -> Unit,
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsState()
    val settings = state.settings

    val enabledFilters = state.filterLists.count { it.isEnabled && !it.isCustom && !it.isDnsOnly }
    val enabledRules = state.filterLists
        .filter { it.isEnabled && !it.isCustom && !it.isDnsOnly }
        .sumOf { it.ruleCount }
    val scriptsOn = state.userscripts.count { it.isEnabled }
    val dnsName = state.dnsProviders
        .firstOrNull { it.id == settings.selectedDnsProviderId }
        ?.name
        ?: L10n.get(Strings.hub_dns_unset)
    val limitedApps = state.allAppFirewallRules.count { it.hasNetworkRules }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(AdGuardDarkBg),
    ) {
        PageHeader(
            title = L10n.get(Strings.nav_protection),
            subtitle = L10n.get(Strings.protection_subtitle),
            modifier = Modifier.padding(
                horizontal = UiSize.gutter.dp,
                vertical = if (isDesktopLayout) 4.dp else 12.dp,
            ),
        )

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = UiSize.gutter.dp),
            verticalArrangement = Arrangement.spacedBy(
                if (isDesktopLayout) 0.dp else 10.dp
            ),
        ) {
            Spacer(modifier = Modifier.height(2.dp))

            ModuleRow(
                icon = Icons.Default.Block,
                accent = AdGuardGreenPrimary,
                title = L10n.get(Strings.home_module_adblock_title),
                subtitle = if (enabledFilters == 0) {
                    L10n.get(Strings.protection_filters_empty)
                } else {
                    L10n.format(Strings.protection_filters_summary,
                        enabledFilters,
                        "%,d".format(enabledRules),
                    )
                },
                checked = settings.isAdBlockingEnabled,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleAdBlocking) },
                onClick = { onOpen(ProtectionRoute.AD_BLOCKING) },
            )

            ModuleRow(
                icon = Icons.Default.NotificationsOff,
                accent = AdGuardOrangeWarning,
                title = L10n.get(Strings.home_module_annoyances_title),
                subtitle = L10n.get(Strings.home_module_annoyances_subtitle),
                checked = settings.isAnnoyancesEnabled,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleAnnoyances) },
                onClick = { onOpen(ProtectionRoute.ANNOYANCES) },
            )

            ModuleRow(
                icon = Icons.Default.TrackChanges,
                accent = AdGuardOrangeWarning,
                title = L10n.get(Strings.home_module_tracking_title),
                subtitle = L10n.get(Strings.home_module_tracking_subtitle),
                checked = settings.isTrackingProtectionEnabled,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleTracking) },
                onClick = { onOpen(ProtectionRoute.TRACKING) },
            )

            ModuleRow(
                icon = Icons.Default.Dns,
                accent = AdGuardBlueDns,
                title = L10n.get(Strings.home_module_dns_title),
                subtitle = dnsName,
                checked = settings.isDnsProtectionEnabled,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleDns) },
                onClick = { onOpen(ProtectionRoute.DNS) },
            )

            ModuleRow(
                icon = Icons.Default.Lock,
                accent = AdGuardPurpleAI,
                title = L10n.get(Strings.settings_https_title),
                subtitle = L10n.get(Strings.settings_https_enable_subtitle),
                checked = settings.isHttpsFilteringEnabled,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleHttps) },
                onClick = { onOpen(ProtectionRoute.HTTPS) },
            )

            ModuleRow(
                icon = Icons.Default.Shield,
                accent = AdGuardGreenPrimary,
                title = L10n.get(Strings.home_module_firewall_title),
                subtitle = if (limitedApps == 0) {
                    L10n.get(Strings.protection_firewall_apps_none)
                } else {
                    L10n.format(Strings.protection_firewall_apps_summary, limitedApps)
                },
                checked = settings.isFirewallEnabled,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleFirewall) },
                onClick = { onOpen(ProtectionRoute.FIREWALL) },
            )

            ModuleRow(
                icon = Icons.Default.Security,
                accent = AdGuardBlueDns,
                title = L10n.get(Strings.home_module_browsing_security_title),
                subtitle = L10n.get(Strings.home_module_browsing_security_subtitle),
                checked = settings.isBrowsingSecurityEnabled,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleBrowsingSecurity) },
                onClick = { onOpen(ProtectionRoute.BROWSING_SECURITY) },
            )

            ModuleRow(
                icon = Icons.Default.BatteryChargingFull,
                accent = AdGuardGreenLight,
                title = L10n.get(Strings.home_module_eco_title),
                subtitle = L10n.get(Strings.home_module_eco_subtitle),
                checked = settings.isEcoBatteryModeEnabled,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleEcoMode) },
                onClick = { onOpen(ProtectionRoute.ECO) },
            )

            Spacer(modifier = Modifier.height(if (isDesktopLayout) 24.dp else 64.dp))
        }
    }
}

@Composable
private fun AdBlockingDetail(
    viewModel: AdGuardViewModel,
    onBack: () -> Unit,
    onFilters: () -> Unit,
    onAllowlist: () -> Unit,
    onExtensions: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsState()
    val settings = state.settings
    val enabledFilters = state.filterLists.count { it.isEnabled && !it.isCustom && !it.isDnsOnly }
    val enabledRules = state.filterLists
        .filter { it.isEnabled && !it.isCustom && !it.isDnsOnly }
        .sumOf { it.ruleCount }
    val exceptionCount = state.filterLists
        .firstOrNull { it.isCustom }
        ?.customRules
        ?.count { it.startsWith("@@") }
        ?: 0
    val scriptsOn = state.userscripts.count { it.isEnabled }

    DetailScaffold(onBack = onBack, modifier = modifier) {
        ModuleDetailHero(
            icon = Icons.Default.Block,
            tint = AdGuardGreenPrimary,
            title = L10n.get(Strings.home_module_adblock_title),
            subtitle = L10n.get(Strings.home_module_adblock_subtitle),
        )

        SettingsSwitch(
            icon = Icons.Default.Block,
            title = L10n.get(Strings.home_module_adblock_title),
            subtitle = L10n.get(Strings.home_module_adblock_subtitle),
            checked = settings.isAdBlockingEnabled,
            onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleAdBlocking) },
        )

        Spacer(modifier = Modifier.height(10.dp))

        NavigationRow(
            icon = Icons.Default.Layers,
            accent = AdGuardGreenLight,
            title = L10n.get(Strings.protection_filters_row),
            subtitle = if (enabledFilters == 0) {
                L10n.get(Strings.protection_filters_empty)
            } else {
                L10n.format(Strings.protection_filters_summary,
                    enabledFilters,
                    "%,d".format(enabledRules),
                )
            },
            onClick = onFilters,
        )

        Spacer(modifier = Modifier.height(10.dp))

        NavigationRow(
            icon = Icons.Default.CheckCircle,
            accent = AdGuardGreenLight,
            title = L10n.get(Strings.allowlist_title),
            subtitle = L10n.format(Strings.allowlist_subtitle, exceptionCount),
            onClick = onAllowlist,
        )

        Spacer(modifier = Modifier.height(10.dp))

        NavigationRow(
            icon = Icons.Default.Extension,
            accent = AdGuardPurpleAI,
            title = L10n.get(Strings.hub_extensions_title),
            subtitle = when {
                state.userscripts.isEmpty() -> L10n.get(Strings.hub_extensions_none)
                !state.scriptsMasterEnabled -> L10n.get(Strings.hub_extensions_master_off)
                else -> L10n.format(Strings.hub_extensions_count,
                    scriptsOn,
                    state.userscripts.size,
                )
            },
            onClick = onExtensions,
        )

        Spacer(modifier = Modifier.height(18.dp))

        SettingsSwitch(
            icon = Icons.Default.VisibilityOff,
            title = L10n.get(Strings.settings_cosmetic_title),
            subtitle = L10n.get(Strings.settings_cosmetic_subtitle),
            checked = settings.cosmeticFiltering,
            onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleCosmeticFiltering(it)) },
        )

        Spacer(modifier = Modifier.height(10.dp))

        SettingsSwitch(
            icon = Icons.Default.BatteryChargingFull,
            title = L10n.get(Strings.settings_smart_filtering_title),
            subtitle = L10n.get(Strings.settings_smart_filtering_subtitle),
            checked = settings.isSmartFilteringEnabled,
            onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleSmartFiltering(it)) },
        )

        Spacer(modifier = Modifier.height(18.dp))

        Text(
            text = L10n.get(Strings.settings_auto_update_title),
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextSecondary,
        )
        Text(
            text = L10n.get(Strings.settings_auto_update_subtitle),
            fontSize = 11.sp,
            color = AdGuardTextMuted,
            modifier = Modifier.padding(top = 2.dp, bottom = 6.dp),
        )
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            listOf(0, 6, 12, 24, 48, 72).forEach { hours ->
                FilterChip(
                    selected = settings.filterAutoUpdateHours == hours,
                    onClick = { viewModel.onIntent(AdGuardIntent.SetFilterAutoUpdate(hours)) },
                    label = { Text(autoUpdateLabel(hours), fontSize = 11.sp) },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = AdGuardGreenPrimary,
                        selectedLabelColor = AdGuardOnAccent,
                    ),
                )
            }
        }
    }
}

@Composable
private fun TrackingDetail(
    viewModel: AdGuardViewModel,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsState()
    val settings = state.settings

    DetailScaffold(onBack = onBack, modifier = modifier) {
        ModuleDetailHero(
            icon = Icons.Default.TrackChanges,
            tint = AdGuardOrangeWarning,
            title = L10n.get(Strings.home_module_tracking_title),
            subtitle = L10n.get(Strings.home_module_tracking_subtitle),
        )

        SettingsSwitch(
            icon = Icons.Default.TrackChanges,
            title = L10n.get(Strings.home_module_tracking_title),
            subtitle = L10n.get(Strings.home_module_tracking_subtitle),
            checked = settings.isTrackingProtectionEnabled,
            onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleTracking) },
        )

        Spacer(modifier = Modifier.height(18.dp))

        Text(
            text = L10n.get(Strings.settings_stealth_title),
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextSecondary,
        )

        Spacer(modifier = Modifier.height(8.dp))

        SettingsSwitch(
            icon = Icons.Default.VisibilityOff,
            title = L10n.get(Strings.settings_stealth_master_title),
            subtitle = L10n.get(Strings.settings_stealth_master_subtitle),
            checked = settings.isStealthModeEnabled,
            onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleStealth) },
        )

        Spacer(modifier = Modifier.height(10.dp))

        Text(
            text = L10n.get(Strings.settings_stealth_preset_title),
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextSecondary,
        )
        Text(
            text = L10n.get(Strings.settings_stealth_preset_note),
            fontSize = 11.sp,
            color = AdGuardTextMuted,
            modifier = Modifier.padding(top = 2.dp, bottom = 8.dp),
        )

        val preset = StealthPreset.of(settings)
        SurfaceCard {
            Column(modifier = Modifier.padding(14.dp)) {
                StealthPreset.entries
                    .filter { it != StealthPreset.CUSTOM }
                    .forEachIndexed { index, level ->
                        if (index > 0) Spacer(modifier = Modifier.height(10.dp))
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(8.dp))
                                .clickable {
                                    viewModel.onIntent(AdGuardIntent.SetStealthPreset(level))
                                }
                                .padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            RadioButton(
                                selected = preset == level,
                                onClick = {
                                    viewModel.onIntent(AdGuardIntent.SetStealthPreset(level))
                                },
                            )
                            Spacer(modifier = Modifier.width(10.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = L10n.get(level.titleRes()),
                                    fontSize = 15.sp,
                                    color = AdGuardTextPrimary,
                                )
                                Text(
                                    text = L10n.get(level.bodyRes()),
                                    fontSize = 12.sp,
                                    color = AdGuardTextMuted,
                                )
                            }
                        }
                    }
                if (preset == StealthPreset.CUSTOM) {
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        text = L10n.get(Strings.settings_stealth_preset_custom),
                        fontSize = 12.sp,
                        color = AdGuardBlueDns,
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        SurfaceCard {
            Column(modifier = Modifier.padding(14.dp)) {
                StealthToggleRow(
                    title = L10n.get(Strings.settings_stealth_utm_title),
                    subtitle = L10n.get(Strings.settings_stealth_utm_subtitle),
                    isChecked = settings.stripUtmTracking,
                    enabled = settings.isStealthModeEnabled,
                    onCheckedChange = {
                        viewModel.onIntent(AdGuardIntent.UpdateStealth(stripUtm = it))
                    },
                )
                Spacer(modifier = Modifier.height(12.dp))
                StealthToggleRow(
                    title = L10n.get(Strings.settings_stealth_webrtc_title),
                    subtitle = L10n.get(Strings.settings_stealth_webrtc_subtitle),
                    isChecked = settings.blockWebRtcLeaks,
                    enabled = settings.isStealthModeEnabled,
                    onCheckedChange = {
                        viewModel.onIntent(AdGuardIntent.UpdateStealth(blockWebRtc = it))
                    },
                )
                Spacer(modifier = Modifier.height(12.dp))
                StealthToggleRow(
                    title = L10n.get(Strings.settings_stealth_ua_title),
                    subtitle = L10n.get(Strings.settings_stealth_ua_subtitle),
                    isChecked = settings.disguiseUserAgent,
                    enabled = settings.isStealthModeEnabled,
                    onCheckedChange = {
                        viewModel.onIntent(AdGuardIntent.UpdateStealth(disguiseUa = it))
                    },
                )
                Spacer(modifier = Modifier.height(12.dp))
                StealthToggleRow(
                    title = L10n.get(Strings.settings_stealth_cookies_title),
                    subtitle = L10n.get(Strings.settings_stealth_cookies_subtitle),
                    isChecked = settings.blockThirdPartyCookies,
                    enabled = settings.isStealthModeEnabled,
                    onCheckedChange = {
                        viewModel.onIntent(AdGuardIntent.UpdateStealth(blockCookies = it))
                    },
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = L10n.get(Strings.settings_stealth_advanced_title),
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextSecondary,
        )
        Text(
            text = L10n.get(Strings.settings_stealth_advanced_subtitle),
            fontSize = 11.sp,
            color = AdGuardTextMuted,
            modifier = Modifier.padding(top = 2.dp, bottom = 8.dp),
        )

        SurfaceCard {
            Column(modifier = Modifier.padding(14.dp)) {
                StealthToggleRow(
                    title = L10n.get(Strings.settings_stealth_all_cookies_title),
                    subtitle = L10n.get(Strings.settings_stealth_all_cookies_subtitle),
                    isChecked = settings.blockAllCookies,
                    enabled = settings.isStealthModeEnabled,
                    onCheckedChange = {
                        viewModel.onIntent(AdGuardIntent.UpdateStealth(blockAllCookies = it))
                    },
                )
                Spacer(modifier = Modifier.height(12.dp))
                StealthToggleRow(
                    title = L10n.get(Strings.settings_stealth_etag_title),
                    subtitle = L10n.get(Strings.settings_stealth_etag_subtitle),
                    isChecked = settings.stripEtag,
                    enabled = settings.isStealthModeEnabled,
                    onCheckedChange = {
                        viewModel.onIntent(AdGuardIntent.UpdateStealth(stripEtag = it))
                    },
                )
                Spacer(modifier = Modifier.height(12.dp))
                StealthToggleRow(
                    title = L10n.get(Strings.settings_stealth_auth_title),
                    subtitle = L10n.get(Strings.settings_stealth_auth_subtitle),
                    isChecked = settings.stripThirdPartyAuthorization,
                    enabled = settings.isStealthModeEnabled,
                    onCheckedChange = {
                        viewModel.onIntent(
                            AdGuardIntent.UpdateStealth(stripThirdPartyAuthorization = it),
                        )
                    },
                )
                Spacer(modifier = Modifier.height(12.dp))
                StealthToggleRow(
                    title = L10n.get(Strings.settings_stealth_referer_title),
                    subtitle = L10n.get(Strings.settings_stealth_referer_subtitle),
                    isChecked = settings.hideThirdPartyReferer,
                    enabled = settings.isStealthModeEnabled,
                    onCheckedChange = {
                        viewModel.onIntent(AdGuardIntent.UpdateStealth(hideThirdPartyReferer = it))
                    },
                )
                Spacer(modifier = Modifier.height(12.dp))
                StealthToggleRow(
                    title = L10n.get(Strings.settings_stealth_gpc_title),
                    subtitle = L10n.get(Strings.settings_stealth_gpc_subtitle),
                    isChecked = settings.injectGpcDnt,
                    enabled = settings.isStealthModeEnabled,
                    onCheckedChange = {
                        viewModel.onIntent(AdGuardIntent.UpdateStealth(injectGpcDnt = it))
                    },
                )
                Spacer(modifier = Modifier.height(12.dp))
                StealthToggleRow(
                    title = L10n.get(Strings.settings_stealth_search_title),
                    subtitle = L10n.get(Strings.settings_stealth_search_subtitle),
                    isChecked = settings.hideSearchQuery,
                    enabled = settings.isStealthModeEnabled,
                    onCheckedChange = {
                        viewModel.onIntent(AdGuardIntent.UpdateStealth(hideSearchQuery = it))
                    },
                )
                Spacer(modifier = Modifier.height(12.dp))
                StealthToggleRow(
                    title = L10n.get(Strings.settings_stealth_push_title),
                    subtitle = L10n.get(Strings.settings_stealth_push_subtitle),
                    isChecked = settings.blockPushApi,
                    enabled = settings.isStealthModeEnabled,
                    onCheckedChange = {
                        viewModel.onIntent(AdGuardIntent.UpdateStealth(blockPushApi = it))
                    },
                )
                Spacer(modifier = Modifier.height(12.dp))
                StealthToggleRow(
                    title = L10n.get(Strings.settings_stealth_geo_title),
                    subtitle = L10n.get(Strings.settings_stealth_geo_subtitle),
                    isChecked = settings.blockGeolocationApi,
                    enabled = settings.isStealthModeEnabled,
                    onCheckedChange = {
                        viewModel.onIntent(AdGuardIntent.UpdateStealth(blockGeolocationApi = it))
                    },
                )
                Spacer(modifier = Modifier.height(12.dp))
                StealthToggleRow(
                    title = L10n.get(Strings.settings_stealth_dpi_title),
                    subtitle = L10n.get(Strings.settings_stealth_dpi_subtitle),
                    isChecked = settings.antiDpi,
                    enabled = settings.isStealthModeEnabled,
                    onCheckedChange = {
                        viewModel.onIntent(AdGuardIntent.UpdateStealth(antiDpi = it))
                    },
                )
                Spacer(modifier = Modifier.height(12.dp))
                StealthMaskIpRow(
                    value = settings.maskIp,
                    enabled = settings.isStealthModeEnabled,
                    onSave = { viewModel.onIntent(AdGuardIntent.UpdateStealth(maskIp = it)) },
                )
            }
        }
    }
}

/**
 * The one entry in AdGuard's tracking-protection list that needs a keyboard.
 * The address is stored exactly as typed and the core decides whether it is
 * applied, so clearing the field is the same as turning the switch off and a
 * value restored from another device stays visible even when it is nonsense.
 * Save is disabled while the text is neither empty nor an address.
 */
@Composable
private fun StealthMaskIpRow(
    value: String,
    enabled: Boolean,
    onSave: (String) -> Unit,
) {
    var editing by rememberSaveable { mutableStateOf(false) }
    var draft by rememberSaveable { mutableStateOf(value) }
    // Outside the editor the field shows what is stored, so a save from another
    // screen or a restore never leaves a stale draft behind the label.
    LaunchedEffect(value, editing) {
        if (!editing) draft = value
    }
    val candidate = normalizeMaskIp(draft)

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = L10n.get(Strings.settings_stealth_mask_title),
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold,
                color = if (enabled) AdGuardTextPrimary else AdGuardTextMuted,
            )
            Text(
                text = L10n.get(Strings.settings_stealth_mask_subtitle),
                fontSize = 11.sp,
                color = AdGuardTextSecondary,
            )
            Text(
                text = if (value.isEmpty()) {
                    L10n.get(Strings.settings_stealth_mask_unset)
                } else {
                    L10n.format(Strings.settings_stealth_mask_set, value)
                },
                fontSize = 11.sp,
                color = if (value.isEmpty()) AdGuardTextMuted else AdGuardGreenLight,
            )
        }
        TextButton(onClick = {
            if (editing) {
                editing = false
                draft = value
            } else {
                draft = value
                editing = true
            }
        }) {
            Text(
                text = L10n.get(if (editing) Strings.common_cancel else Strings.settings_stealth_mask_change
                ),
                fontSize = 11.sp,
                color = AdGuardGreenLight,
            )
        }
    }

    if (editing) {
        Spacer(modifier = Modifier.height(8.dp))
        OutlinedTextField(
            value = draft,
            onValueChange = { draft = it },
            label = { Text(L10n.get(Strings.settings_stealth_mask_label), fontSize = 12.sp) },
            placeholder = { Text("203.0.113.9", fontSize = 12.sp, color = AdGuardTextMuted) },
            singleLine = true,
            isError = candidate == null,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(10.dp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = AdGuardGreenPrimary,
                unfocusedBorderColor = AdGuardDarkOutline,
                focusedTextColor = AdGuardTextPrimary,
                unfocusedTextColor = AdGuardTextPrimary,
            ),
        )
        Spacer(modifier = Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = {
                    candidate?.let(onSave)
                    editing = false
                },
                enabled = candidate != null,
                colors = ButtonDefaults.buttonColors(
                    containerColor = AdGuardGreenPrimary,
                    contentColor = AdGuardOnAccent,
                ),
            ) {
                Text(L10n.get(Strings.settings_stealth_mask_apply), fontSize = 12.sp)
            }
            if (candidate == null) {
                Text(
                    text = L10n.get(Strings.settings_stealth_mask_invalid),
                    fontSize = 11.sp,
                    color = AdGuardRedBlocked,
                    modifier = Modifier.align(Alignment.CenterVertically),
                )
            }
        }
    }
}

/** The label the radio shows for a level. */
private fun StealthPreset.titleRes(): String = when (this) {
    StealthPreset.STANDARD -> Strings.settings_stealth_preset_standard_title
    StealthPreset.HIGH -> Strings.settings_stealth_preset_high_title
    StealthPreset.ULTRA -> Strings.settings_stealth_preset_ultra_title
    StealthPreset.CUSTOM -> Strings.settings_stealth_preset_custom_title
}

/** What the level turns on, and what it costs. */
private fun StealthPreset.bodyRes(): String = when (this) {
    StealthPreset.STANDARD -> Strings.settings_stealth_preset_standard_body
    StealthPreset.HIGH -> Strings.settings_stealth_preset_high_body
    StealthPreset.ULTRA -> Strings.settings_stealth_preset_ultra_body
    StealthPreset.CUSTOM -> Strings.settings_stealth_preset_custom_body
}

@Composable
private fun AnnoyancesDetail(
    viewModel: AdGuardViewModel,
    onBack: () -> Unit,
    onFilters: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsState()
    val settings = state.settings
    val lists = state.filterLists.filter { it.groupId == "annoyances" && !it.isCustom }
    val active = lists.count { it.isEnabled }

    DetailScaffold(onBack = onBack, modifier = modifier) {
        ModuleDetailHero(
            icon = Icons.Default.NotificationsOff,
            tint = AdGuardOrangeWarning,
            title = L10n.get(Strings.home_module_annoyances_title),
            subtitle = L10n.get(Strings.home_module_annoyances_subtitle),
        )

        SettingsSwitch(
            icon = Icons.Default.NotificationsOff,
            title = L10n.get(Strings.home_module_annoyances_title),
            subtitle = L10n.get(Strings.home_module_annoyances_subtitle),
            checked = settings.isAnnoyancesEnabled,
            onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleAnnoyances) },
        )

        Spacer(modifier = Modifier.height(18.dp))

        Text(
            text = L10n.get(Strings.protection_annoyances_lists_title),
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextSecondary,
        )
        Text(
            text = L10n.get(Strings.protection_annoyances_lists_body),
            fontSize = 11.sp,
            color = AdGuardTextMuted,
            modifier = Modifier.padding(top = 2.dp, bottom = 8.dp),
        )

        if (lists.isEmpty()) {
            Text(
                text = L10n.get(Strings.protection_annoyances_empty),
                fontSize = 12.sp,
                color = AdGuardTextMuted,
            )
        } else {
            SurfaceCard {
                Column(modifier = Modifier.padding(14.dp)) {
                    lists.forEachIndexed { index, list ->
                        if (index > 0) Spacer(modifier = Modifier.height(12.dp))
                        StealthToggleRow(
                            title = list.nameKey?.let { L10n.get(it) } ?: list.name,
                            subtitle = list.descriptionKey?.let { L10n.get(it) } ?: list.description,
                            isChecked = list.isEnabled,
                            enabled = settings.isAnnoyancesEnabled,
                            onCheckedChange = {
                                viewModel.onIntent(AdGuardIntent.ToggleFilterList(list.id, it))
                            },
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        NavigationRow(
            icon = Icons.Default.Layers,
            accent = AdGuardOrangeWarning,
            title = L10n.get(Strings.protection_filters_row),
            subtitle = L10n.format(Strings.protection_annoyances_summary, active),
            onClick = onFilters,
        )
    }
}

@Composable
private fun HttpsDetail(
    viewModel: AdGuardViewModel,
    onBack: () -> Unit,
    onManageScripts: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsState()

    DetailScaffold(onBack = onBack, modifier = modifier) {
        ModuleDetailHero(
            icon = Icons.Default.Lock,
            tint = AdGuardPurpleAI,
            title = L10n.get(Strings.settings_https_title),
            subtitle = L10n.get(Strings.settings_https_body),
        )

        HttpsFilterSection(
            viewModel = viewModel,
            echBlockingEnabled = state.settings.isEchBlockingEnabled,
            onManageScripts = onManageScripts,
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FirewallDetail(
    viewModel: AdGuardViewModel,
    onBack: () -> Unit,
    onGlobal: () -> Unit,
    onCustom: () -> Unit,
    onQuick: () -> Unit,
    onNotifications: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsState()
    val settings = state.settings
    val overrides = state.allAppFirewallRules.count { it.hasNetworkRules }
    val blockedGlobals = listOf(
        settings.firewallAllowWifi,
        settings.firewallAllowWifiScreenOff,
        settings.firewallAllowCellular,
        settings.firewallAllowCellularScreenOff,
        settings.firewallAllowRoaming,
    ).count { !it }
    var showReset by rememberSaveable { mutableStateOf(false) }

    DetailScaffold(
        onBack = onBack,
        modifier = modifier,
        trailing = {
            TextButton(onClick = { showReset = true }) {
                Icon(
                    imageVector = Icons.Default.RestartAlt,
                    contentDescription = null,
                    tint = AdGuardOrangeWarning,
                    modifier = Modifier.size(16.dp),
                )
                Spacer(modifier = Modifier.width(4.dp))
                Text(
                    text = L10n.get(Strings.firewall_reset_action),
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = AdGuardOrangeWarning,
                )
            }
        },
    ) {
        ModuleDetailHero(
            icon = Icons.Default.Shield,
            tint = AdGuardGreenPrimary,
            title = L10n.get(Strings.home_module_firewall_title),
            subtitle = L10n.get(Strings.home_module_firewall_subtitle),
        )

        SettingsSwitch(
            icon = Icons.Default.Shield,
            title = L10n.get(Strings.home_module_firewall_title),
            subtitle = L10n.get(Strings.home_module_firewall_subtitle),
            checked = settings.isFirewallEnabled,
            onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleFirewall) },
        )

        Spacer(modifier = Modifier.height(9.dp))

        FirewallToggleRow(
            icon = Icons.Default.Shield,
            accent = AdGuardGreenPrimary,
            title = L10n.get(Strings.firewall_global_title),
            subtitle = if (settings.firewallGlobalRules && blockedGlobals > 0) {
                L10n.format(Strings.firewall_global_some_blocked, blockedGlobals)
            } else {
                L10n.get(Strings.firewall_global_all_allowed)
            },
            checked = settings.firewallGlobalRules,
            onCheckedChange = {
                viewModel.onIntent(AdGuardIntent.UpdateFirewallSettings(globalRules = it))
            },
            onClick = onGlobal,
        ) {
            FirewallNetworkStrip(
                rule = AppFirewallRule(packageName = "", appName = ""),
                settings = settings,
            )
        }

        Spacer(modifier = Modifier.height(9.dp))

        FirewallToggleRow(
            icon = Icons.Default.Apps,
            accent = AdGuardGreenLight,
            title = L10n.get(Strings.firewall_custom_title),
            subtitle = if (overrides == 0) {
                L10n.get(Strings.firewall_custom_empty)
            } else {
                L10n.format(Strings.firewall_custom_summary, overrides)
            },
            checked = settings.firewallCustomRules,
            onCheckedChange = {
                viewModel.onIntent(AdGuardIntent.UpdateFirewallSettings(customRules = it))
            },
            onClick = onCustom,
        )

        Spacer(modifier = Modifier.height(9.dp))

        NavigationRow(
            icon = Icons.Default.History,
            accent = AdGuardOrangeWarning,
            title = L10n.get(Strings.firewall_quick_title),
            subtitle = L10n.get(Strings.firewall_quick_subtitle),
            onClick = onQuick,
        )

        Spacer(modifier = Modifier.height(9.dp))

        FirewallToggleRow(
            icon = Icons.Default.NotificationsOff,
            accent = AdGuardOrangeWarning,
            title = L10n.get(Strings.firewall_notifications_title),
            subtitle = L10n.get(Strings.firewall_notifications_body),
            checked = settings.firewallNotifications,
            onCheckedChange = {
                viewModel.onIntent(AdGuardIntent.UpdateFirewallSettings(notifications = it))
            },
            onClick = onNotifications,
        )
    }

    if (showReset) {
        ModalBottomSheet(
            onDismissRequest = { showReset = false },
            containerColor = AdGuardDarkSurface,
            contentColor = AdGuardTextPrimary,
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 24.dp)
                    .padding(bottom = 24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    text = L10n.get(Strings.firewall_reset_title),
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextPrimary,
                    textAlign = TextAlign.Center,
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = L10n.get(Strings.firewall_reset_body),
                    fontSize = 12.sp,
                    color = AdGuardTextSecondary,
                    textAlign = TextAlign.Center,
                )
                Spacer(modifier = Modifier.height(18.dp))
                Button(
                    onClick = {
                        viewModel.onIntent(AdGuardIntent.ResetFirewall)
                        showReset = false
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(46.dp),
                    shape = RoundedCornerShape(10.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = AdGuardOrangeWarning,
                        contentColor = Color.White,
                    ),
                ) {
                    Text(
                        text = L10n.get(Strings.firewall_reset_confirm),
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                    )
                }
            }
        }
    }
}

/** A firewall row whose switch edits the value while the row opens the screen. */
@Composable
private fun FirewallToggleRow(
    icon: ImageVector,
    accent: Color,
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    onClick: () -> Unit,
    preview: (@Composable () -> Unit)? = null,
) {
    SurfaceCard(modifier = Modifier.clickable(onClick = onClick)) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(36.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(accent.copy(alpha = 0.12f)),
            ) {
                Icon(icon, contentDescription = null, tint = accent, modifier = Modifier.size(18.dp))
            }
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = AdGuardTextPrimary,
                )
                Text(
                    text = subtitle,
                    fontSize = 11.sp,
                    color = AdGuardTextSecondary,
                )
                if (preview != null) {
                    preview()
                }
            }
            Switch(
                checked = checked,
                onCheckedChange = onCheckedChange,
                colors = SwitchDefaults.colors(
                    checkedThumbColor = Color.White,
                    checkedTrackColor = AdGuardGreenPrimary,
                    uncheckedThumbColor = AdGuardTextMuted,
                    uncheckedTrackColor = AdGuardDarkSurfaceVariant,
                ),
            )
        }
    }
}

@Composable
private fun BrowsingSecurityDetail(
    viewModel: AdGuardViewModel,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsState()

    DetailScaffold(onBack = onBack, modifier = modifier) {
        ModuleDetailHero(
            icon = Icons.Default.Security,
            tint = AdGuardBlueDns,
            title = L10n.get(Strings.home_module_browsing_security_title),
            subtitle = L10n.get(Strings.home_module_browsing_security_subtitle),
        )

        SettingsSwitch(
            icon = Icons.Default.Security,
            title = L10n.get(Strings.home_module_browsing_security_title),
            subtitle = L10n.get(Strings.home_module_browsing_security_subtitle),
            checked = state.settings.isBrowsingSecurityEnabled,
            onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleBrowsingSecurity) },
        )

        Spacer(modifier = Modifier.height(12.dp))

        SurfaceCard {
            Text(
                text = L10n.get(Strings.protection_browsing_security_body),
                fontSize = 12.sp,
                color = AdGuardTextMuted,
                modifier = Modifier.padding(14.dp),
            )
        }
    }
}

@Composable
private fun EcoDetail(
    viewModel: AdGuardViewModel,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsState()

    DetailScaffold(onBack = onBack, modifier = modifier) {
        ModuleDetailHero(
            icon = Icons.Default.BatteryChargingFull,
            tint = AdGuardGreenLight,
            title = L10n.get(Strings.home_module_eco_title),
            subtitle = L10n.get(Strings.home_module_eco_subtitle),
        )

        SettingsSwitch(
            icon = Icons.Default.BatteryChargingFull,
            title = L10n.get(Strings.home_module_eco_title),
            subtitle = L10n.get(Strings.home_module_eco_subtitle),
            checked = state.settings.isEcoBatteryModeEnabled,
            onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleEcoMode) },
        )

        Spacer(modifier = Modifier.height(12.dp))

        Text(
            text = L10n.get(Strings.protection_eco_body),
            fontSize = 12.sp,
            color = AdGuardTextMuted,
        )
    }
}

/** Back arrow plus the scrolling body every module detail shares. */
@Composable
internal fun DetailScaffold(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    trailing: (@Composable () -> Unit)? = null,
    content: @Composable () -> Unit,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .background(AdGuardDarkBg),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) {
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = L10n.get(Strings.hub_back),
                    tint = AdGuardTextPrimary,
                )
            }
            Spacer(modifier = Modifier.weight(1f))
            trailing?.invoke()
        }

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp)
                .padding(bottom = 64.dp),
        ) {
            content()
        }
    }
}

@Composable
internal fun ModuleDetailHero(
    icon: ImageVector,
    tint: Color,
    title: String,
    subtitle: String,
) {
    // The phone hero is a big centred icon over the module name. On a
    // desktop the page title belongs to the module's own switch row right
    // below it, so drawing the hero twice only repeats the name.
    if (isDesktopLayout) return

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp, bottom = 20.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier
                .size(56.dp)
                .clip(RoundedCornerShape(18.dp))
                .background(tint.copy(alpha = 0.12f)),
        ) {
            Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(28.dp))
        }
        Spacer(modifier = Modifier.height(12.dp))
        Text(
            text = title,
            fontSize = 20.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextPrimary,
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = subtitle,
            fontSize = 12.sp,
            color = AdGuardTextMuted,
            textAlign = TextAlign.Center,
        )
    }
}

@Composable
private fun ModuleRow(
    icon: ImageVector,
    accent: Color,
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    onClick: () -> Unit,
) {
    // Desktop: a line in a list, separated from its neighbours by a hairline.
    // Phone: a tile you can hit with a thumb.
    val desktop = isDesktopLayout
    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .then(
                    if (desktop) Modifier
                    else Modifier
                        .clip(RoundedCornerShape(14.dp))
                        .background(AdGuardDarkSurface)
                        .border(1.dp, AdGuardDarkOutline, RoundedCornerShape(14.dp))
                )
                .clickable(onClick = onClick)
                .heightIn(min = if (desktop) UiSize.rowMinHeight.dp else 0.dp)
                .padding(
                    horizontal = if (desktop) 10.dp else 14.dp,
                    vertical = if (desktop) 4.dp else 12.dp,
                ),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(if (desktop) 26.dp else 36.dp)
                    .clip(RoundedCornerShape(if (desktop) 7.dp else 10.dp))
                    .background(accent.copy(alpha = 0.12f)),
            ) {
                Icon(
                    icon,
                    contentDescription = null,
                    tint = accent,
                    modifier = Modifier.size(if (desktop) 15.dp else 18.dp),
                )
            }
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    fontSize = if (desktop) UiSize.rowTitleSp.sp else 14.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = AdGuardTextPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = subtitle,
                    fontSize = if (desktop) UiSize.rowSubtitleSp.sp else 11.sp,
                    color = if (desktop) AdGuardTextMuted else AdGuardTextSecondary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Switch(
                checked = checked,
                onCheckedChange = onCheckedChange,
                modifier = Modifier.scale(if (desktop) 0.82f else 1f),
                colors = SwitchDefaults.colors(
                    checkedThumbColor = Color.White,
                    checkedTrackColor = AdGuardGreenPrimary,
                    uncheckedThumbColor = AdGuardTextMuted,
                    uncheckedTrackColor = AdGuardDarkSurfaceVariant,
                ),
            )
        }
        if (desktop) RowDivider()
    }
}

@Composable
internal fun NavigationRow(
    icon: ImageVector,
    accent: Color,
    title: String,
    subtitle: String,
    onClick: () -> Unit,
) {
    val desktop = isDesktopLayout
    SurfaceCard {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(onClick = onClick)
                .heightIn(min = if (desktop) UiSize.rowMinHeight.dp else 0.dp)
                .padding(
                    horizontal = if (desktop) 10.dp else 14.dp,
                    vertical = if (desktop) 4.dp else 12.dp,
                ),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(if (desktop) 26.dp else 36.dp)
                    .clip(RoundedCornerShape(if (desktop) 7.dp else 10.dp))
                    .background(accent.copy(alpha = 0.12f)),
            ) {
                Icon(
                    icon,
                    contentDescription = null,
                    tint = accent,
                    modifier = Modifier.size(if (desktop) 15.dp else 18.dp),
                )
            }
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    fontSize = if (desktop) UiSize.rowTitleSp.sp else 13.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = AdGuardTextPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = subtitle,
                    fontSize = if (desktop) UiSize.rowSubtitleSp.sp else 11.sp,
                    color = if (desktop) AdGuardTextMuted else AdGuardTextSecondary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Icon(
                imageVector = Icons.Default.ChevronRight,
                contentDescription = null,
                tint = AdGuardTextMuted,
                modifier = Modifier.size(if (desktop) 16.dp else 20.dp),
            )
        }
        if (desktop) RowDivider()
    }
}

/** Label for the auto-update chips; 0 means "off". */
@Composable
private fun autoUpdateLabel(hours: Int): String =
    if (hours <= 0) L10n.get(Strings.settings_auto_update_off)
    else L10n.format(Strings.settings_auto_update_hours, hours)

/** Header for destinations that still show a title bar instead of a hero. */
@Composable
internal fun HubDestinationHeader(
    title: String,
    subtitle: String,
    onBack: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconButton(onClick = onBack) {
            Icon(
                imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                contentDescription = L10n.get(Strings.hub_back),
                tint = AdGuardTextPrimary,
            )
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                fontSize = 19.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextPrimary,
            )
            Text(
                text = subtitle,
                fontSize = 12.sp,
                color = AdGuardTextMuted,
            )
        }
    }
}
