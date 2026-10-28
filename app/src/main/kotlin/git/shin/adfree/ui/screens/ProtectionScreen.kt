package git.shin.adfree.ui.screens

import androidx.activity.compose.BackHandler
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
import androidx.compose.foundation.layout.fillMaxSize
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
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Extension
import androidx.compose.material.icons.filled.Layers
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.TrackChanges
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.R
import git.shin.adfree.ui.AdGuardIntent
import git.shin.adfree.ui.AdGuardTab
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
import git.shin.adfree.ui.theme.AdGuardTextMuted
import git.shin.adfree.ui.theme.AdGuardTextPrimary
import git.shin.adfree.ui.theme.AdGuardTextSecondary
import git.shin.adfree.ui.theme.AdGuardOnAccent

/**
 * Where the Protection tab currently is. The list is the landing; everything
 * else is one module's options, the way the reference client nests them.
 */
private enum class ProtectionRoute {
    LIST, AD_BLOCKING, TRACKING, DNS, HTTPS, FIREWALL, ECO, FILTERS, EXTENSIONS
}

private fun ProtectionSection.route(): ProtectionRoute = when (this) {
    ProtectionSection.AD_BLOCKING -> ProtectionRoute.AD_BLOCKING
    ProtectionSection.TRACKING -> ProtectionRoute.TRACKING
    ProtectionSection.DNS -> ProtectionRoute.DNS
    ProtectionSection.HTTPS -> ProtectionRoute.HTTPS
    ProtectionSection.FIREWALL -> ProtectionRoute.FIREWALL
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

    fun navigate(next: ProtectionRoute) {
        if (next == route) return
        previous = route
        route = next
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
                onExtensions = { navigate(ProtectionRoute.EXTENSIONS) },
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

    val enabledFilters = state.filterLists.count { it.isEnabled && !it.isCustom }
    val enabledRules = state.filterLists
        .filter { it.isEnabled && !it.isCustom }
        .sumOf { it.ruleCount }
    val scriptsOn = state.userscripts.count { it.isEnabled }
    val dnsName = state.dnsProviders
        .firstOrNull { it.id == settings.selectedDnsProviderId }
        ?.name
        ?: stringResource(R.string.hub_dns_unset)
    val limitedApps = state.appFirewallRules.count {
        !it.isCellularAllowed || !it.isWifiAllowed
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(AdGuardDarkBg),
    ) {
        Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
            Text(
                text = stringResource(R.string.nav_protection),
                fontSize = 19.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextPrimary,
            )
            Text(
                text = stringResource(R.string.protection_subtitle),
                fontSize = 12.sp,
                color = AdGuardTextMuted,
            )
        }

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Spacer(modifier = Modifier.height(2.dp))

            ModuleRow(
                icon = Icons.Default.Block,
                accent = AdGuardGreenPrimary,
                title = stringResource(R.string.home_module_adblock_title),
                subtitle = if (enabledFilters == 0) {
                    stringResource(R.string.protection_filters_empty)
                } else {
                    stringResource(
                        R.string.protection_filters_summary,
                        enabledFilters,
                        "%,d".format(enabledRules),
                    )
                },
                checked = settings.isAdBlockingEnabled,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleAdBlocking) },
                onClick = { onOpen(ProtectionRoute.AD_BLOCKING) },
            )

            ModuleRow(
                icon = Icons.Default.TrackChanges,
                accent = AdGuardOrangeWarning,
                title = stringResource(R.string.home_module_tracking_title),
                subtitle = stringResource(R.string.home_module_tracking_subtitle),
                checked = settings.isTrackingProtectionEnabled,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleTracking) },
                onClick = { onOpen(ProtectionRoute.TRACKING) },
            )

            ModuleRow(
                icon = Icons.Default.Dns,
                accent = AdGuardBlueDns,
                title = stringResource(R.string.home_module_dns_title),
                subtitle = dnsName,
                checked = settings.isDnsProtectionEnabled,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleDns) },
                onClick = { onOpen(ProtectionRoute.DNS) },
            )

            ModuleRow(
                icon = Icons.Default.Lock,
                accent = AdGuardPurpleAI,
                title = stringResource(R.string.settings_https_title),
                subtitle = stringResource(R.string.settings_https_enable_subtitle),
                checked = settings.isHttpsFilteringEnabled,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleHttps) },
                onClick = { onOpen(ProtectionRoute.HTTPS) },
            )

            ModuleRow(
                icon = Icons.Default.Shield,
                accent = AdGuardGreenPrimary,
                title = stringResource(R.string.home_module_firewall_title),
                subtitle = if (limitedApps == 0) {
                    stringResource(R.string.protection_firewall_apps_none)
                } else {
                    stringResource(R.string.protection_firewall_apps_summary, limitedApps)
                },
                checked = settings.isFirewallEnabled,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleFirewall) },
                onClick = { onOpen(ProtectionRoute.FIREWALL) },
            )

            ModuleRow(
                icon = Icons.Default.BatteryChargingFull,
                accent = AdGuardGreenLight,
                title = stringResource(R.string.home_module_eco_title),
                subtitle = stringResource(R.string.home_module_eco_subtitle),
                checked = settings.isEcoBatteryModeEnabled,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleEcoMode) },
                onClick = { onOpen(ProtectionRoute.ECO) },
            )

            Spacer(modifier = Modifier.height(64.dp))
        }
    }
}

@Composable
private fun AdBlockingDetail(
    viewModel: AdGuardViewModel,
    onBack: () -> Unit,
    onFilters: () -> Unit,
    onExtensions: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsState()
    val settings = state.settings
    val enabledFilters = state.filterLists.count { it.isEnabled && !it.isCustom }
    val enabledRules = state.filterLists
        .filter { it.isEnabled && !it.isCustom }
        .sumOf { it.ruleCount }
    val scriptsOn = state.userscripts.count { it.isEnabled }

    DetailScaffold(onBack = onBack, modifier = modifier) {
        ModuleDetailHero(
            icon = Icons.Default.Block,
            tint = AdGuardGreenPrimary,
            title = stringResource(R.string.home_module_adblock_title),
            subtitle = stringResource(R.string.home_module_adblock_subtitle),
        )

        SettingsSwitch(
            icon = Icons.Default.Block,
            title = stringResource(R.string.home_module_adblock_title),
            subtitle = stringResource(R.string.home_module_adblock_subtitle),
            checked = settings.isAdBlockingEnabled,
            onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleAdBlocking) },
        )

        Spacer(modifier = Modifier.height(10.dp))

        NavigationRow(
            icon = Icons.Default.Layers,
            accent = AdGuardGreenLight,
            title = stringResource(R.string.protection_filters_row),
            subtitle = if (enabledFilters == 0) {
                stringResource(R.string.protection_filters_empty)
            } else {
                stringResource(
                    R.string.protection_filters_summary,
                    enabledFilters,
                    "%,d".format(enabledRules),
                )
            },
            onClick = onFilters,
        )

        Spacer(modifier = Modifier.height(10.dp))

        NavigationRow(
            icon = Icons.Default.Extension,
            accent = AdGuardPurpleAI,
            title = stringResource(R.string.hub_extensions_title),
            subtitle = when {
                state.userscripts.isEmpty() -> stringResource(R.string.hub_extensions_none)
                !state.scriptsMasterEnabled -> stringResource(R.string.hub_extensions_master_off)
                else -> stringResource(
                    R.string.hub_extensions_count,
                    scriptsOn,
                    state.userscripts.size,
                )
            },
            onClick = onExtensions,
        )

        Spacer(modifier = Modifier.height(18.dp))

        SettingsSwitch(
            icon = Icons.Default.VisibilityOff,
            title = stringResource(R.string.settings_cosmetic_title),
            subtitle = stringResource(R.string.settings_cosmetic_subtitle),
            checked = settings.cosmeticFiltering,
            onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleCosmeticFiltering(it)) },
        )

        Spacer(modifier = Modifier.height(10.dp))

        SettingsSwitch(
            icon = Icons.Default.BatteryChargingFull,
            title = stringResource(R.string.settings_smart_filtering_title),
            subtitle = stringResource(R.string.settings_smart_filtering_subtitle),
            checked = settings.isSmartFilteringEnabled,
            onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleSmartFiltering(it)) },
        )

        Spacer(modifier = Modifier.height(18.dp))

        Text(
            text = stringResource(R.string.settings_auto_update_title),
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextSecondary,
        )
        Text(
            text = stringResource(R.string.settings_auto_update_subtitle),
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
            title = stringResource(R.string.home_module_tracking_title),
            subtitle = stringResource(R.string.home_module_tracking_subtitle),
        )

        SettingsSwitch(
            icon = Icons.Default.TrackChanges,
            title = stringResource(R.string.home_module_tracking_title),
            subtitle = stringResource(R.string.home_module_tracking_subtitle),
            checked = settings.isTrackingProtectionEnabled,
            onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleTracking) },
        )

        Spacer(modifier = Modifier.height(18.dp))

        Text(
            text = stringResource(R.string.settings_stealth_title),
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextSecondary,
        )

        Spacer(modifier = Modifier.height(8.dp))

        SettingsSwitch(
            icon = Icons.Default.VisibilityOff,
            title = stringResource(R.string.settings_stealth_master_title),
            subtitle = stringResource(R.string.settings_stealth_master_subtitle),
            checked = settings.isStealthModeEnabled,
            onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleStealth) },
        )

        Spacer(modifier = Modifier.height(10.dp))

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                StealthToggleRow(
                    title = stringResource(R.string.settings_stealth_utm_title),
                    subtitle = stringResource(R.string.settings_stealth_utm_subtitle),
                    isChecked = settings.stripUtmTracking,
                    enabled = settings.isStealthModeEnabled,
                    onCheckedChange = {
                        viewModel.onIntent(AdGuardIntent.UpdateStealth(stripUtm = it))
                    },
                )
                Spacer(modifier = Modifier.height(12.dp))
                StealthToggleRow(
                    title = stringResource(R.string.settings_stealth_webrtc_title),
                    subtitle = stringResource(R.string.settings_stealth_webrtc_subtitle),
                    isChecked = settings.blockWebRtcLeaks,
                    enabled = settings.isStealthModeEnabled,
                    onCheckedChange = {
                        viewModel.onIntent(AdGuardIntent.UpdateStealth(blockWebRtc = it))
                    },
                )
                Spacer(modifier = Modifier.height(12.dp))
                StealthToggleRow(
                    title = stringResource(R.string.settings_stealth_ua_title),
                    subtitle = stringResource(R.string.settings_stealth_ua_subtitle),
                    isChecked = settings.disguiseUserAgent,
                    enabled = settings.isStealthModeEnabled,
                    onCheckedChange = {
                        viewModel.onIntent(AdGuardIntent.UpdateStealth(disguiseUa = it))
                    },
                )
                Spacer(modifier = Modifier.height(12.dp))
                StealthToggleRow(
                    title = stringResource(R.string.settings_stealth_cookies_title),
                    subtitle = stringResource(R.string.settings_stealth_cookies_subtitle),
                    isChecked = settings.blockThirdPartyCookies,
                    enabled = settings.isStealthModeEnabled,
                    onCheckedChange = {
                        viewModel.onIntent(AdGuardIntent.UpdateStealth(blockCookies = it))
                    },
                )
            }
        }
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
            title = stringResource(R.string.settings_https_title),
            subtitle = stringResource(R.string.settings_https_body),
        )

        HttpsFilterSection(
            viewModel = viewModel,
            fullEchEnabled = state.settings.isFullEchEnabled,
            onManageScripts = onManageScripts,
        )
    }
}

@Composable
private fun FirewallDetail(
    viewModel: AdGuardViewModel,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsState()
    val limitedApps = state.appFirewallRules.count {
        !it.isCellularAllowed || !it.isWifiAllowed
    }

    DetailScaffold(onBack = onBack, modifier = modifier) {
        ModuleDetailHero(
            icon = Icons.Default.Shield,
            tint = AdGuardGreenPrimary,
            title = stringResource(R.string.home_module_firewall_title),
            subtitle = stringResource(R.string.home_module_firewall_subtitle),
        )

        SettingsSwitch(
            icon = Icons.Default.Shield,
            title = stringResource(R.string.home_module_firewall_title),
            subtitle = stringResource(R.string.home_module_firewall_subtitle),
            checked = state.settings.isFirewallEnabled,
            onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleFirewall) },
        )

        Spacer(modifier = Modifier.height(10.dp))

        NavigationRow(
            icon = Icons.Default.Apps,
            accent = AdGuardBlueDns,
            title = stringResource(R.string.protection_firewall_apps),
            subtitle = if (limitedApps == 0) {
                stringResource(R.string.protection_firewall_apps_none)
            } else {
                stringResource(R.string.protection_firewall_apps_summary, limitedApps)
            },
            onClick = { viewModel.onIntent(AdGuardIntent.SelectTab(AdGuardTab.APPS)) },
        )
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
            title = stringResource(R.string.home_module_eco_title),
            subtitle = stringResource(R.string.home_module_eco_subtitle),
        )

        SettingsSwitch(
            icon = Icons.Default.BatteryChargingFull,
            title = stringResource(R.string.home_module_eco_title),
            subtitle = stringResource(R.string.home_module_eco_subtitle),
            checked = state.settings.isEcoBatteryModeEnabled,
            onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleEcoMode) },
        )

        Spacer(modifier = Modifier.height(12.dp))

        Text(
            text = stringResource(R.string.protection_eco_body),
            fontSize = 12.sp,
            color = AdGuardTextMuted,
        )
    }
}

/** Back arrow plus the scrolling body every module detail shares. */
@Composable
private fun DetailScaffold(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .background(AdGuardDarkBg),
    ) {
        IconButton(onClick = onBack) {
            Icon(
                imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                contentDescription = stringResource(R.string.hub_back),
                tint = AdGuardTextPrimary,
            )
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
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        border = BorderStroke(1.dp, AdGuardDarkOutline),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(38.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(accent.copy(alpha = 0.12f)),
            ) {
                Icon(icon, contentDescription = null, tint = accent, modifier = Modifier.size(20.dp))
            }
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = AdGuardTextPrimary,
                )
                Text(
                    text = subtitle,
                    fontSize = 11.sp,
                    color = AdGuardTextSecondary,
                )
            }
            Icon(
                imageVector = Icons.Default.ChevronRight,
                contentDescription = stringResource(R.string.protection_module_open),
                tint = AdGuardTextMuted,
                modifier = Modifier.size(18.dp),
            )
            Spacer(modifier = Modifier.width(4.dp))
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
private fun NavigationRow(
    icon: ImageVector,
    accent: Color,
    title: String,
    subtitle: String,
    onClick: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(34.dp)
                    .clip(RoundedCornerShape(9.dp))
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
            }
            Icon(
                imageVector = Icons.Default.ChevronRight,
                contentDescription = null,
                tint = AdGuardTextMuted,
                modifier = Modifier.size(20.dp),
            )
        }
    }
}

/** Label for the auto-update chips; 0 means "off". */
@Composable
private fun autoUpdateLabel(hours: Int): String =
    if (hours <= 0) stringResource(R.string.settings_auto_update_off)
    else stringResource(R.string.settings_auto_update_hours, hours)

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
                contentDescription = stringResource(R.string.hub_back),
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
