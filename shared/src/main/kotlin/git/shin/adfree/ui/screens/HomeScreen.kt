package git.shin.adfree.ui.screens

import git.shin.adfree.l10n.Strings
import git.shin.adfree.l10n.L10n
import git.shin.adfree.platform.OnResumeTick
import git.shin.adfree.platform.currentPlatformHost
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BatteryChargingFull
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.NotificationsActive
import androidx.compose.material.icons.filled.NotificationsOff
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.TrackChanges
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import git.shin.adfree.model.CountFormat
import git.shin.adfree.model.ProtectionStats
import git.shin.adfree.ui.AdGuardIntent
import git.shin.adfree.ui.AdGuardTab
import git.shin.adfree.ui.AdGuardUiState
import git.shin.adfree.ui.AdGuardViewModel
import git.shin.adfree.ui.theme.AdGuardBlueDns
import git.shin.adfree.ui.theme.AdGuardDarkBg
import git.shin.adfree.ui.theme.AdGuardDarkOutline
import git.shin.adfree.ui.theme.AdGuardDarkSurface
import git.shin.adfree.ui.theme.AdGuardGreenLight
import git.shin.adfree.ui.theme.AdGuardGreenPrimary
import git.shin.adfree.ui.theme.AdGuardOrangeWarning
import git.shin.adfree.ui.theme.AdGuardRedBlocked
import git.shin.adfree.ui.theme.AdGuardTextMuted
import git.shin.adfree.ui.theme.AdGuardTextPrimary
import git.shin.adfree.ui.theme.AdGuardTextSecondary
import git.shin.adfree.ui.theme.UiSize
import git.shin.adfree.ui.theme.isDesktopLayout

/**
 * The home tab: the power switch, a compact row of module switches, and the
 * numbers the tunnel produced.
 *
 * Deliberately short — the per-module options live behind the Protection tab,
 * the way the reference client lays it out, so this screen never turns into a
 * long settings list.
 */
@Composable
fun HomeScreen(
    viewModel: AdGuardViewModel,
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()
    val privateDnsOn by viewModel.privateDnsOn.collectAsState()
    val platform = currentPlatformHost()
    val scope = rememberCoroutineScope()

    // The switch lives in the system settings, so re-read it on every return;
    // the same call re-pushes the effective DoT policy to the core.
    OnResumeTick { viewModel.refreshPrivateDnsState() }

    if (isDesktopLayout) {
        DesktopHome(
            state = state,
            privateDnsOn = privateDnsOn,
            modifier = modifier,
            onToggle = { viewModel.onIntent(AdGuardIntent.ToggleProtection) },
            onOpenStatistics = {
                viewModel.onIntent(AdGuardIntent.SelectTab(AdGuardTab.STATISTICS))
            },
            onOpenPrivateDns = { platform.openPrivateDnsSettings() },
            quickModuleRow = {
                QuickModuleRow(
                    adBlocking = state.settings.isAdBlockingEnabled,
                    tracking = state.settings.isTrackingProtectionEnabled,
                    dns = state.settings.isDnsProtectionEnabled,
                    https = state.settings.isHttpsFilteringEnabled,
                    firewall = state.settings.isFirewallEnabled,
                    eco = state.settings.isEcoBatteryModeEnabled,
                    onAdBlocking = { viewModel.onIntent(AdGuardIntent.ToggleAdBlocking) },
                    onTracking = { viewModel.onIntent(AdGuardIntent.ToggleTracking) },
                    onDns = { viewModel.onIntent(AdGuardIntent.ToggleDns) },
                    onHttps = { viewModel.onIntent(AdGuardIntent.ToggleHttps) },
                    onFirewall = { viewModel.onIntent(AdGuardIntent.ToggleFirewall) },
                    onEco = { viewModel.onIntent(AdGuardIntent.ToggleEcoMode) },
                )
            },
        )
        return
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(AdGuardDarkBg),
    ) {
        HomeHeader(
            isActive = state.isVpnActive,
        )

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            QuickModuleRow(
                adBlocking = state.settings.isAdBlockingEnabled,
                tracking = state.settings.isTrackingProtectionEnabled,
                dns = state.settings.isDnsProtectionEnabled,
                https = state.settings.isHttpsFilteringEnabled,
                firewall = state.settings.isFirewallEnabled,
                eco = state.settings.isEcoBatteryModeEnabled,
                onAdBlocking = { viewModel.onIntent(AdGuardIntent.ToggleAdBlocking) },
                onTracking = { viewModel.onIntent(AdGuardIntent.ToggleTracking) },
                onDns = { viewModel.onIntent(AdGuardIntent.ToggleDns) },
                onHttps = { viewModel.onIntent(AdGuardIntent.ToggleHttps) },
                onFirewall = { viewModel.onIntent(AdGuardIntent.ToggleFirewall) },
                onEco = { viewModel.onIntent(AdGuardIntent.ToggleEcoMode) },
            )

            Spacer(modifier = Modifier.height(6.dp))

            AdGuardShieldHero(
                isActive = state.isVpnActive,
                onToggle = { viewModel.onIntent(AdGuardIntent.ToggleProtection) }
            )

            Spacer(modifier = Modifier.height(14.dp))

            HomeSystemStatusRow()

            if (privateDnsOn) {
                Spacer(modifier = Modifier.height(16.dp))
                PrivateDnsWarningCard(
                    onOpenSettings = { platform.openPrivateDnsSettings() }
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            StatsGrid(
                stats = state.stats,
                onCardClick = { viewModel.onIntent(AdGuardIntent.SelectTab(AdGuardTab.STATISTICS)) }
            )

            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}

/** App identity plus the live on/off state. No build or rule counts. */
@Composable
private fun HomeHeader(isActive: Boolean) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 10.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                imageVector = Icons.Default.Shield,
                contentDescription = null,
                tint = AdGuardGreenPrimary,
                modifier = Modifier.size(26.dp)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = L10n.get(Strings.app_name),
                fontWeight = FontWeight.Bold,
                fontSize = 19.sp,
                color = AdGuardTextPrimary
            )
        }

        StatusChip(isActive = isActive)
    }
}

@Composable
private fun StatusChip(isActive: Boolean) {
    val tint = if (isActive) AdGuardGreenPrimary else AdGuardRedBlocked
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(20.dp))
            .background(tint.copy(alpha = 0.15f))
            .padding(horizontal = 10.dp, vertical = 5.dp)
    ) {
        Text(
            text = if (isActive) L10n.get(Strings.home_status_filtering)
            else L10n.get(Strings.home_status_paused),
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            color = tint
        )
    }
}

/**
 * The two system-level checks AdGuard surfaces on its dashboard: whether the
 * app may post notifications (the ongoing protection status is invisible
 * without them) and whether the OS battery optimizer is exempting the tunnel.
 * Each chip opens the system screen that changes the answer.
 */
@Composable
private fun HomeSystemStatusRow() {
    val platform = currentPlatformHost()
    val scope = rememberCoroutineScope()
    val showNotifications = platform.supportsNotifications()
    val showBattery = platform.supportsBatteryOptimization()
    var notificationsOn by remember { mutableStateOf(platform.notificationsEnabled()) }
    var batteryOptimized by remember { mutableStateOf(!platform.ignoringBatteryOptimizations()) }

    fun refresh() {
        notificationsOn = platform.notificationsEnabled()
        batteryOptimized = !platform.ignoringBatteryOptimizations()
    }

    OnResumeTick {
        refresh()
        // MIUI and other OEMs persist their per-app power policy slightly
        // after the settings activity closes, so the read taken on resume can
        // still see the old value. Re-read while the chip is complaining.
        if (batteryOptimized) {
            scope.launch {
                repeat(3) {
                    delay(1_000)
                    batteryOptimized = !platform.ignoringBatteryOptimizations()
                    if (!batteryOptimized) return@launch
                }
            }
        }
    }

    if (!showNotifications && !showBattery) return

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        if (showNotifications) {
            SystemStatusChip(
                icon = if (notificationsOn) Icons.Default.NotificationsActive
                else Icons.Default.NotificationsOff,
                title = L10n.get(Strings.home_health_notifications),
                value = L10n.get(if (notificationsOn) Strings.home_health_notifications_on
                    else Strings.home_health_notifications_off
                ),
                ok = notificationsOn,
                onClick = { platform.requestNotificationPermission() },
                modifier = Modifier
                    .weight(1f)
                    .testTag("home_status_notifications"),
            )
        }
        if (showBattery) {
            SystemStatusChip(
                icon = Icons.Default.BatteryChargingFull,
                title = L10n.get(Strings.home_health_battery),
                value = L10n.get(if (batteryOptimized) Strings.home_health_battery_on
                    else Strings.home_health_battery_ok
                ),
                ok = !batteryOptimized,
                onClick = {
                    if (batteryOptimized) platform.requestIgnoreBatteryOptimizations()
                    else platform.openBatterySettings()
                },
                modifier = Modifier
                    .weight(1f)
                    .testTag("home_status_battery"),
            )
        }
    }
}

@Composable
private fun SystemStatusChip(
    icon: ImageVector,
    title: String,
    value: String,
    ok: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val accent = if (ok) AdGuardGreenPrimary else AdGuardOrangeWarning
    Row(
        modifier = modifier
            .clip(RoundedCornerShape(12.dp))
            .background(AdGuardDarkSurface)
            .border(1.dp, accent.copy(alpha = 0.35f), RoundedCornerShape(12.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 10.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier
                .size(26.dp)
                .clip(RoundedCornerShape(8.dp))
                .background(accent.copy(alpha = 0.15f)),
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = accent,
                modifier = Modifier.size(15.dp),
            )
        }
        Spacer(modifier = Modifier.width(8.dp))
        Column {
            Text(
                text = title,
                fontSize = 11.sp,
                color = AdGuardTextPrimary,
                maxLines = 1,
            )
            Text(
                text = value,
                fontSize = 10.sp,
                fontWeight = FontWeight.SemiBold,
                color = accent,
                maxLines = 1,
            )
        }
    }
}


/**
 * Shown while Android's Private DNS is on. The core stops resetting port 853
 * in that mode (otherwise strict mode loses all resolution), which means DNS
 * filtering cannot see those lookups; the user gets the trade and a shortcut
 * to the system switch instead of a silently weaker app.
 */
@Composable
private fun PrivateDnsWarningCard(onOpenSettings: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(
            containerColor = AdGuardOrangeWarning.copy(alpha = 0.12f),
        ),
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Default.Warning,
                    contentDescription = null,
                    tint = AdGuardOrangeWarning,
                    modifier = Modifier.size(18.dp),
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = L10n.get(Strings.home_private_dns_title),
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextPrimary,
                )
            }
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = L10n.get(Strings.home_private_dns_body),
                fontSize = 11.sp,
                color = AdGuardTextSecondary,
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedButton(
                onClick = onOpenSettings,
                shape = RoundedCornerShape(8.dp),
            ) {
                Text(L10n.get(Strings.home_private_dns_open), fontSize = 11.sp)
            }
        }
    }
}

/**
 * One row, one tap per module, the way the reference client shows them: the
 * icon carries the state, so six switches fit above the power button.
 */
@Composable
private fun QuickModuleRow(
    adBlocking: Boolean,
    tracking: Boolean,
    dns: Boolean,
    https: Boolean,
    firewall: Boolean,
    eco: Boolean,
    onAdBlocking: () -> Unit,
    onTracking: () -> Unit,
    onDns: () -> Unit,
    onHttps: () -> Unit,
    onFirewall: () -> Unit,
    onEco: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 4.dp),
        horizontalArrangement = Arrangement.SpaceEvenly,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        QuickModuleToggle(
            icon = Icons.Default.Block,
            label = L10n.get(Strings.home_quick_ads),
            active = adBlocking,
            accent = AdGuardGreenPrimary,
            onClick = onAdBlocking,
            modifier = Modifier.weight(1f),
        )
        QuickModuleToggle(
            icon = Icons.Default.TrackChanges,
            label = L10n.get(Strings.home_quick_tracking),
            active = tracking,
            accent = AdGuardOrangeWarning,
            onClick = onTracking,
            modifier = Modifier.weight(1f),
        )
        QuickModuleToggle(
            icon = Icons.Default.Dns,
            label = L10n.get(Strings.home_quick_dns),
            active = dns,
            accent = AdGuardBlueDns,
            onClick = onDns,
            modifier = Modifier.weight(1f),
        )
        QuickModuleToggle(
            icon = Icons.Default.Lock,
            label = L10n.get(Strings.home_quick_https),
            active = https,
            accent = Color(0xFFB48CFF),
            onClick = onHttps,
            modifier = Modifier.weight(1f),
        )
        QuickModuleToggle(
            icon = Icons.Default.Shield,
            label = L10n.get(Strings.home_quick_firewall),
            active = firewall,
            accent = AdGuardGreenPrimary,
            onClick = onFirewall,
            modifier = Modifier.weight(1f),
        )
        QuickModuleToggle(
            icon = Icons.Default.BatteryChargingFull,
            label = L10n.get(Strings.home_quick_eco),
            active = eco,
            accent = AdGuardGreenLight,
            onClick = onEco,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun QuickModuleToggle(
    icon: ImageVector,
    label: String,
    active: Boolean,
    accent: Color,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = modifier
            .clip(RoundedCornerShape(12.dp))
            .clickable(onClick = onClick)
            .padding(vertical = 6.dp)
            .testTag("quick_$label"),
    ) {
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier
                .size(40.dp)
                .clip(RoundedCornerShape(13.dp))
                .background(
                    if (active) accent.copy(alpha = 0.16f) else AdGuardDarkSurface
                ),
        ) {
            Icon(
                imageVector = icon,
                contentDescription = label,
                tint = if (active) accent else AdGuardTextMuted,
                modifier = Modifier.size(21.dp),
            )
        }
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = label,
            fontSize = 10.sp,
            fontWeight = if (active) FontWeight.SemiBold else FontWeight.Normal,
            color = if (active) AdGuardTextPrimary else AdGuardTextMuted,
            maxLines = 1,
        )
    }
}

/** The power button. Doubles as the protection switch. */
@Composable
fun AdGuardShieldHero(
    isActive: Boolean,
    onToggle: () -> Unit
) {
    val shieldBgColor by animateColorAsState(
        targetValue = if (isActive) AdGuardGreenPrimary else Color(0xFF232D37),
        label = "shieldColor"
    )

    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier.fillMaxWidth()
    ) {
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier
                .size(108.dp)
                .clickable { onToggle() }
                .testTag("shield_power_toggle")
        ) {
            // The rings are drawn well inside the box: the older version scaled
            // them past the box edge, and everything outside was simply clipped
            // away by the layout bounds.
            if (isActive) {
                Canvas(modifier = Modifier.fillMaxSize()) {
                    val base = size.minDimension * 0.40f
                    val radius = base + size.minDimension * 0.055f
                    drawCircle(color = Color(0x1A00D06C), radius = radius)
                    drawCircle(color = Color(0x2800D06C), radius = radius * 0.88f)
                }
            }

            // The button itself, always drawn: it used to sit inside the
            // `isActive` block, so it vanished from the screen whenever the
            // protection was off and left only the caption behind.
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(76.dp)
                    .clip(CircleShape)
                    .background(
                        Brush.radialGradient(
                            colors = if (isActive) listOf(
                                Color(0xFF00FF85),
                                AdGuardGreenPrimary,
                                Color(0xFF008040)
                            ) else listOf(
                                Color(0xFF374653),
                                Color(0xFF232D37),
                                Color(0xFF141A20)
                            )
                        )
                    )
                    .border(
                        width = 2.dp,
                        color = if (isActive) Color(0x88FFFFFF) else AdGuardDarkOutline,
                        shape = CircleShape
                    )
            ) {
                Icon(
                    imageVector = Icons.Default.PowerSettingsNew,
                    contentDescription = L10n.get(Strings.home_shield_toggle),
                    tint = if (isActive) Color.Black else Color(0xFF8B9DAF),
                    modifier = Modifier.size(44.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        Text(
            text = if (isActive) L10n.get(Strings.home_shield_protected)
            else L10n.get(Strings.home_shield_off),
            fontSize = 15.sp,
            fontWeight = FontWeight.SemiBold,
            color = if (isActive) AdGuardGreenLight else AdGuardTextMuted
        )
    }
}

/** Four counters, two per row, each one opening the filtering log. */
@Composable
private fun StatsGrid(
    stats: ProtectionStats,
    onCardClick: () -> Unit = {}
) {

    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            StatCard(
                title = L10n.get(Strings.home_stat_ads),
                value = CountFormat.compact(stats.adsBlocked),
                icon = Icons.Default.Block,
                accentColor = AdGuardGreenPrimary,
                onClick = onCardClick,
                modifier = Modifier.weight(1f)
            )
            StatCard(
                title = L10n.get(Strings.home_stat_trackers),
                value = CountFormat.compact(stats.trackersBlocked),
                icon = Icons.Default.TrackChanges,
                accentColor = AdGuardOrangeWarning,
                onClick = onCardClick,
                modifier = Modifier.weight(1f)
            )
        }

        Spacer(modifier = Modifier.height(10.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            StatCard(
                title = L10n.get(Strings.home_stat_data),
                value = L10n.format(Strings.home_stat_data_value, CountFormat.data(stats.dataSavedBytes)),
                icon = Icons.Default.CloudDownload,
                accentColor = AdGuardBlueDns,
                onClick = onCardClick,
                modifier = Modifier.weight(1f)
            )
            StatCard(
                title = L10n.get(Strings.home_stat_battery),
                value = L10n.format(Strings.home_stat_battery_value,
                    stats.estimatedBatterySavedPercent,
                ),
                icon = Icons.Default.BatteryChargingFull,
                accentColor = AdGuardGreenLight,
                onClick = onCardClick,
                modifier = Modifier.weight(1f)
            )
        }
    }
}

@Composable
private fun StatCard(
    title: String,
    value: String,
    icon: ImageVector,
    accentColor: Color,
    onClick: () -> Unit = {},
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier.clickable { onClick() },
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        border = CardDefaults.outlinedCardBorder().copy(
            brush = Brush.linearGradient(
                listOf(AdGuardDarkOutline, accentColor.copy(alpha = 0.2f))
            )
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(10.dp)
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = accentColor,
                modifier = Modifier.size(18.dp)
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = value,
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextPrimary
            )
            Text(
                text = title,
                fontSize = 11.sp,
                color = AdGuardTextMuted
            )
        }
    }
}


/**
 * The desktop home, drawn the way AdGuard for Windows draws its own: one
 * centred state, said once in a big line, with the switch right under it.
 *
 * The phone body stacks four stat cards under the power button because a
 * 400dp screen has nowhere else to put them. On a window this wide that grid
 * stretches into four wide, mostly-empty tiles, which is exactly what made
 * the app read as a phone screenshot blown up: here the counters become one
 * strip of numbers on the bare surface, separated by hairlines.
 */
@Composable
private fun DesktopHome(
    state: AdGuardUiState,
    privateDnsOn: Boolean,
    modifier: Modifier = Modifier,
    onToggle: () -> Unit,
    onOpenStatistics: () -> Unit,
    onOpenPrivateDns: () -> Unit,
    quickModuleRow: @Composable () -> Unit,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .background(AdGuardDarkBg)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = UiSize.gutter.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(modifier = Modifier.height(18.dp))

        // Six switches spread over 1090dp read as six islands. AdGuard keeps
        // this row as one cluster under the status, so it gets a width.
        Box(modifier = Modifier.widthIn(max = 560.dp)) {
            quickModuleRow()
        }

        Spacer(modifier = Modifier.height(26.dp))

        Text(
            text = if (state.isVpnActive) L10n.get(Strings.home_shield_protected)
            else L10n.get(Strings.home_shield_off),
            fontSize = 26.sp,
            fontWeight = FontWeight.Bold,
            color = if (state.isVpnActive) AdGuardTextPrimary else AdGuardTextMuted,
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = L10n.get(
                if (state.isVpnActive) Strings.home_state_subtitle_on
                else Strings.home_state_subtitle_off
            ),
            fontSize = 12.5.sp,
            color = AdGuardTextMuted,
        )

        Spacer(modifier = Modifier.height(18.dp))

        ProtectionSwitch(isActive = state.isVpnActive, onToggle = onToggle)

        Spacer(modifier = Modifier.height(30.dp))

        DesktopStatStrip(stats = state.stats, onClick = onOpenStatistics)

        if (privateDnsOn) {
            Spacer(modifier = Modifier.height(UiSize.sectionGap.dp))
            PrivateDnsWarningCard(onOpenSettings = onOpenPrivateDns)
        }

        Spacer(modifier = Modifier.height(24.dp))
    }
}

/** The pill switch AdGuard for Windows puts under the state line. */
@Composable
private fun ProtectionSwitch(isActive: Boolean, onToggle: () -> Unit) {
    val track by animateColorAsState(
        targetValue = if (isActive) AdGuardGreenPrimary else Color(0xFF2C3A46),
        label = "switchTrack",
    )
    val knobX by animateFloatAsState(
        targetValue = if (isActive) 1f else 0f,
        label = "switchKnob",
    )
    Box(
        modifier = Modifier
            .width(62.dp)
            .height(32.dp)
            .clip(RoundedCornerShape(16.dp))
            .background(track)
            .border(
                1.dp,
                if (isActive) Color(0x55FFFFFF) else AdGuardDarkOutline,
                RoundedCornerShape(16.dp),
            )
            .clickable(onClick = onToggle)
            .testTag("shield_power_toggle"),
        contentAlignment = Alignment.CenterStart,
    ) {
        Box(
            modifier = Modifier
                .padding(start = 3.dp)
                .offset(x = 30.dp * knobX)
                .size(26.dp)
                .clip(CircleShape)
                .background(Color.White),
        )
    }
}

/** Four counters on one line, the way the reference client lists numbers. */
@Composable
private fun DesktopStatStrip(stats: ProtectionStats, onClick: () -> Unit) {
    val cells = listOf(
        CountFormat.compact(stats.adsBlocked) to L10n.get(Strings.home_stat_ads),
        CountFormat.compact(stats.trackersBlocked) to L10n.get(Strings.home_stat_trackers),
        L10n.format(Strings.home_stat_data_value, CountFormat.data(stats.dataSavedBytes)) to
            L10n.get(Strings.home_stat_data),
        L10n.format(Strings.home_stat_battery_value, stats.estimatedBatterySavedPercent) to
            L10n.get(Strings.home_stat_battery),
    )
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(AdGuardDarkSurface)
            .clickable(onClick = onClick)
            .testTag("home_stat_strip")
            .padding(vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        cells.forEachIndexed { index, (value, label) ->
            if (index > 0) {
                Box(
                    modifier = Modifier
                        .width(1.dp)
                        .height(28.dp)
                        .background(AdGuardTextMuted.copy(alpha = 0.16f)),
                )
            }
            Column(
                modifier = Modifier.weight(1f),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    text = value,
                    fontSize = 17.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextPrimary,
                    maxLines = 1,
                )
                Text(
                    text = label,
                    fontSize = 11.sp,
                    color = AdGuardTextMuted,
                    maxLines = 1,
                )
            }
        }
    }
}
