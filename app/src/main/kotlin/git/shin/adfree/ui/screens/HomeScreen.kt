package git.shin.adfree.ui.screens

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import git.shin.adfree.R
import git.shin.adfree.model.ProtectionStats
import git.shin.adfree.ui.AdGuardIntent
import git.shin.adfree.ui.AdGuardTab
import git.shin.adfree.ui.AdGuardViewModel
import git.shin.adfree.vpn.PrivateDns
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
    val context = LocalContext.current

    // The switch lives in the system settings, so re-read it on every return;
    // the same call re-pushes the effective DoT policy to the core.
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { viewModel.refreshPrivateDnsState() }

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

            if (privateDnsOn) {
                Spacer(modifier = Modifier.height(16.dp))
                PrivateDnsWarningCard(
                    onOpenSettings = { PrivateDns.openSettings(context) }
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            StatsGrid(
                stats = state.stats,
                onCardClick = { viewModel.onIntent(AdGuardIntent.SelectTab(AdGuardTab.ACTIVITY)) }
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
                text = stringResource(R.string.app_name),
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
            text = if (isActive) stringResource(R.string.home_status_filtering)
            else stringResource(R.string.home_status_paused),
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            color = tint
        )
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
                    text = stringResource(R.string.home_private_dns_title),
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextPrimary,
                )
            }
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = stringResource(R.string.home_private_dns_body),
                fontSize = 11.sp,
                color = AdGuardTextSecondary,
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedButton(
                onClick = onOpenSettings,
                shape = RoundedCornerShape(8.dp),
            ) {
                Text(stringResource(R.string.home_private_dns_open), fontSize = 11.sp)
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
            label = stringResource(R.string.home_quick_ads),
            active = adBlocking,
            accent = AdGuardGreenPrimary,
            onClick = onAdBlocking,
            modifier = Modifier.weight(1f),
        )
        QuickModuleToggle(
            icon = Icons.Default.TrackChanges,
            label = stringResource(R.string.home_quick_tracking),
            active = tracking,
            accent = AdGuardOrangeWarning,
            onClick = onTracking,
            modifier = Modifier.weight(1f),
        )
        QuickModuleToggle(
            icon = Icons.Default.Dns,
            label = stringResource(R.string.home_quick_dns),
            active = dns,
            accent = AdGuardBlueDns,
            onClick = onDns,
            modifier = Modifier.weight(1f),
        )
        QuickModuleToggle(
            icon = Icons.Default.Lock,
            label = stringResource(R.string.home_quick_https),
            active = https,
            accent = Color(0xFFB48CFF),
            onClick = onHttps,
            modifier = Modifier.weight(1f),
        )
        QuickModuleToggle(
            icon = Icons.Default.Shield,
            label = stringResource(R.string.home_quick_firewall),
            active = firewall,
            accent = AdGuardGreenPrimary,
            onClick = onFirewall,
            modifier = Modifier.weight(1f),
        )
        QuickModuleToggle(
            icon = Icons.Default.BatteryChargingFull,
            label = stringResource(R.string.home_quick_eco),
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
    val infiniteTransition = rememberInfiniteTransition(label = "pulse")
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = 1.08f,
        animationSpec = infiniteRepeatable(
            animation = tween(1800, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulseScale"
    )

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
                    val radius = base + (size.minDimension * 0.055f) * pulseScale
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
                    contentDescription = stringResource(R.string.home_shield_toggle),
                    tint = if (isActive) Color.Black else Color(0xFF8B9DAF),
                    modifier = Modifier.size(44.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        Text(
            text = if (isActive) stringResource(R.string.home_shield_protected)
            else stringResource(R.string.home_shield_off),
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
    val dataMb = stats.dataSavedBytes / (1024 * 1024)

    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            StatCard(
                title = stringResource(R.string.home_stat_ads),
                value = stats.adsBlocked.toString(),
                icon = Icons.Default.Block,
                accentColor = AdGuardGreenPrimary,
                onClick = onCardClick,
                modifier = Modifier.weight(1f)
            )
            StatCard(
                title = stringResource(R.string.home_stat_trackers),
                value = stats.trackersBlocked.toString(),
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
                title = stringResource(R.string.home_stat_data),
                value = stringResource(R.string.home_stat_data_value, dataMb),
                icon = Icons.Default.CloudDownload,
                accentColor = AdGuardBlueDns,
                onClick = onCardClick,
                modifier = Modifier.weight(1f)
            )
            StatCard(
                title = stringResource(R.string.home_stat_battery),
                value = stringResource(
                    R.string.home_stat_battery_value,
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

