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
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.TrackChanges
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
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
 * The protection tab: one big switch, the numbers it produced, and the modules
 * it can switch off.
 *
 * Deliberately short — everything here fits without scrolling, the way the
 * reference client lays it out. Only the module list scrolls, and it is capped
 * at four real modules rather than every flag the engine supports.
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

            SectionTitle(stringResource(R.string.home_modules_title))

            Spacer(modifier = Modifier.height(8.dp))

            ModuleToggleCard(
                title = stringResource(R.string.home_module_adblock_title),
                subtitle = stringResource(R.string.home_module_adblock_subtitle),
                icon = Icons.Default.Block,
                isChecked = state.settings.isAdBlockingEnabled,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleAdBlocking) },
                accentColor = AdGuardGreenPrimary
            )

            ModuleRow()

            ModuleToggleCard(
                title = stringResource(R.string.home_module_tracking_title),
                subtitle = stringResource(R.string.home_module_tracking_subtitle),
                icon = Icons.Default.TrackChanges,
                isChecked = state.settings.isTrackingProtectionEnabled,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleTracking) },
                accentColor = AdGuardOrangeWarning
            )

            ModuleRow()

            ModuleToggleCard(
                title = stringResource(R.string.home_module_dns_title),
                subtitle = stringResource(R.string.home_module_dns_subtitle),
                icon = Icons.Default.Dns,
                isChecked = state.settings.isDnsProtectionEnabled,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleDns) },
                accentColor = AdGuardBlueDns
            )

            ModuleRow()

            ModuleToggleCard(
                title = stringResource(R.string.home_module_firewall_title),
                subtitle = stringResource(R.string.home_module_firewall_subtitle),
                icon = Icons.Default.Shield,
                isChecked = state.settings.isFirewallEnabled,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleFirewall) },
                accentColor = AdGuardGreenPrimary
            )

            ModuleRow()

            ModuleToggleCard(
                title = stringResource(R.string.home_module_eco_title),
                subtitle = stringResource(R.string.home_module_eco_subtitle),
                icon = Icons.Default.BatteryChargingFull,
                isChecked = state.settings.isEcoBatteryModeEnabled,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleEcoMode) },
                accentColor = AdGuardGreenLight
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

@Composable
private fun SectionTitle(text: String) {
    Text(
        text = text,
        fontSize = 13.sp,
        fontWeight = FontWeight.Bold,
        color = AdGuardTextSecondary,
        modifier = Modifier.fillMaxWidth()
    )
}

/** Thin separator so the module list reads as one group. */
@Composable
private fun ModuleRow() {
    HorizontalDivider(
        color = AdGuardDarkOutline.copy(alpha = 0.5f),
        thickness = 0.5.dp,
        modifier = Modifier.padding(top = 7.dp, bottom = 7.dp)
    )
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

@Composable
private fun ModuleToggleCard(
    title: String,
    subtitle: String,
    icon: ImageVector,
    isChecked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    accentColor: Color
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onCheckedChange(!isChecked) },
        shape = RoundedCornerShape(0.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkBg),
        border = null
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 9.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(36.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(accentColor.copy(alpha = 0.15f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = accentColor,
                    modifier = Modifier.size(20.dp)
                )
            }

            Spacer(modifier = Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = AdGuardTextPrimary
                )
                Text(
                    text = subtitle,
                    fontSize = 12.sp,
                    color = AdGuardTextSecondary
                )
            }

            Switch(
                checked = isChecked,
                onCheckedChange = onCheckedChange,
                colors = SwitchDefaults.colors(
                    checkedThumbColor = Color.White,
                    checkedTrackColor = AdGuardGreenPrimary,
                    uncheckedThumbColor = AdGuardTextMuted,
                    uncheckedTrackColor = AdGuardDarkOutline
                )
            )
        }
    }
}
