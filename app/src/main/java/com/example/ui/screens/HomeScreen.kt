package com.example.ui.screens

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
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Science
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.TrackChanges
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
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
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.model.ProtectionSettings
import com.example.model.ProtectionStats
import com.example.ui.AdGuardIntent
import com.example.ui.AdGuardTab
import com.example.ui.AdGuardViewModel
import com.example.ui.theme.AdGuardBlueDns
import com.example.ui.theme.AdGuardDarkBg
import com.example.ui.theme.AdGuardDarkOutline
import com.example.ui.theme.AdGuardDarkSurface
import com.example.ui.theme.AdGuardDarkSurfaceVariant
import com.example.ui.theme.AdGuardGreenLight
import com.example.ui.theme.AdGuardGreenPrimary
import com.example.ui.theme.AdGuardOrangeWarning
import com.example.ui.theme.AdGuardPurpleAI
import com.example.ui.theme.AdGuardRedBlocked
import com.example.ui.theme.AdGuardTextMuted
import com.example.ui.theme.AdGuardTextPrimary
import com.example.ui.theme.AdGuardTextSecondary

@Composable
fun HomeScreen(
    viewModel: AdGuardViewModel,
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()
    val scrollState = rememberScrollState()

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(AdGuardDarkBg)
            .verticalScroll(scrollState)
            .padding(horizontal = 20.dp, vertical = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // App Header Branding
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Shield,
                        contentDescription = "AdGuard Logo",
                        tint = AdGuardGreenPrimary,
                        modifier = Modifier.size(24.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "ADFREE",
                        fontWeight = FontWeight.Black,
                        fontSize = 20.sp,
                        letterSpacing = 2.sp,
                        color = AdGuardTextPrimary
                    )
                    Text(
                        text = " ULTRA",
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp,
                        color = AdGuardGreenLight
                    )
                }
                Text(
                    text = "git.shin.adfree • Zero-Allocation Packet Interceptor",
                    fontSize = 11.sp,
                    color = AdGuardTextMuted
                )
            }

            // Engine status chip
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(20.dp))
                    .background(if (state.settings.isProtectionActive) Color(0x2200D06C) else Color(0x22FF435A))
                    .border(
                        1.dp,
                        if (state.settings.isProtectionActive) AdGuardGreenPrimary else AdGuardRedBlocked,
                        RoundedCornerShape(20.dp)
                    )
                    .padding(horizontal = 10.dp, vertical = 4.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(6.dp)
                            .clip(CircleShape)
                            .background(if (state.settings.isProtectionActive) AdGuardGreenPrimary else AdGuardRedBlocked)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = if (state.settings.isProtectionActive) "LIVE" else "PAUSED",
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = if (state.settings.isProtectionActive) AdGuardGreenPrimary else AdGuardRedBlocked
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(28.dp))

        // Big Iconic AdGuard Shield Toggle (MVI dispatch)
        AdGuardShieldHero(
            isActive = state.settings.isProtectionActive,
            onToggle = { viewModel.onIntent(AdGuardIntent.ToggleProtection) }
        )

        Spacer(modifier = Modifier.height(20.dp))

        // Sub-millisecond performance status banner
        HighEfficiencyEngineBanner(stats = state.stats, isSimMode = state.isSimulationModeEnabled)

        Spacer(modifier = Modifier.height(24.dp))

        // Stats Summary Cards (Ads, Trackers, Data, Battery)
        StatsGrid(
            stats = state.stats,
            onCardClick = { viewModel.onIntent(AdGuardIntent.SelectTab(AdGuardTab.ACTIVITY)) }
        )

        Spacer(modifier = Modifier.height(24.dp))

        // UI Simulation mode toggle card for user testing
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(14.dp),
            colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
            border = CardDefaults.outlinedCardBorder().copy(
                brush = Brush.horizontalGradient(
                    listOf(AdGuardDarkOutline, if (state.isSimulationModeEnabled) AdGuardPurpleAI.copy(alpha = 0.4f) else Color.Transparent)
                )
            )
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(
                    modifier = Modifier.weight(1f),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .size(36.dp)
                            .clip(RoundedCornerShape(8.dp))
                            .background(AdGuardPurpleAI.copy(alpha = 0.15f)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(Icons.Default.Science, contentDescription = null, tint = AdGuardPurpleAI, modifier = Modifier.size(20.dp))
                    }
                    Spacer(modifier = Modifier.width(12.dp))
                    Column {
                        Text(
                            text = "Dữ liệu Test UI (Simulation)",
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Bold,
                            color = AdGuardTextPrimary
                        )
                        Text(
                            text = if (state.isSimulationModeEnabled) "Đang phát gói tin giả lập để test" else "Đang nhận gói tin THẬT từ VPN TUN",
                            fontSize = 11.sp,
                            color = if (state.isSimulationModeEnabled) AdGuardPurpleAI else AdGuardGreenLight
                        )
                    }
                }

                Switch(
                    checked = state.isSimulationModeEnabled,
                    onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleSimulationMode(it)) },
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = Color.White,
                        checkedTrackColor = AdGuardPurpleAI,
                        uncheckedThumbColor = AdGuardTextMuted,
                        uncheckedTrackColor = AdGuardDarkSurfaceVariant
                    )
                )
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // Quick feature protection switches (MVI Dispatches)
        Text(
            text = "PROTECTION MODULES",
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextSecondary,
            letterSpacing = 1.sp,
            modifier = Modifier.fillMaxWidth()
        )

        Spacer(modifier = Modifier.height(12.dp))

        ModuleToggleCard(
            title = "Ad Blocking",
            subtitle = "Blocks display ads, video rolls & popups",
            icon = Icons.Default.Block,
            isChecked = state.settings.isAdBlockingEnabled,
            onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleAdBlocking) },
            accentColor = AdGuardGreenPrimary
        )

        Spacer(modifier = Modifier.height(10.dp))

        ModuleToggleCard(
            title = "Tracking Protection",
            subtitle = "Intercepts cross-app analytics & spyware telemetry",
            icon = Icons.Default.TrackChanges,
            isChecked = state.settings.isTrackingProtectionEnabled,
            onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleTracking) },
            accentColor = AdGuardOrangeWarning
        )

        Spacer(modifier = Modifier.height(10.dp))

        ModuleToggleCard(
            title = "DNS Protection",
            subtitle = "Encrypted DNS-over-HTTPS with zero ISP leak",
            icon = Icons.Default.Dns,
            isChecked = state.settings.isDnsProtectionEnabled,
            onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleDns) },
            accentColor = AdGuardBlueDns
        )

        Spacer(modifier = Modifier.height(10.dp))

        ModuleToggleCard(
            title = "Eco Battery Saver Mode",
            subtitle = "Early drop of TCP SYN packets (-14% CPU wakeups)",
            icon = Icons.Default.BatteryChargingFull,
            isChecked = state.settings.isEcoBatteryModeEnabled,
            onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleEcoMode) },
            accentColor = AdGuardGreenLight
        )

        Spacer(modifier = Modifier.height(10.dp))

        ModuleToggleCard(
            title = "Per-App Firewall",
            subtitle = "Control Wi-Fi & cellular rules per application",
            icon = Icons.Default.Security,
            isChecked = state.settings.isFirewallEnabled,
            onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleFirewall) },
            accentColor = Color(0xFFAB47BC)
        )

        Spacer(modifier = Modifier.height(24.dp))
    }
}

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
                .size(190.dp)
                .clickable { onToggle() }
                .testTag("shield_power_toggle")
        ) {
            if (isActive) {
                Canvas(modifier = Modifier.fillMaxSize()) {
                    val radius = (size.minDimension / 2f) * pulseScale
                    drawCircle(color = Color(0x1A00D06C), radius = radius)
                    drawCircle(color = Color(0x2800D06C), radius = radius * 0.88f)
                }
            }

            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(140.dp)
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
                        width = 3.dp,
                        color = if (isActive) Color(0x88FFFFFF) else AdGuardDarkOutline,
                        shape = CircleShape
                    )
            ) {
                Icon(
                    imageVector = Icons.Default.PowerSettingsNew,
                    contentDescription = "Toggle Protection",
                    tint = if (isActive) Color.Black else Color(0xFF8B9DAF),
                    modifier = Modifier.size(64.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        Text(
            text = if (isActive) "PROTECTION IS ENABLED" else "PROTECTION IS PAUSED",
            fontSize = 18.sp,
            fontWeight = FontWeight.ExtraBold,
            color = if (isActive) AdGuardGreenLight else AdGuardRedBlocked,
            letterSpacing = 1.sp
        )

        Spacer(modifier = Modifier.height(4.dp))

        Text(
            text = if (isActive) "All network ads and trackers are being filtered" else "Tap the shield to activate protection",
            fontSize = 13.sp,
            color = AdGuardTextSecondary
        )
    }
}

@Composable
fun HighEfficiencyEngineBanner(
    stats: ProtectionStats,
    isSimMode: Boolean
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        border = CardDefaults.outlinedCardBorder().copy(
            brush = Brush.horizontalGradient(
                listOf(AdGuardDarkOutline, AdGuardGreenPrimary.copy(alpha = 0.3f))
            )
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Default.Bolt,
                    contentDescription = null,
                    tint = AdGuardGreenLight,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Column {
                    Text(
                        text = "Rust Core Matcher: 0.08ms",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardTextPrimary
                    )
                    Text(
                        text = "${stats.activeRulesCount} active rules • ${if (isSimMode) "Mode: Simulation" else "Mode: Real TUN Loop"}",
                        fontSize = 11.sp,
                        color = AdGuardTextMuted
                    )
                }
            }

            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(8.dp))
                    .background(Color(0x2200D06C))
                    .padding(horizontal = 8.dp, vertical = 4.dp)
            ) {
                Text(
                    text = "Bloom O(1)",
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardGreenLight
                )
            }
        }
    }
}

@Composable
fun StatsGrid(
    stats: ProtectionStats,
    onCardClick: () -> Unit = {}
) {
    val dataMb = stats.dataSavedBytes / (1024 * 1024)

    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            StatCard(
                title = "ĐÃ CHẶN QUẢNG CÁO",
                value = stats.adsBlocked.toString(),
                icon = Icons.Default.Block,
                accentColor = AdGuardGreenPrimary,
                onClick = onCardClick,
                modifier = Modifier.weight(1f)
            )
            StatCard(
                title = "TRÌNH THEO DÕI",
                value = stats.trackersBlocked.toString(),
                icon = Icons.Default.TrackChanges,
                accentColor = AdGuardOrangeWarning,
                onClick = onCardClick,
                modifier = Modifier.weight(1f)
            )
        }

        Spacer(modifier = Modifier.height(12.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            StatCard(
                title = "DỮ LIỆU ĐÃ LƯU",
                value = "$dataMb MB",
                icon = Icons.Default.CloudDownload,
                accentColor = AdGuardBlueDns,
                onClick = onCardClick,
                modifier = Modifier.weight(1f)
            )
            StatCard(
                title = "PIN BẢO TỒN",
                value = "+${String.format("%.1f", stats.batteryConservedPercent)}%",
                icon = Icons.Default.BatteryChargingFull,
                accentColor = AdGuardGreenLight,
                onClick = onCardClick,
                modifier = Modifier.weight(1f)
            )
        }
    }
}

@Composable
fun StatCard(
    title: String,
    value: String,
    icon: ImageVector,
    accentColor: Color,
    onClick: () -> Unit = {},
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier.clickable { onClick() },
        shape = RoundedCornerShape(14.dp),
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
                .padding(14.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = title,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextSecondary,
                    letterSpacing = 0.5.sp
                )
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = accentColor,
                    modifier = Modifier.size(18.dp)
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = value,
                fontSize = 20.sp,
                fontWeight = FontWeight.Black,
                color = AdGuardTextPrimary,
                fontFamily = FontFamily.SansSerif
            )
        }
    }
}

@Composable
fun ModuleToggleCard(
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
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        border = CardDefaults.outlinedCardBorder().copy(
            brush = Brush.linearGradient(
                listOf(AdGuardDarkOutline, if (isChecked) accentColor.copy(alpha = 0.3f) else Color.Transparent)
            )
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Row(
                modifier = Modifier.weight(1f),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(accentColor.copy(alpha = 0.15f)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = icon,
                        contentDescription = null,
                        tint = accentColor,
                        modifier = Modifier.size(22.dp)
                    )
                }

                Spacer(modifier = Modifier.width(14.dp))

                Column {
                    Text(
                        text = title,
                        fontSize = 15.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = AdGuardTextPrimary
                    )
                    Text(
                        text = subtitle,
                        fontSize = 12.sp,
                        color = AdGuardTextSecondary
                    )
                }
            }

            Switch(
                checked = isChecked,
                onCheckedChange = onCheckedChange,
                colors = SwitchDefaults.colors(
                    checkedThumbColor = Color.White,
                    checkedTrackColor = AdGuardGreenPrimary,
                    uncheckedThumbColor = AdGuardTextMuted,
                    uncheckedTrackColor = AdGuardDarkSurfaceVariant
                )
            )
        }
    }
}
