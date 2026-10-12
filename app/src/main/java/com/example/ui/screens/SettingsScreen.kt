package com.example.ui.screens

import androidx.compose.foundation.background
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
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Science
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.model.DnsProvider
import com.example.ui.AdGuardIntent
import com.example.ui.AdGuardViewModel
import com.example.ui.theme.AdGuardBlueDns
import com.example.ui.theme.AdGuardDarkBg
import com.example.ui.theme.AdGuardDarkOutline
import com.example.ui.theme.AdGuardDarkSurface
import com.example.ui.theme.AdGuardDarkSurfaceVariant
import com.example.ui.theme.AdGuardGreenLight
import com.example.ui.theme.AdGuardGreenPrimary
import com.example.ui.theme.AdGuardPurpleAI
import com.example.ui.theme.AdGuardTextMuted
import com.example.ui.theme.AdGuardTextPrimary
import com.example.ui.theme.AdGuardTextSecondary

@Composable
fun SettingsScreen(
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
            .padding(horizontal = 16.dp, vertical = 12.dp)
    ) {
        // Header
        Text(
            text = "CÀI ĐẶT & TỐI ƯU PIN",
            fontSize = 18.sp,
            fontWeight = FontWeight.Black,
            color = AdGuardTextPrimary,
            letterSpacing = 1.sp
        )
        Text(
            text = "DNS mã hóa, Chế độ tàng hình & Bộ lọc tiết kiệm năng lượng",
            fontSize = 12.sp,
            color = AdGuardTextMuted
        )

        Spacer(modifier = Modifier.height(20.dp))

        // UI Test Simulation Toggle (Prominent in Settings)
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
            border = CardDefaults.outlinedCardBorder().copy(
                brush = androidx.compose.ui.graphics.SolidColor(
                    if (state.isSimulationModeEnabled) AdGuardPurpleAI.copy(alpha = 0.5f) else AdGuardDarkOutline
                )
            )
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 14.dp, vertical = 12.dp),
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
                            text = "Chế độ mô phỏng (Test UI Simulation)",
                            fontSize = 14.sp,
                            fontWeight = FontWeight.Bold,
                            color = AdGuardTextPrimary
                        )
                        Text(
                            text = if (state.isSimulationModeEnabled) "Đang bật phát dữ liệu giả lập để test giao diện" else "Đang tắt: 100% logic lọc gói tin THẬT từ Android TUN",
                            fontSize = 11.sp,
                            color = if (state.isSimulationModeEnabled) AdGuardPurpleAI else AdGuardTextSecondary
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

        // Section: DNS Protection
        Text(
            text = "NHÀ CUNG CẤP DNS MÃ HÓA (DOH)",
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextSecondary,
            letterSpacing = 0.5.sp
        )

        Spacer(modifier = Modifier.height(8.dp))

        state.dnsProviders.forEach { provider ->
            DnsProviderCard(
                provider = provider,
                isSelected = state.settings.selectedDnsProviderId == provider.id,
                onSelect = { viewModel.onIntent(AdGuardIntent.SelectDnsProvider(provider.id)) }
            )
            Spacer(modifier = Modifier.height(8.dp))
        }

        Spacer(modifier = Modifier.height(20.dp))

        // Section: Stealth Mode
        Text(
            text = "CHẾ ĐỘ TÀNG HÌNH (STEALTH PRIVACY)",
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextSecondary,
            letterSpacing = 0.5.sp
        )

        Spacer(modifier = Modifier.height(8.dp))

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
            border = CardDefaults.outlinedCardBorder().copy(brush = androidx.compose.ui.graphics.SolidColor(AdGuardDarkOutline))
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                StealthToggleRow(
                    title = "Tự động xóa tham số theo dõi URL",
                    subtitle = "Loại bỏ utm_source, fbclid khi mở liên kết",
                    isChecked = state.settings.stripUtmTracking,
                    onCheckedChange = { viewModel.onIntent(AdGuardIntent.UpdateStealth(stripUtm = it)) }
                )

                Spacer(modifier = Modifier.height(12.dp))

                StealthToggleRow(
                    title = "Chống rò rỉ IP qua WebRTC",
                    subtitle = "Ngăn các trình duyệt web phát hiện địa chỉ IP thực",
                    isChecked = state.settings.blockWebRtcLeaks,
                    onCheckedChange = { viewModel.onIntent(AdGuardIntent.UpdateStealth(blockWebRtc = it)) }
                )

                Spacer(modifier = Modifier.height(12.dp))

                StealthToggleRow(
                    title = "Ngụy trang User-Agent Header",
                    subtitle = "Ẩn thông tin phiên bản thiết bị Android",
                    isChecked = state.settings.disguiseUserAgent,
                    onCheckedChange = { viewModel.onIntent(AdGuardIntent.UpdateStealth(disguiseUa = it)) }
                )

                Spacer(modifier = Modifier.height(12.dp))

                StealthToggleRow(
                    title = "Chặn Cookie theo dõi bên thứ ba",
                    subtitle = "Ngăn theo dõi chéo giữa các ứng dụng và trang web",
                    isChecked = state.settings.blockThirdPartyCookies,
                    onCheckedChange = { viewModel.onIntent(AdGuardIntent.UpdateStealth(blockCookies = it)) }
                )
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // Section: Ultra-Low Battery Optimization
        Text(
            text = "TỐI ƯU HÓA PIN & TIẾT KIỆM NĂNG LƯỢNG",
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextSecondary,
            letterSpacing = 0.5.sp
        )

        Spacer(modifier = Modifier.height(8.dp))

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
            border = CardDefaults.outlinedCardBorder().copy(brush = androidx.compose.ui.graphics.SolidColor(AdGuardDarkOutline))
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "TCP Fast-Drop (RST Early Terminate)",
                            fontSize = 14.sp,
                            fontWeight = FontWeight.Bold,
                            color = AdGuardTextPrimary
                        )
                        Text(
                            text = "Lập tức phản hồi NXDOMAIN / TCP RST cho tracker thay vì chờ đợi timeout, giúp modem radio chuyển về chế độ ngủ tiết kiệm pin",
                            fontSize = 12.sp,
                            color = AdGuardTextSecondary
                        )
                    }
                    Switch(
                        checked = state.settings.isEcoBatteryModeEnabled,
                        onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleEcoMode) },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = Color.White,
                            checkedTrackColor = AdGuardGreenPrimary,
                            uncheckedThumbColor = AdGuardTextMuted,
                            uncheckedTrackColor = AdGuardDarkSurfaceVariant
                        )
                    )
                }

                Spacer(modifier = Modifier.height(14.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            text = "Bộ nhớ đệm LRU DNS Cache",
                            fontSize = 14.sp,
                            fontWeight = FontWeight.Bold,
                            color = AdGuardTextPrimary
                        )
                        Text(
                            text = "Giảm thiểu đánh thức sóng radio • Dung lượng: 64 mục",
                            fontSize = 12.sp,
                            color = AdGuardTextSecondary
                        )
                    }

                    Button(
                        onClick = { viewModel.onIntent(AdGuardIntent.ToggleEcoMode) },
                        colors = ButtonDefaults.buttonColors(containerColor = AdGuardDarkSurfaceVariant),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Text("Tối ưu", color = AdGuardGreenLight, fontSize = 11.sp)
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(32.dp))
    }
}

@Composable
fun DnsProviderCard(
    provider: DnsProvider,
    isSelected: Boolean,
    onSelect: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onSelect() }
            .testTag("dns_provider_${provider.id}"),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        border = CardDefaults.outlinedCardBorder().copy(
            brush = androidx.compose.ui.graphics.SolidColor(
                if (isSelected) AdGuardGreenPrimary else AdGuardDarkOutline
            )
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = provider.name,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardTextPrimary
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(4.dp))
                            .background(AdGuardDarkSurfaceVariant)
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = "${provider.pingMs}ms",
                            fontSize = 10.sp,
                            fontFamily = FontFamily.Monospace,
                            color = AdGuardBlueDns
                        )
                    }
                }

                Spacer(modifier = Modifier.height(2.dp))

                Text(
                    text = provider.description,
                    fontSize = 12.sp,
                    color = AdGuardTextSecondary
                )
            }

            if (isSelected) {
                Box(
                    modifier = Modifier
                        .size(24.dp)
                        .clip(CircleShape)
                        .background(AdGuardGreenPrimary),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.Check,
                        contentDescription = "Đã chọn",
                        tint = Color.Black,
                        modifier = Modifier.size(16.dp)
                    )
                }
            }
        }
    }
}

@Composable
fun StealthToggleRow(
    title: String,
    subtitle: String,
    isChecked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold,
                color = AdGuardTextPrimary
            )
            Text(
                text = subtitle,
                fontSize = 11.sp,
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
                uncheckedTrackColor = AdGuardDarkSurfaceVariant
            )
        )
    }
}
