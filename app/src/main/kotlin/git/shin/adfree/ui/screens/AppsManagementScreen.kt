package git.shin.adfree.ui.screens

import android.graphics.Bitmap
import android.graphics.drawable.BitmapDrawable
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.CellTower
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Wifi
import git.shin.adfree.model.FilterStatus
import git.shin.adfree.model.NetworkRequestLog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.model.AppFirewallRule
import git.shin.adfree.ui.AdGuardIntent
import git.shin.adfree.ui.AdGuardViewModel
import git.shin.adfree.ui.theme.AdGuardBlueDns
import git.shin.adfree.ui.theme.AdGuardDarkBg
import git.shin.adfree.ui.theme.AdGuardDarkOutline
import git.shin.adfree.ui.theme.AdGuardDarkSurface
import androidx.compose.ui.graphics.Brush
import git.shin.adfree.ui.theme.AdGuardDarkSurfaceVariant
import git.shin.adfree.ui.theme.AdGuardGreenLight
import git.shin.adfree.ui.theme.AdGuardGreenPrimary
import git.shin.adfree.ui.theme.AdGuardOrangeWarning
import git.shin.adfree.ui.theme.AdGuardPurpleAI
import git.shin.adfree.ui.theme.AdGuardRedBlocked
import git.shin.adfree.ui.theme.AdGuardTextMuted
import git.shin.adfree.ui.theme.AdGuardTextPrimary
import git.shin.adfree.ui.theme.AdGuardTextSecondary

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppsManagementScreen(
    viewModel: AdGuardViewModel,
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()

    val categories = listOf("Tất cả", "Đang chặn", "Được lọc", "Bỏ qua lọc", "Trình duyệt", "Mạng xã hội", "Đa phương tiện")

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(AdGuardDarkBg)
            .padding(horizontal = 16.dp, vertical = 12.dp)
    ) {
        // Header
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "Ứng dụng",
                    fontSize = 19.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextPrimary
                )
                Text(
                    text = if (state.settings.isFirewallEnabled) {
                        "${state.appFirewallRules.size} ứng dụng • chọn app nào được lọc"
                    } else {
                        "Tường lửa đang tắt — giới hạn mạng theo app chưa áp dụng"
                    },
                    fontSize = 12.sp,
                    color = if (state.settings.isFirewallEnabled) AdGuardTextMuted else AdGuardOrangeWarning
                )
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Search Bar
        OutlinedTextField(
            value = state.appSearchQuery,
            onValueChange = { viewModel.onIntent(AdGuardIntent.AppSearchQueryChanged(it)) },
            placeholder = { Text("Tìm ứng dụng theo tên hoặc gói (package)...", color = AdGuardTextMuted, fontSize = 13.sp) },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = AdGuardTextMuted) },
            trailingIcon = {
                if (state.appSearchQuery.isNotEmpty()) {
                    IconButton(onClick = { viewModel.onIntent(AdGuardIntent.AppSearchQueryChanged("")) }) {
                        Icon(Icons.Default.Clear, contentDescription = "Clear", tint = AdGuardTextMuted)
                    }
                }
            },
            singleLine = true,
            modifier = Modifier
                .fillMaxWidth()
                .testTag("app_search_input"),
            shape = RoundedCornerShape(12.dp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedContainerColor = AdGuardDarkSurface,
                unfocusedContainerColor = AdGuardDarkSurface,
                focusedBorderColor = AdGuardGreenPrimary,
                unfocusedBorderColor = AdGuardDarkOutline,
                focusedTextColor = AdGuardTextPrimary,
                unfocusedTextColor = AdGuardTextPrimary
            )
        )

        Spacer(modifier = Modifier.height(10.dp))

        // Quick Category Filter Chips
        // A plain scrolling Row, not a LazyRow: the row sits beside a vertical
        // LazyColumn, and a lazy row nested like this refuses to scroll, so the
        // last chips simply stay cut off at the screen edge.
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            categories.forEach { cat ->
                val isSelected = (state.appCategoryFilter == null && cat == "Tất cả") || (state.appCategoryFilter == cat)
                FilterChip(
                    selected = isSelected,
                    onClick = {
                        viewModel.onIntent(AdGuardIntent.AppCategoryFilterChanged(if (cat == "Tất cả") null else cat))
                    },
                    label = { Text(cat, fontSize = 11.sp) },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = AdGuardGreenPrimary,
                        selectedLabelColor = Color.Black,
                        containerColor = AdGuardDarkSurface,
                        labelColor = AdGuardTextSecondary
                    )
                )
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        // Legend Summary Bar
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(10.dp),
            colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
            border = CardDefaults.outlinedCardBorder().copy(brush = androidx.compose.ui.graphics.SolidColor(AdGuardDarkOutline))
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 14.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.CellTower, contentDescription = null, tint = AdGuardGreenLight, modifier = Modifier.size(14.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Di động", fontSize = 11.sp, color = AdGuardTextSecondary)
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Wifi, contentDescription = null, tint = AdGuardGreenLight, modifier = Modifier.size(14.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Wi-Fi", fontSize = 11.sp, color = AdGuardTextSecondary)
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Shield, contentDescription = null, tint = AdGuardGreenPrimary, modifier = Modifier.size(14.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Lọc AdGuard", fontSize = 11.sp, color = AdGuardTextSecondary)
                }
                Text("Chạm thẻ để mở chi tiết", fontSize = 10.sp, color = AdGuardTextMuted)
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        // Apps List
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            items(state.appFirewallRules, key = { it.packageName }) { app ->
                AppFirewallCard(
                    app = app,
                    onClick = { viewModel.onIntent(AdGuardIntent.InspectAppDetails(app)) },
                    onViewLogs = { viewModel.onIntent(AdGuardIntent.ViewAppLogs(app)) },
                    onToggleCellular = {
                        viewModel.onIntent(
                            AdGuardIntent.UpdateAppFirewall(app.packageName, cellular = !app.isCellularAllowed)
                        )
                    },
                    onToggleWifi = {
                        viewModel.onIntent(
                            AdGuardIntent.UpdateAppFirewall(app.packageName, wifi = !app.isWifiAllowed)
                        )
                    },
                    onToggleFiltered = {
                        viewModel.onIntent(
                            AdGuardIntent.UpdateAppFirewall(app.packageName, filtered = !app.isFilterRouted)
                        )
                    }
                )
            }
        }
    }

    // Modal Bottom Sheet: Detailed App Firewall & Routing (AdGuard Style)
    if (state.inspectedApp != null) {
        val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ModalBottomSheet(
            onDismissRequest = { viewModel.onIntent(AdGuardIntent.InspectAppDetails(null)) },
            sheetState = sheetState,
            containerColor = AdGuardDarkSurface,
            contentColor = AdGuardTextPrimary
        ) {
            AppDetailsFirewallSheet(
                app = state.inspectedApp!!,
                logs = state.logs,
                vpnActive = state.isVpnActive,
                httpsFilteringEnabled = state.settings.isHttpsFilteringEnabled,
                onViewLogs = { viewModel.onIntent(AdGuardIntent.ViewAppLogs(it)) },
                onRestartVpn = { viewModel.onIntent(AdGuardIntent.RestartVpn) },
                onUpdate = { pkg, cell, wifi, filtered, screenOff, https ->
                    viewModel.onIntent(
                        AdGuardIntent.UpdateAppFirewall(pkg, cell, wifi, filtered, screenOff, https)
                    )
                },
                onClose = { viewModel.onIntent(AdGuardIntent.InspectAppDetails(null)) }
            )
        }
    }
}

@Composable
fun AppFirewallCard(
    app: AppFirewallRule,
    onClick: () -> Unit,
    onViewLogs: () -> Unit,
    onToggleCellular: () -> Unit,
    onToggleWifi: () -> Unit,
    onToggleFiltered: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() }
            .testTag("app_card_${app.packageName}"),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        border = CardDefaults.outlinedCardBorder().copy(brush = androidx.compose.ui.graphics.SolidColor(AdGuardDarkOutline))
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // The real launcher icon: a generic glyph tells the user nothing
                // about which app they are looking at.
                Box(
                    modifier = Modifier
                        .size(42.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(AdGuardDarkSurfaceVariant),
                    contentAlignment = Alignment.Center
                ) {
                    val icon = rememberAppIcon(app.packageName)
                    if (icon != null) {
                        Image(
                            bitmap = icon,
                            contentDescription = null,
                            modifier = Modifier.size(32.dp)
                        )
                    } else {
                        Icon(
                            imageVector = Icons.Default.Apps,
                            contentDescription = null,
                            tint = if (app.isFilterRouted) AdGuardGreenPrimary else AdGuardOrangeWarning,
                            modifier = Modifier.size(22.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.width(12.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = app.appName,
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardTextPrimary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = app.category,
                        fontSize = 11.sp,
                        color = AdGuardTextSecondary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = "${app.blockedRequestsToday} chặn • ${app.dataTransferredBytes / (1024 * 1024)} MB",
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        color = AdGuardTextMuted,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                Spacer(modifier = Modifier.width(8.dp))

                AppQuickAction(
                    icon = Icons.Default.Shield,
                    description = if (app.isFilterRouted) {
                        "Tắt lọc AdGuard cho ${app.appName}"
                    } else {
                        "Bật lọc AdGuard cho ${app.appName}"
                    },
                    tint = if (app.isFilterRouted) AdGuardGreenPrimary else AdGuardOrangeWarning,
                    background = if (app.isFilterRouted) Color(0x2200D06C) else Color(0x22FF9800),
                    onClick = onToggleFiltered,
                    modifier = Modifier
                        .size(34.dp)
                        .testTag("app_filter_btn_${app.packageName}")
                )
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Auxiliary actions on their own row: beside the text, four buttons
            // left barely 80 dp for the name on a 360 dp screen, and they were
            // top-aligned inside their boxes.
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                AppQuickAction(
                    icon = Icons.Default.FilterList,
                    description = "Xem nhật ký của ${app.appName}",
                    tint = AdGuardGreenLight,
                    background = AdGuardDarkSurfaceVariant,
                    onClick = onViewLogs,
                    modifier = Modifier
                        .weight(1f)
                        .height(32.dp)
                        .testTag("app_logs_btn_${app.packageName}")
                )
                AppQuickAction(
                    icon = Icons.Default.CellTower,
                    description = "Chuyển Di động",
                    tint = if (app.isCellularAllowed) AdGuardGreenLight else AdGuardRedBlocked,
                    background = if (app.isCellularAllowed) Color(0x2200D06C) else Color(0x22FF435A),
                    onClick = onToggleCellular,
                    modifier = Modifier
                        .weight(1f)
                        .height(32.dp)
                        .testTag("app_cell_btn_${app.packageName}")
                )
                AppQuickAction(
                    icon = Icons.Default.Wifi,
                    description = "Chuyển Wi-Fi",
                    tint = if (app.isWifiAllowed) AdGuardGreenLight else AdGuardRedBlocked,
                    background = if (app.isWifiAllowed) Color(0x2200D06C) else Color(0x22FF435A),
                    onClick = onToggleWifi,
                    modifier = Modifier
                        .weight(1f)
                        .height(32.dp)
                        .testTag("app_wifi_btn_${app.packageName}")
                )
            }
        }
    }
}

/** One compact, centre-aligned icon button of an app row. */
@Composable
private fun AppQuickAction(
    icon: ImageVector,
    description: String,
    tint: Color,
    background: Color,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .background(background)
            .clickable { onClick() },
        contentAlignment = Alignment.Center
    ) {
        Icon(
            imageVector = icon,
            contentDescription = description,
            tint = tint,
            modifier = Modifier.size(16.dp)
        )
    }
}

/**
 * Loads the launcher icon of [packageName], or null when it cannot be read.
 *
 * Icons are drawn once per row and cached by `remember`: the PackageManager has
 * to decode a bitmap, which is far too slow to do on every recomposition of a
 * list of apps.
 */
@Composable
private fun rememberAppIcon(packageName: String): ImageBitmap? {
    val context = LocalContext.current
    return remember(packageName) {
        runCatching {
            val drawable = context.packageManager.getApplicationIcon(packageName)
            val bitmap = (drawable as? BitmapDrawable)?.bitmap
                ?: Bitmap.createBitmap(
                    drawable.intrinsicWidth.coerceAtLeast(1),
                    drawable.intrinsicHeight.coerceAtLeast(1),
                    Bitmap.Config.ARGB_8888,
                ).also { bmp ->
                    android.graphics.Canvas(bmp).let { canvas ->
                        drawable.setBounds(0, 0, canvas.width, canvas.height)
                        drawable.draw(canvas)
                    }
                }
            bitmap.asImageBitmap()
        }.getOrNull()
    }
}

/**
 * Detailed App Firewall Modal Sheet (AdGuard v4 Style).
 */
@Composable
fun AppDetailsFirewallSheet(
    app: AppFirewallRule,
    logs: List<NetworkRequestLog> = emptyList(),
    vpnActive: Boolean = false,
    httpsFilteringEnabled: Boolean = false,
    onViewLogs: (AppFirewallRule) -> Unit = {},
    onRestartVpn: () -> Unit = {},
    onUpdate: (
        packageName: String,
        cellular: Boolean?,
        wifi: Boolean?,
        filtered: Boolean?,
        screenOff: Boolean?,
        httpsFiltered: Boolean?,
    ) -> Unit,
    onClose: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp, vertical = 16.dp)
    ) {
        // App Title & Close
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(44.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .background(AdGuardDarkSurfaceVariant),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(Icons.Default.Apps, contentDescription = null, tint = AdGuardGreenLight, modifier = Modifier.size(26.dp))
                }
                Spacer(modifier = Modifier.width(12.dp))
                Column {
                    Text(
                        text = app.appName,
                        fontSize = 17.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardTextPrimary
                    )
                    Text(
                        text = app.packageName,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        color = AdGuardTextSecondary
                    )
                }
            }

            IconButton(onClick = onClose) {
                Icon(Icons.Default.Close, contentDescription = "Đóng", tint = AdGuardTextSecondary)
            }
        }

        Spacer(modifier = Modifier.height(18.dp))

        // Master Switch Card: AdGuard Protection for this App
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurfaceVariant),
            border = CardDefaults.outlinedCardBorder().copy(
                brush = Brush.horizontalGradient(
                    listOf(AdGuardDarkOutline, if (app.isFilterRouted) AdGuardGreenPrimary.copy(alpha = 0.4f) else Color.Transparent)
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
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Bảo vệ AdGuard cho ứng dụng này",
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardTextPrimary
                    )
                    Text(
                        text = if (app.isFilterRouted) "Lưu lượng được kiểm tra và chặn quảng cáo/tracker" else "Bỏ qua bộ lọc: Kết nối thẳng trực tiếp ra internet",
                        fontSize = 11.sp,
                        color = if (app.isFilterRouted) AdGuardGreenLight else AdGuardOrangeWarning
                    )
                }

                Switch(
                    checked = app.isFilterRouted,
                    onCheckedChange = { onUpdate(app.packageName, null, null, it, null, null) },
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = Color.White,
                        checkedTrackColor = AdGuardGreenPrimary,
                        uncheckedThumbColor = AdGuardTextMuted,
                        uncheckedTrackColor = AdGuardDarkSurface
                    )
                )
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        if (vpnActive) {
            OutlinedButton(
                onClick = onRestartVpn,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(40.dp)
                    .testTag("btn_apply_app_routing"),
                shape = RoundedCornerShape(10.dp),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = AdGuardOrangeWarning)
            ) {
                Icon(Icons.Default.PowerSettingsNew, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "Khởi động lại VPN để áp dụng",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold
                )
            }
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "VPN đang chạy giữ danh sách app được lọc từ lúc bật; khởi động lại để thay đổi có hiệu lực.",
                fontSize = 10.sp,
                color = AdGuardTextMuted
            )
        } else {
            Text(
                text = "Thay đổi sẽ được áp dụng ở lần bật VPN kế tiếp.",
                fontSize = 10.sp,
                color = AdGuardTextMuted
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // The only per-app switch with a live effect on the tunnel today.
        Text(
            text = "LỌC HTTPS",
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextMuted,
        )
        Text(
            text = if (httpsFilteringEnabled) {
                "Áp dụng cho kết nối mới của ứng dụng này."
            } else {
                "Lọc HTTPS đang tắt trong Cài đặt — công tắc này có hiệu lực khi bật lại."
            },
            fontSize = 10.sp,
            color = if (httpsFilteringEnabled) AdGuardTextMuted else AdGuardOrangeWarning,
        )
        Spacer(modifier = Modifier.height(8.dp))

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurfaceVariant)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 14.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Giải mã HTTPS để lọc nội dung",
                        fontSize = 13.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = AdGuardTextPrimary
                    )
                    Text(
                        text = if (app.isHttpsFiltered) {
                            "Chặn quảng cáo và tracker trong lưu lượng HTTPS của ứng dụng."
                        } else {
                            "Splice TLS: DNS vẫn được lọc, còn nội dung HTTPS thì không bị chặn."
                        },
                        fontSize = 11.sp,
                        color = if (app.isHttpsFiltered) AdGuardTextSecondary else AdGuardOrangeWarning
                    )
                }
                Switch(
                    checked = app.isHttpsFiltered,
                    onCheckedChange = {
                        onUpdate(app.packageName, null, null, null, null, it)
                    },
                    modifier = Modifier.testTag("switch_app_https_${app.packageName}"),
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = Color.White,
                        checkedTrackColor = AdGuardGreenPrimary,
                        uncheckedThumbColor = AdGuardTextMuted,
                        uncheckedTrackColor = AdGuardDarkSurface
                    )
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Section: Firewall Rules
        Text(
            text = "LỌC THEO ỨNG DỤNG",
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextMuted,
        )
        Text(
            text = "Các công tắc bên dưới do VPN thực thi cho kết nối mới và cả " +
                "kết nối đang mở. App đang \"Bỏ qua lọc\" không đi qua VPN nên " +
                "không bị chặn theo mạng.",
            fontSize = 10.sp,
            color = AdGuardOrangeWarning,
        )

        Spacer(modifier = Modifier.height(8.dp))

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurfaceVariant)
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                // Cellular toggle
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Cho phép Dữ liệu di động (Cellular)", fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = AdGuardTextPrimary)
                        Text("Bật/tắt truy cập mạng 4G/5G cho ứng dụng này", fontSize = 11.sp, color = AdGuardTextSecondary)
                    }
                    Switch(
                        checked = app.isCellularAllowed,
                        onCheckedChange = { onUpdate(app.packageName, it, null, null, null, null) },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = Color.White,
                            checkedTrackColor = AdGuardGreenPrimary,
                            uncheckedThumbColor = AdGuardTextMuted,
                            uncheckedTrackColor = AdGuardDarkSurface
                        )
                    )
                }

                Spacer(modifier = Modifier.height(12.dp))

                // Wi-Fi toggle
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Cho phép mạng Wi-Fi", fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = AdGuardTextPrimary)
                        Text("Bật/tắt truy cập Wi-Fi cho ứng dụng này", fontSize = 11.sp, color = AdGuardTextSecondary)
                    }
                    Switch(
                        checked = app.isWifiAllowed,
                        onCheckedChange = { onUpdate(app.packageName, null, it, null, null, null) },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = Color.White,
                            checkedTrackColor = AdGuardGreenPrimary,
                            uncheckedThumbColor = AdGuardTextMuted,
                            uncheckedTrackColor = AdGuardDarkSurface
                        )
                    )
                }

                Spacer(modifier = Modifier.height(12.dp))

                // Block when screen off (Background power saving)
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Chặn khi màn hình tắt (Tiết kiệm pin)", fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = AdGuardTextPrimary)
                        Text("Không cho phép ứng dụng chạy ngầm tải dữ liệu khi khóa máy", fontSize = 11.sp, color = AdGuardTextSecondary)
                    }
                    Switch(
                        checked = app.blockWhenScreenOff,
                        onCheckedChange = { onUpdate(app.packageName, null, null, null, it, null) },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = Color.White,
                            checkedTrackColor = AdGuardGreenPrimary,
                            uncheckedThumbColor = AdGuardTextMuted,
                            uncheckedTrackColor = AdGuardDarkSurface
                        )
                    )
                }
            }
        }

        if (!app.isFilterRouted &&
            (!app.isCellularAllowed || !app.isWifiAllowed || app.blockWhenScreenOff)
        ) {
            Spacer(modifier = Modifier.height(10.dp))
            Text(
                text = "App này đang bỏ qua VPN: các giới hạn mạng ở trên không " +
                    "có tác dụng cho tới khi bật lại lọc.",
                fontSize = 10.sp,
                color = AdGuardOrangeWarning,
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Traffic Stats Summary Row
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Box(
                modifier = Modifier
                    .weight(1f)
                    .clip(RoundedCornerShape(10.dp))
                    .background(AdGuardDarkSurfaceVariant)
                    .padding(12.dp)
            ) {
                Column {
                    Text("Dữ liệu hôm nay", fontSize = 11.sp, color = AdGuardTextSecondary)
                    Spacer(modifier = Modifier.height(2.dp))
                    Text("${app.dataTransferredBytes / (1024 * 1024)} MB", fontSize = 16.sp, fontWeight = FontWeight.Bold, color = AdGuardTextPrimary)
                }
            }

            Box(
                modifier = Modifier
                    .weight(1f)
                    .clip(RoundedCornerShape(10.dp))
                    .background(AdGuardDarkSurfaceVariant)
                    .padding(12.dp)
            ) {
                Column {
                    Text("Truy vấn đã chặn", fontSize = 11.sp, color = AdGuardTextSecondary)
                    Spacer(modifier = Modifier.height(2.dp))
                    Text("${app.blockedRequestsToday}", fontSize = 16.sp, fontWeight = FontWeight.Bold, color = AdGuardRedBlocked)
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // Big Prominent Button to View Filtering Logs for this App
        Button(
            onClick = {
                onClose()
                onViewLogs(app)
            },
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp)
                .testTag("btn_view_app_logs_${app.packageName}"),
            colors = ButtonDefaults.buttonColors(containerColor = AdGuardGreenPrimary),
            shape = RoundedCornerShape(10.dp)
        ) {
            Icon(Icons.Default.FilterList, contentDescription = null, tint = Color.Black)
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = "Xem nhật ký lọc của ${app.appName}",
                color = Color.Black,
                fontWeight = FontWeight.Bold,
                fontSize = 13.sp
            )
        }

        // Recent Requests made by this specific app. Log rows carry the
        // attributed package now; rows written before that (or by a core that
        // could not attribute the flow) still match through a `$app=` rule.
        val appLogs = logs.filter {
            it.appPackage.equals(app.packageName, true) ||
                it.matchedRule?.contains(app.packageName, true) == true
        }.take(4)
        if (appLogs.isNotEmpty()) {
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = "Truy vấn mạng gần đây",
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextMuted
            )
            Spacer(modifier = Modifier.height(8.dp))
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                appLogs.forEach { logItem ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .background(AdGuardDarkSurfaceVariant)
                            .padding(horizontal = 10.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = logItem.domain,
                                fontSize = 12.sp,
                                fontFamily = FontFamily.Monospace,
                                color = AdGuardTextPrimary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            if (logItem.matchedRule != null) {
                                Text(
                                    text = logItem.matchedRule,
                                    fontSize = 10.sp,
                                    color = AdGuardRedBlocked,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                        }
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(4.dp))
                                .background(
                                    if (logItem.status == FilterStatus.BLOCKED) AdGuardRedBlocked.copy(alpha = 0.2f)
                                    else AdGuardGreenPrimary.copy(alpha = 0.2f)
                                )
                                .padding(horizontal = 6.dp, vertical = 2.dp)
                        ) {
                            Text(
                                text = if (logItem.status == FilterStatus.BLOCKED) "ĐÃ CHẶN" else "CHO PHÉP",
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Bold,
                                color = if (logItem.status == FilterStatus.BLOCKED) AdGuardRedBlocked else AdGuardGreenLight
                            )
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(18.dp))

        // Quick Preset Buttons
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            OutlinedButton(
                onClick = { onUpdate(app.packageName, true, true, false, false, false) },
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(8.dp)
            ) {
                Text("Bỏ lọc & mở mạng", fontSize = 11.sp, color = AdGuardOrangeWarning)
            }

            Button(
                onClick = { onUpdate(app.packageName, true, true, true, false, true) },
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(containerColor = AdGuardDarkSurfaceVariant),
                shape = RoundedCornerShape(8.dp)
            ) {
                Text("Bật lọc mặc định", fontSize = 11.sp, color = AdGuardGreenLight, fontWeight = FontWeight.Bold)
            }
        }

        Spacer(modifier = Modifier.height(16.dp))
    }
}
