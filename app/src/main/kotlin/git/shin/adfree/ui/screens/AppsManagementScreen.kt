package git.shin.adfree.ui.screens

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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
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
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
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
                    text = "${state.appFirewallRules.size} ứng dụng • chọn app nào được lọc",
                    fontSize = 12.sp,
                    color = AdGuardTextMuted
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
        LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            items(categories) { cat ->
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
                onViewLogs = { viewModel.onIntent(AdGuardIntent.ViewAppLogs(it)) },
                onUpdate = { pkg, cell, wifi, filtered, screenOff ->
                    viewModel.onIntent(
                        AdGuardIntent.UpdateAppFirewall(pkg, cell, wifi, filtered, screenOff)
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
                        .size(42.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(AdGuardDarkSurfaceVariant),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.Apps,
                        contentDescription = null,
                        tint = if (app.isFilterRouted) AdGuardGreenPrimary else AdGuardOrangeWarning,
                        modifier = Modifier.size(22.dp)
                    )
                }

                Spacer(modifier = Modifier.width(12.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = app.appName,
                            fontSize = 14.sp,
                            fontWeight = FontWeight.Bold,
                            color = AdGuardTextPrimary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(4.dp))
                                .background(AdGuardDarkSurfaceVariant)
                                .padding(horizontal = 5.dp, vertical = 1.dp)
                        ) {
                            Text(app.category, fontSize = 9.sp, color = AdGuardTextSecondary)
                        }
                    }
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = "Đã chặn ${app.blockedRequestsToday} • ${app.dataTransferredBytes / (1024 * 1024)} MB truyền tải",
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        color = AdGuardTextMuted
                    )
                }
            }

            Spacer(modifier = Modifier.width(8.dp))

            // Fast Actions (Logs, Cellular, Wifi, Filtered)
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                IconButton(
                    onClick = onViewLogs,
                    modifier = Modifier
                        .size(34.dp)
                        .clip(RoundedCornerShape(8.dp))
                        .background(AdGuardDarkSurfaceVariant)
                        .testTag("app_logs_btn_${app.packageName}")
                ) {
                    Icon(
                        imageVector = Icons.Default.FilterList,
                        contentDescription = "Xem nhật ký của ${app.appName}",
                        tint = AdGuardBlueDns,
                        modifier = Modifier.size(16.dp)
                    )
                }

                IconButton(
                    onClick = onToggleCellular,
                    modifier = Modifier
                        .size(34.dp)
                        .clip(RoundedCornerShape(8.dp))
                        .background(if (app.isCellularAllowed) Color(0x2200D06C) else Color(0x22FF435A))
                ) {
                    Icon(
                        imageVector = Icons.Default.CellTower,
                        contentDescription = "Chuyển Di động",
                        tint = if (app.isCellularAllowed) AdGuardGreenLight else AdGuardRedBlocked,
                        modifier = Modifier.size(16.dp)
                    )
                }

                IconButton(
                    onClick = onToggleWifi,
                    modifier = Modifier
                        .size(34.dp)
                        .clip(RoundedCornerShape(8.dp))
                        .background(if (app.isWifiAllowed) Color(0x2200D06C) else Color(0x22FF435A))
                ) {
                    Icon(
                        imageVector = Icons.Default.Wifi,
                        contentDescription = "Chuyển Wi-Fi",
                        tint = if (app.isWifiAllowed) AdGuardGreenLight else AdGuardRedBlocked,
                        modifier = Modifier.size(16.dp)
                    )
                }

                IconButton(
                    onClick = onToggleFiltered,
                    modifier = Modifier
                        .size(34.dp)
                        .clip(RoundedCornerShape(8.dp))
                        .background(if (app.isFilterRouted) Color(0x2200D06C) else Color(0x22FF9800))
                ) {
                    Icon(
                        imageVector = Icons.Default.Shield,
                        contentDescription = "Chuyển lọc AdGuard",
                        tint = if (app.isFilterRouted) AdGuardGreenPrimary else AdGuardOrangeWarning,
                        modifier = Modifier.size(16.dp)
                    )
                }
            }
        }
    }
}

/**
 * Detailed App Firewall Modal Sheet (AdGuard v4 Style).
 */
@Composable
fun AppDetailsFirewallSheet(
    app: AppFirewallRule,
    logs: List<NetworkRequestLog> = emptyList(),
    onViewLogs: (AppFirewallRule) -> Unit = {},
    onUpdate: (packageName: String, cellular: Boolean?, wifi: Boolean?, filtered: Boolean?, screenOff: Boolean?) -> Unit,
    onClose: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
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
                    onCheckedChange = { onUpdate(app.packageName, null, null, it, null) },
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
            text = "QUY TẮC TƯỜNG LỬA MẠNG (FIREWALL)",
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextMuted,
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
                        onCheckedChange = { onUpdate(app.packageName, it, null, null, null) },
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
                        onCheckedChange = { onUpdate(app.packageName, null, it, null, null) },
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
                        onCheckedChange = { onUpdate(app.packageName, null, null, null, it) },
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

        // Recent Requests made by this specific app
        // The activity log no longer binds each row to an app, so this section only
        // shows while the user filters by that app.
        val appLogs = logs.filter { it.domain == app.packageName }.take(4)
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
                onClick = { onUpdate(app.packageName, false, false, false, false) },
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(8.dp)
            ) {
                Text("Chặn toàn bộ mạng", fontSize = 11.sp, color = AdGuardRedBlocked)
            }

            Button(
                onClick = { onUpdate(app.packageName, true, true, true, false) },
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(containerColor = AdGuardDarkSurfaceVariant),
                shape = RoundedCornerShape(8.dp)
            ) {
                Text("Mặc định an toàn", fontSize = 11.sp, color = AdGuardGreenLight, fontWeight = FontWeight.Bold)
            }
        }

        Spacer(modifier = Modifier.height(16.dp))
    }
}
