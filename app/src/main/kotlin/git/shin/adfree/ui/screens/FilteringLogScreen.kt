package git.shin.adfree.ui.screens

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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.AlertDialog
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
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.model.FilterStatus
import git.shin.adfree.model.NetworkRequestLog
import git.shin.adfree.ui.AdGuardIntent
import git.shin.adfree.ui.AdGuardTab
import git.shin.adfree.ui.AdGuardViewModel
import git.shin.adfree.ui.theme.AdGuardBlueDns
import git.shin.adfree.ui.theme.AdGuardDarkBg
import git.shin.adfree.ui.theme.AdGuardDarkOutline
import git.shin.adfree.ui.theme.AdGuardDarkSurface
import git.shin.adfree.ui.theme.AdGuardDarkSurfaceVariant
import git.shin.adfree.ui.theme.AdGuardGreenLight
import git.shin.adfree.ui.theme.AdGuardGreenPrimary
import git.shin.adfree.ui.theme.AdGuardPurpleAI
import git.shin.adfree.ui.theme.AdGuardRedBlocked
import git.shin.adfree.ui.theme.AdGuardTextMuted
import git.shin.adfree.ui.theme.AdGuardTextPrimary
import git.shin.adfree.ui.theme.AdGuardTextSecondary
import kotlinx.coroutines.flow.distinctUntilChanged
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The label to show for a log row's package: the installed app's name when
 * the package is still installed, the raw package otherwise.
 */
private fun appLabelFor(appNames: Map<String, String>, packageName: String?): String? =
    packageName?.let { pkg -> appNames[pkg] ?: pkg }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FilteringLogScreen(
    viewModel: AdGuardViewModel,
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()
    val listState = rememberLazyListState()
    var showClearConfirm by remember { mutableStateOf(false) }

    // While the list sits at its top it follows incoming rows; scrolling into
    // history tells the repository to freeze the window instead, or fresh rows
    // would keep pushing the rows under the user's finger.
    LaunchedEffect(listState) {
        snapshotFlow { listState.firstVisibleItemIndex == 0 }
            .distinctUntilChanged()
            .collect { viewModel.onIntent(AdGuardIntent.SetLogTailing(it)) }
    }

    if (showClearConfirm) {
        AlertDialog(
            onDismissRequest = { showClearConfirm = false },
            containerColor = AdGuardDarkSurface,
            titleContentColor = AdGuardTextPrimary,
            textContentColor = AdGuardTextSecondary,
            title = { Text("Xoá nhật ký?") },
            text = {
                Text(
                    "Toàn bộ ${state.logs.size} bản ghi sẽ bị xoá và không thể hoàn tác.",
                    fontSize = 13.sp,
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    showClearConfirm = false
                    viewModel.onIntent(AdGuardIntent.ClearLogs)
                }) {
                    Text("Xoá", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = AdGuardRedBlocked)
                }
            },
            dismissButton = {
                TextButton(onClick = { showClearConfirm = false }) {
                    Text("Hủy", fontSize = 13.sp, color = AdGuardTextSecondary)
                }
            },
        )
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(AdGuardDarkBg)
            .padding(horizontal = 16.dp, vertical = 12.dp)
    ) {
        // Title Bar & Quick Clear
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "Nhật ký",
                    fontSize = 19.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextPrimary
                )
                Text(
                    text = "Các truy vấn mạng gần đây của thiết bị",
                    fontSize = 12.sp,
                    color = AdGuardTextMuted
                )
            }

            IconButton(
                onClick = { showClearConfirm = true },
                modifier = Modifier.testTag("clear_logs_button")
            ) {
                Icon(
                    imageVector = Icons.Default.DeleteSweep,
                    contentDescription = "Xóa nhật ký",
                    tint = AdGuardTextSecondary
                )
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Search Bar
        OutlinedTextField(
            value = state.searchQuery,
            onValueChange = { viewModel.onIntent(AdGuardIntent.SearchQueryChanged(it)) },
            placeholder = { Text("Tìm theo tên miền, ứng dụng, quy tắc...", color = AdGuardTextMuted, fontSize = 13.sp) },
            leadingIcon = {
                Icon(Icons.Default.Search, contentDescription = null, tint = AdGuardTextMuted)
            },
            trailingIcon = {
                if (state.searchQuery.isNotEmpty()) {
                    IconButton(onClick = { viewModel.onIntent(AdGuardIntent.SearchQueryChanged("")) }) {
                        Icon(Icons.Default.Clear, contentDescription = "Clear", tint = AdGuardTextMuted)
                    }
                }
            },
            singleLine = true,
            modifier = Modifier
                .fillMaxWidth()
                .testTag("log_search_input"),
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

        // Filter chips (All, Blocked, Allowed)
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            FilterChip(
                selected = state.statusFilter == null,
                onClick = { viewModel.onIntent(AdGuardIntent.FilterStatusChanged(null)) },
                label = { Text("Tất cả (${state.logs.size})", fontSize = 12.sp) },
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = AdGuardGreenPrimary,
                    selectedLabelColor = Color.Black,
                    containerColor = AdGuardDarkSurface,
                    labelColor = AdGuardTextSecondary
                )
            )

            FilterChip(
                selected = state.statusFilter == FilterStatus.BLOCKED,
                onClick = { viewModel.onIntent(AdGuardIntent.FilterStatusChanged(FilterStatus.BLOCKED)) },
                label = { Text("Đã chặn (${state.logs.count { it.status == FilterStatus.BLOCKED }})", fontSize = 12.sp) },
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = AdGuardRedBlocked,
                    selectedLabelColor = Color.White,
                    containerColor = AdGuardDarkSurface,
                    labelColor = AdGuardTextSecondary
                )
            )

            FilterChip(
                selected = state.statusFilter == FilterStatus.ALLOWED,
                onClick = { viewModel.onIntent(AdGuardIntent.FilterStatusChanged(FilterStatus.ALLOWED)) },
                label = { Text("Cho phép (${state.logs.count { it.status == FilterStatus.ALLOWED }})", fontSize = 12.sp) },
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = AdGuardGreenLight,
                    selectedLabelColor = Color.Black,
                    containerColor = AdGuardDarkSurface,
                    labelColor = AdGuardTextSecondary
                )
            )
        }

        Spacer(modifier = Modifier.height(10.dp))

        // Active App Filter Banner
        if (state.selectedAppFilter != null) {
            val selected = state.selectedAppFilter
            val appDisplayName = selected?.let { state.appNames[it] ?: it } ?: ""

            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("app_filter_indicator_banner"),
                shape = RoundedCornerShape(10.dp),
                colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurfaceVariant),
                border = CardDefaults.outlinedCardBorder().copy(
                    brush = androidx.compose.ui.graphics.SolidColor(AdGuardGreenPrimary.copy(alpha = 0.6f))
                )
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(
                            imageVector = Icons.Default.FilterList,
                            contentDescription = null,
                            tint = AdGuardGreenLight,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Đang lọc theo ứng dụng: $appDisplayName",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            color = AdGuardGreenLight,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    IconButton(
                        onClick = { viewModel.onIntent(AdGuardIntent.FilterLogsByApp(null)) },
                        modifier = Modifier.size(24.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Close,
                            contentDescription = "Bỏ lọc theo ứng dụng",
                            tint = AdGuardTextMuted,
                            modifier = Modifier.size(16.dp)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(10.dp))
        }

        // Logs List
        if (state.filteredLogs.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(32.dp),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        imageVector = Icons.Default.FilterList,
                        contentDescription = null,
                        tint = AdGuardTextMuted,
                        modifier = Modifier.size(48.dp)
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        text = "Chưa có lưu lượng mạng được ghi nhận",
                        fontSize = 15.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = AdGuardTextSecondary
                    )
                    Text(
                        text = "Bật công tắc bảo vệ ở tab Bảo vệ để bắt đầu lọc",
                        fontSize = 12.sp,
                        color = AdGuardTextMuted
                    )
                }
            }
        } else {
            LazyColumn(
                state = listState,
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(state.filteredLogs, key = { it.id }) { log ->
                    LogItemCard(
                        log = log,
                        appLabel = appLabelFor(state.appNames, log.appPackage),
                        onClick = { viewModel.onIntent(AdGuardIntent.InspectLog(log)) }
                    )
                }

                // The screen mirrors a window of the database log; this tail
                // grows it one page at a time so the list stays cheap to build.
                if (state.logs.size < state.logTotal) {
                    item(key = "log_load_more") {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 8.dp)
                                .testTag("log_load_more_footer"),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Text(
                                text = "Đang hiển thị ${state.logs.size}/${state.logTotal} dòng",
                                fontSize = 11.sp,
                                color = AdGuardTextMuted
                            )
                            Spacer(modifier = Modifier.height(6.dp))
                            OutlinedButton(
                                onClick = { viewModel.onIntent(AdGuardIntent.LoadMoreLogs) },
                                modifier = Modifier.testTag("load_more_logs_button"),
                                shape = RoundedCornerShape(10.dp),
                                border = androidx.compose.foundation.BorderStroke(1.dp, AdGuardGreenPrimary)
                            ) {
                                Text(
                                    text = "Tải thêm",
                                    color = AdGuardGreenPrimary,
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    // Modal Bottom Sheet for Log Details Inspection
    if (state.inspectedLog != null) {
        val inspected = state.inspectedLog!!
        val sheetState = rememberModalBottomSheetState()
        ModalBottomSheet(
            onDismissRequest = { viewModel.onIntent(AdGuardIntent.InspectLog(null)) },
            sheetState = sheetState,
            containerColor = AdGuardDarkSurface,
            contentColor = AdGuardTextPrimary
        ) {
            PacketInspectionSheetContent(
                log = inspected,
                appLabel = appLabelFor(state.appNames, inspected.appPackage),
                onAddToWhitelist = { viewModel.onIntent(AdGuardIntent.AddToWhitelist(it)) },
                onAddToBlacklist = { viewModel.onIntent(AdGuardIntent.AddToBlacklist(it)) },
                onAnalyzeWithAi = { domain ->
                    viewModel.onIntent(AdGuardIntent.InspectLog(null))
                    viewModel.onIntent(AdGuardIntent.SelectTab(AdGuardTab.AI_LAB))
                    viewModel.onIntent(AdGuardIntent.RunThreatScan(domain))
                },
                onClose = { viewModel.onIntent(AdGuardIntent.InspectLog(null)) }
            )
        }
    }
}

@Composable
fun LogItemCard(
    log: NetworkRequestLog,
    appLabel: String? = null,
    onClick: () -> Unit
) {
    val statusColor = when (log.status) {
        FilterStatus.BLOCKED -> AdGuardRedBlocked
        FilterStatus.ALLOWED -> AdGuardGreenPrimary
        FilterStatus.WHITELISTED -> AdGuardBlueDns
    }

    val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
    val timeStr = timeFormat.format(Date(log.timestampMs))

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() }
            .testTag("log_item_${log.domain}"),
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
            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(8.dp)
                            .clip(CircleShape)
                            .background(statusColor)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = log.domain,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = AdGuardTextPrimary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false)
                    )
                }

                Spacer(modifier = Modifier.height(4.dp))

                // What the user can act on: why it was blocked, and when.
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Text(
                        text = timeStr,
                        fontSize = 11.sp,
                        color = AdGuardTextMuted
                    )
                    if (log.protocol.name.isNotEmpty()) {
                        Text(
                            text = "•",
                            fontSize = 11.sp,
                            color = AdGuardTextMuted
                        )
                        Text(
                            text = log.protocol.name,
                            fontSize = 11.sp,
                            color = AdGuardTextSecondary
                        )
                    }
                    if (appLabel != null) {
                        Text(
                            text = "•",
                            fontSize = 11.sp,
                            color = AdGuardTextMuted
                        )
                        Text(
                            text = appLabel,
                            fontSize = 11.sp,
                            color = AdGuardTextSecondary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f, fill = false)
                        )
                    }
                    if (log.matchedRule != null) {
                        Text(
                            text = "•",
                            fontSize = 11.sp,
                            color = AdGuardTextMuted
                        )
                        Text(
                            text = log.matchedRule,
                            fontSize = 11.sp,
                            color = AdGuardTextSecondary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f, fill = false)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.width(8.dp))

            // Status only: the latency belonged to the engine, not to the user.
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .background(statusColor.copy(alpha = 0.15f))
                    .padding(horizontal = 8.dp, vertical = 3.dp)
            ) {
                Text(
                    text = when (log.status) {
                        FilterStatus.BLOCKED -> "Đã chặn"
                        FilterStatus.ALLOWED -> "Cho phép"
                        FilterStatus.WHITELISTED -> "Trắng"
                    },
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    color = statusColor
                )
            }
        }
    }
}

@Composable
fun PacketInspectionSheetContent(
    log: NetworkRequestLog,
    appLabel: String? = null,
    onAddToWhitelist: (String) -> Unit,
    onAddToBlacklist: (String) -> Unit,
    onAnalyzeWithAi: (String) -> Unit,
    onClose: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 24.dp, vertical = 16.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "Chi tiết truy vấn",
                fontSize = 17.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextPrimary
            )
            IconButton(onClick = onClose) {
                Icon(Icons.Default.Close, contentDescription = "Close", tint = AdGuardTextSecondary)
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Domain Header Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurfaceVariant)
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Text(
                    text = "TÊN MIỀN ĐÍCH",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextMuted
                )
                Text(
                    text = log.domain,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace,
                    color = AdGuardGreenLight
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "IP: ${log.ipAddress} • Giao thức: ${log.protocol.label}",
                    fontSize = 12.sp,
                    color = AdGuardTextSecondary
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Detailed Metadata Grid
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            DetailRow(label = "Tên miền", value = log.domain)
            DetailRow(
                label = "Quyết định xử lý",
                value = when (log.status) {
                    FilterStatus.BLOCKED -> "Đã chặn"
                    FilterStatus.ALLOWED -> "Cho phép"
                    FilterStatus.WHITELISTED -> "Trong danh sách trắng"
                }
            )
            DetailRow(label = "Phân loại", value = log.category.label)
            DetailRow(label = "Ứng dụng", value = appLabel ?: "Không xác định")
            if (log.matchedRule != null) {
                DetailRow(label = "Quy tắc kích hoạt", value = log.matchedRule)
            }
            if (log.filterListName != null) {
                DetailRow(label = "Nguồn bộ lọc", value = log.filterListName)
            }
            if (log.dataSavedBytes > 0) {
                DetailRow(label = "Dung lượng tiết kiệm", value = "${log.dataSavedBytes / 1024} KB")
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        // Action Buttons
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            OutlinedButton(
                onClick = { onAddToWhitelist(log.domain) },
                modifier = Modifier
                    .weight(1f)
                    .height(48.dp),
                shape = RoundedCornerShape(10.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, AdGuardBlueDns)
            ) {
                Text("Danh sách trắng", color = AdGuardBlueDns, fontWeight = FontWeight.Bold, fontSize = 12.sp)
            }

            OutlinedButton(
                onClick = { onAddToBlacklist(log.domain) },
                modifier = Modifier
                    .weight(1f)
                    .height(48.dp),
                shape = RoundedCornerShape(10.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, AdGuardRedBlocked)
            ) {
                Text("Chặn tên miền", color = AdGuardRedBlocked, fontWeight = FontWeight.Bold, fontSize = 12.sp)
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        Button(
            onClick = { onAnalyzeWithAi(log.domain) },
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp),
            shape = RoundedCornerShape(10.dp),
            colors = ButtonDefaults.buttonColors(containerColor = AdGuardPurpleAI)
        ) {
            Icon(Icons.Default.Search, contentDescription = null, tint = Color.Black)
            Spacer(modifier = Modifier.width(8.dp))
            Text("Kiểm tra an toàn", color = Color.Black, fontWeight = FontWeight.Bold)
        }

        Spacer(modifier = Modifier.height(16.dp))
    }
}

@Composable
fun DetailRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(text = label, fontSize = 12.sp, color = AdGuardTextSecondary)
        Text(
            text = value,
            fontSize = 12.sp,
            fontWeight = FontWeight.SemiBold,
            color = AdGuardTextPrimary,
            fontFamily = FontFamily.Monospace
        )
    }
}
