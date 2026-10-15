package git.shin.adfree.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.PaddingValues
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.AutoFixHigh
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Layers
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.TabRowDefaults
import androidx.compose.material3.TabRowDefaults.tabIndicatorOffset
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
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
import git.shin.adfree.model.FilterList
import git.shin.adfree.ui.AdGuardIntent
import git.shin.adfree.ui.AdGuardViewModel
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FiltersScreen(
    viewModel: AdGuardViewModel,
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(AdGuardDarkBg)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp, vertical = 12.dp)
        ) {
            // Header
            Column(modifier = Modifier.fillMaxWidth()) {
                Text(
                    text = "Bộ lọc",
                    fontSize = 19.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextPrimary
                )
                Text(
                    text = "Bật hoặc tắt từng danh sách chặn",
                    fontSize = 12.sp,
                    color = AdGuardTextMuted
                )

                Spacer(modifier = Modifier.height(10.dp))

                // Actions on their own row: two labelled buttons never fit next
                // to the title on a narrow screen, and the update button then
                // gets squeezed until its height collapses.
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        onClick = { viewModel.onIntent(AdGuardIntent.ShowOnlineSubDialog(true)) },
                        shape = RoundedCornerShape(10.dp),
                        border = BorderStroke(1.dp, AdGuardDarkOutline),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                        modifier = Modifier.testTag("add_online_filter_btn")
                    ) {
                        Icon(Icons.Default.Public, contentDescription = null, tint = AdGuardBlueDns, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Nguồn online", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = AdGuardTextPrimary)
                    }

                    OutlinedButton(
                        onClick = { viewModel.onIntent(AdGuardIntent.RefreshAllSubscriptions) },
                        enabled = state.loadingMessage == null,
                        shape = RoundedCornerShape(10.dp),
                        border = BorderStroke(1.dp, AdGuardDarkOutline),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Sync,
                            contentDescription = "Cập nhật",
                            tint = AdGuardGreenLight,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        // Never print the progress text here: a long message is
                        // what used to stretch this button out of its bounds.
                        Text(
                            text = if (state.loadingMessage == null) "Cập nhật" else "Đang tải…",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            color = AdGuardGreenLight
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Stats Card
            val totalActiveRules = state.filterLists.filter { it.isEnabled }.sumOf { it.ruleCount }
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
                border = CardDefaults.outlinedCardBorder().copy(brush = androidx.compose.ui.graphics.SolidColor(AdGuardDarkOutline))
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column {
                        Text(
                            text = "Quy tắc đang lọc",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = AdGuardTextSecondary
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "%,d".format(totalActiveRules),
                            fontSize = 24.sp,
                            fontWeight = FontWeight.ExtraBold,
                            color = AdGuardGreenPrimary,
                            fontFamily = FontFamily.SansSerif
                        )
                        Text(
                            text = "${state.filterLists.size} danh sách bộ lọc đang hoạt động",
                            fontSize = 11.sp,
                            color = AdGuardTextMuted
                        )
                    }

                    Box(
                        modifier = Modifier
                            .size(46.dp)
                            .clip(RoundedCornerShape(12.dp))
                            .background(AdGuardGreenPrimary.copy(alpha = 0.15f)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.Layers,
                            contentDescription = null,
                            tint = AdGuardGreenPrimary,
                            modifier = Modifier.size(24.dp)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Subscriptions list
            Text(
                text = "Danh sách bộ lọc",
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextSecondary,
            )

            Spacer(modifier = Modifier.height(10.dp))

            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                items(state.filterLists, key = { it.id }) { list ->
                    FilterListCard(
                        list = list,
                        onToggle = { viewModel.onIntent(AdGuardIntent.ToggleFilterList(list.id, !list.isEnabled)) },
                        onEditCustom = { viewModel.onIntent(AdGuardIntent.ShowCustomRuleEditor(true)) },
                        onRefreshSub = { viewModel.onIntent(AdGuardIntent.RefreshSubscription(list.id)) },
                        onDeleteSub = { viewModel.onIntent(AdGuardIntent.DeleteFilterList(list.id)) }
                    )
                }

                item {
                    Spacer(modifier = Modifier.height(72.dp))
                }
            }
        }

        // FAB to open friendly custom rules editor
        FloatingActionButton(
            onClick = { viewModel.onIntent(AdGuardIntent.ShowCustomRuleEditor(true)) },
            containerColor = AdGuardGreenPrimary,
            contentColor = Color.Black,
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .padding(20.dp)
                .testTag("open_custom_rules_editor_fab")
        ) {
            Icon(Icons.Default.Edit, contentDescription = "Sửa quy tắc tùy chỉnh")
        }
    }

    // Modal Sheet 1: Add Custom Online Filter Subscription
    if (state.showOnlineSubDialog) {
        AddOnlineFilterDialog(
            onDismiss = { viewModel.onIntent(AdGuardIntent.ShowOnlineSubDialog(false)) },
            onAdd = { name, url, category ->
                viewModel.onIntent(AdGuardIntent.AddOnlineSubscription(name, url, category))
            }
        )
    }

    // Modal Sheet 2: Friendly Custom Rules Full-Featured Editor
    if (state.showCustomRuleEditor) {
        val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        val customFilter = state.filterLists.find { it.isCustom }
        val currentRules = customFilter?.customRules ?: emptyList()

        ModalBottomSheet(
            onDismissRequest = { viewModel.onIntent(AdGuardIntent.ShowCustomRuleEditor(false)) },
            sheetState = sheetState,
            containerColor = AdGuardDarkSurface,
            contentColor = AdGuardTextPrimary
        ) {
            FriendlyCustomRuleEditorSheet(
                initialRules = currentRules,
                onSaveAll = { newRules ->
                    viewModel.onIntent(AdGuardIntent.UpdateAllCustomRules(newRules))
                },
                onClose = { viewModel.onIntent(AdGuardIntent.ShowCustomRuleEditor(false)) }
            )
        }
    }
}

@Composable
fun FilterListCard(
    list: FilterList,
    onToggle: () -> Unit,
    onEditCustom: () -> Unit,
    onRefreshSub: () -> Unit,
    onDeleteSub: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        border = CardDefaults.outlinedCardBorder().copy(brush = androidx.compose.ui.graphics.SolidColor(AdGuardDarkOutline))
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
                Column(modifier = Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = list.name,
                            fontSize = 15.sp,
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
                                text = "%,d quy tắc".format(list.ruleCount),
                                fontSize = 10.sp,
                                fontFamily = FontFamily.Monospace,
                                color = AdGuardGreenLight
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = list.description,
                        fontSize = 12.sp,
                        color = AdGuardTextSecondary
                    )

                    if (list.isOnlineSubscription && list.subscriptionUrl != null) {
                        Spacer(modifier = Modifier.height(4.dp))
                        // The source, not a labelled field: a raw URL with an
                        // "URL:" prefix is debug output, not a setting.
                        Text(
                            text = list.subscriptionUrl,
                            fontSize = 10.sp,
                            fontFamily = FontFamily.Monospace,
                            color = AdGuardBlueDns,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }

                Switch(
                    checked = list.isEnabled,
                    onCheckedChange = { onToggle() },
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = Color.White,
                        checkedTrackColor = AdGuardGreenPrimary,
                        uncheckedThumbColor = AdGuardTextMuted,
                        uncheckedTrackColor = AdGuardDarkSurfaceVariant
                    )
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            // Action row for Custom Rule or Online Subscriptions
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Cập nhật: ${list.lastUpdatedText}",
                    fontSize = 10.sp,
                    color = AdGuardTextMuted
                )

                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    if (list.isCustom) {
                        Button(
                            onClick = onEditCustom,
                            colors = ButtonDefaults.buttonColors(containerColor = AdGuardDarkSurfaceVariant),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.height(32.dp)
                        ) {
                            Icon(Icons.Default.Edit, contentDescription = null, tint = AdGuardGreenLight, modifier = Modifier.size(14.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Chỉnh sửa quy tắc", fontSize = 11.sp, color = AdGuardGreenLight, fontWeight = FontWeight.Bold)
                        }
                    }

                    if (list.isOnlineSubscription) {
                        IconButton(onClick = onRefreshSub, modifier = Modifier.size(32.dp)) {
                            Icon(Icons.Default.Refresh, contentDescription = "Tải lại", tint = AdGuardBlueDns, modifier = Modifier.size(16.dp))
                        }
                        IconButton(onClick = onDeleteSub, modifier = Modifier.size(32.dp)) {
                            Icon(Icons.Default.Delete, contentDescription = "Xóa", tint = AdGuardRedBlocked, modifier = Modifier.size(16.dp))
                        }
                    }
                }
            }
        }
    }
}

/**
 * Friendly Dialog to Add Online Filter Subscription with 1-click popular presets.
 */
@Composable
fun AddOnlineFilterDialog(
    onDismiss: () -> Unit,
    onAdd: (name: String, url: String, category: String) -> Unit
) {
    var name by remember { mutableStateOf("") }
    var url by remember { mutableStateOf("") }
    var category by remember { mutableStateOf("Chặn quảng cáo") }

    val presetFilters = listOf(
        PresetOnlineFilter("hostsVN (EasyList VN)", "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts", "Việt Nam"),
        PresetOnlineFilter("OISD Big DNS Filter", "https://big.oisd.nl", "Bảo mật & Toàn diện"),
        PresetOnlineFilter("Peter Lowe's Blocklist", "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus", "Quảng cáo quốc tế"),
        PresetOnlineFilter("HaGeZi Multi PRO", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt", "DNS Chuyên sâu")
    )

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = AdGuardDarkSurface,
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Public, contentDescription = null, tint = AdGuardBlueDns, modifier = Modifier.size(22.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "Thêm bộ lọc Online tùy chỉnh",
                    fontSize = 17.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextPrimary
                )
            }
        },
        text = {
            Column {
                Text(
                    text = "Đăng ký danh sách lọc từ đường dẫn trực tuyến. Bộ lọc sẽ tự động cập nhật định kỳ.",
                    fontSize = 12.sp,
                    color = AdGuardTextSecondary
                )

                Spacer(modifier = Modifier.height(12.dp))

                // Presets row
                Text(
                    text = "Gợi ý phổ biến (Chạm để điền nhanh):",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextMuted
                )
                Spacer(modifier = Modifier.height(6.dp))

                LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    items(presetFilters) { preset ->
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(8.dp))
                                .background(AdGuardDarkSurfaceVariant)
                                .clickable {
                                    name = preset.name
                                    url = preset.url
                                    category = preset.category
                                }
                                .padding(horizontal = 10.dp, vertical = 6.dp)
                        ) {
                            Text(preset.name, fontSize = 11.sp, color = AdGuardBlueDns, fontWeight = FontWeight.SemiBold)
                        }
                    }
                }

                Spacer(modifier = Modifier.height(14.dp))

                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Tên bộ lọc") },
                    placeholder = { Text("Ví dụ: EasyList Vietnam") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedContainerColor = AdGuardDarkSurfaceVariant,
                        unfocusedContainerColor = AdGuardDarkSurfaceVariant,
                        focusedBorderColor = AdGuardBlueDns,
                        unfocusedBorderColor = AdGuardDarkOutline,
                        focusedTextColor = AdGuardTextPrimary,
                        unfocusedTextColor = AdGuardTextPrimary
                    )
                )

                Spacer(modifier = Modifier.height(10.dp))

                OutlinedTextField(
                    value = url,
                    onValueChange = { url = it },
                    label = { Text("URL đăng ký bộ lọc") },
                    placeholder = { Text("https://example.com/filter.txt") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedContainerColor = AdGuardDarkSurfaceVariant,
                        unfocusedContainerColor = AdGuardDarkSurfaceVariant,
                        focusedBorderColor = AdGuardBlueDns,
                        unfocusedBorderColor = AdGuardDarkOutline,
                        focusedTextColor = AdGuardTextPrimary,
                        unfocusedTextColor = AdGuardTextPrimary
                    )
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    if (url.isNotBlank()) {
                        onAdd(name, url, category)
                    }
                },
                colors = ButtonDefaults.buttonColors(containerColor = AdGuardBlueDns),
                shape = RoundedCornerShape(8.dp)
            ) {
                Text("Đăng ký bộ lọc", color = Color.Black, fontWeight = FontWeight.Bold)
            }
        },
        dismissButton = {
            OutlinedButton(
                onClick = onDismiss,
                shape = RoundedCornerShape(8.dp)
            ) {
                Text("Hủy", color = AdGuardTextSecondary)
            }
        }
    )
}

data class PresetOnlineFilter(val name: String, val url: String, val category: String)

/**
 * Friendly Full-Featured Custom Rules Editor Modal Sheet.
 * Provides two modes:
 * 1. Visual Card Manager (Search, Delete, Type Badges)
 * 2. Raw Multi-line Editor with syntax helper chips and live validator.
 */
@Composable
fun FriendlyCustomRuleEditorSheet(
    initialRules: List<String>,
    onSaveAll: (List<String>) -> Unit,
    onClose: () -> Unit
) {
    var selectedTab by remember { mutableIntStateOf(0) } // 0: Visual Cards, 1: Raw Text Editor
    var rulesList by remember { mutableStateOf(initialRules) }
    var rawText by remember { mutableStateOf(initialRules.joinToString("\n")) }
    var newSingleRule by remember { mutableStateOf("") }
    var searchQuery by remember { mutableStateOf("") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp, vertical = 14.dp)
    ) {
        // Sheet Title & Close
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "Quy tắc của bạn",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Black,
                    color = AdGuardTextPrimary,
                )
                Text(
                    text = "${rulesList.size} quy tắc người dùng đang lưu trong bộ nhớ",
                    fontSize = 12.sp,
                    color = AdGuardTextMuted
                )
            }

            IconButton(onClick = onClose) {
                Icon(Icons.Default.Close, contentDescription = "Đóng", tint = AdGuardTextSecondary)
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Mode Switcher Tabs
        TabRow(
            selectedTabIndex = selectedTab,
            containerColor = AdGuardDarkSurfaceVariant,
            contentColor = AdGuardGreenPrimary,
            indicator = { tabPositions ->
                TabRowDefaults.SecondaryIndicator(
                    modifier = Modifier.tabIndicatorOffset(tabPositions[selectedTab]),
                    color = AdGuardGreenPrimary
                )
            },
            modifier = Modifier.clip(RoundedCornerShape(10.dp))
        ) {
            Tab(
                selected = selectedTab == 0,
                onClick = {
                    selectedTab = 0
                    // Sync from raw text if user edited there
                    rulesList = rawText.lines().map { it.trim() }.filter { it.isNotEmpty() }
                },
                text = { Text("Quản lý trực quan (${rulesList.size})", fontSize = 12.sp, fontWeight = FontWeight.Bold) }
            )
            Tab(
                selected = selectedTab == 1,
                onClick = {
                    selectedTab = 1
                    // Sync to raw text
                    rawText = rulesList.joinToString("\n")
                },
                text = { Text("Soạn thảo toàn văn (Raw)", fontSize = 12.sp, fontWeight = FontWeight.Bold) }
            )
        }

        Spacer(modifier = Modifier.height(14.dp))

        if (selectedTab == 0) {
            // MODE 0: Visual Cards Mode
            // Add new rule bar
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedTextField(
                    value = newSingleRule,
                    onValueChange = { newSingleRule = it },
                    placeholder = { Text("Nhập quy tắc: ||domain.com^ hoặc @@||cho-phep.com^", color = AdGuardTextMuted, fontSize = 12.sp) },
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(10.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedContainerColor = AdGuardDarkSurfaceVariant,
                        unfocusedContainerColor = AdGuardDarkSurfaceVariant,
                        focusedBorderColor = AdGuardGreenPrimary,
                        unfocusedBorderColor = AdGuardDarkOutline,
                        focusedTextColor = AdGuardTextPrimary,
                        unfocusedTextColor = AdGuardTextPrimary
                    )
                )

                Spacer(modifier = Modifier.width(8.dp))

                Button(
                    onClick = {
                        val trimmed = newSingleRule.trim()
                        if (trimmed.isNotEmpty()) {
                            rulesList = listOf(trimmed) + rulesList
                            rawText = rulesList.joinToString("\n")
                            newSingleRule = ""
                            onSaveAll(rulesList)
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = AdGuardGreenPrimary),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.height(52.dp)
                ) {
                    Icon(Icons.Default.Add, contentDescription = null, tint = Color.Black)
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Search in custom rules
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                placeholder = { Text("Lọc tìm quy tắc...", color = AdGuardTextMuted, fontSize = 12.sp) },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = AdGuardTextMuted) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(10.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedContainerColor = AdGuardDarkSurfaceVariant,
                    unfocusedContainerColor = AdGuardDarkSurfaceVariant,
                    focusedBorderColor = AdGuardGreenPrimary,
                    unfocusedBorderColor = AdGuardDarkOutline,
                    focusedTextColor = AdGuardTextPrimary,
                    unfocusedTextColor = AdGuardTextPrimary
                )
            )

            Spacer(modifier = Modifier.height(10.dp))

            val filteredRules = rulesList.filter {
                searchQuery.isBlank() || it.contains(searchQuery, ignoreCase = true)
            }

            LazyColumn(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                items(filteredRules) { rule ->
                    val isWhitelist = rule.startsWith("@@")
                    val isRegex = rule.startsWith("/") && rule.endsWith("/")
                    val badgeColor = if (isWhitelist) AdGuardGreenLight else if (isRegex) AdGuardPurpleAI else AdGuardRedBlocked
                    val badgeText = if (isWhitelist) "CHO PHÉP" else if (isRegex) "REGEX" else "CHẶN"

                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(10.dp),
                        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurfaceVariant)
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 12.dp, vertical = 10.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(
                                modifier = Modifier.weight(1f),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Box(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(6.dp))
                                        .background(badgeColor.copy(alpha = 0.15f))
                                        .padding(horizontal = 6.dp, vertical = 2.dp)
                                ) {
                                    Text(badgeText, fontSize = 9.sp, fontWeight = FontWeight.Bold, color = badgeColor)
                                }
                                Spacer(modifier = Modifier.width(10.dp))
                                Text(
                                    text = rule,
                                    fontSize = 13.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = AdGuardTextPrimary
                                )
                            }

                            IconButton(
                                onClick = {
                                    rulesList = rulesList.filter { it != rule }
                                    rawText = rulesList.joinToString("\n")
                                    onSaveAll(rulesList)
                                },
                                modifier = Modifier.size(28.dp)
                            ) {
                                Icon(Icons.Default.Delete, contentDescription = "Xóa", tint = AdGuardTextMuted, modifier = Modifier.size(16.dp))
                            }
                        }
                    }
                }
            }
        } else {
            // MODE 1: Raw Text Multi-line Editor Mode
            // Quick syntax chips
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                QuickSyntaxChip("+ ||domain^") { rawText += (if (rawText.isNotEmpty() && !rawText.endsWith("\n")) "\n" else "") + "||example.com^" }
                QuickSyntaxChip("+ @@||whitelist^") { rawText += (if (rawText.isNotEmpty() && !rawText.endsWith("\n")) "\n" else "") + "@@||safe.com^" }
                QuickSyntaxChip("+ /regex/") { rawText += (if (rawText.isNotEmpty() && !rawText.endsWith("\n")) "\n" else "") + "/.*[-_]telemetry\\..*/" }
            }

            Spacer(modifier = Modifier.height(10.dp))

            OutlinedTextField(
                value = rawText,
                onValueChange = { rawText = it },
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth(),
                shape = RoundedCornerShape(10.dp),
                textStyle = androidx.compose.ui.text.TextStyle(
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    color = AdGuardTextPrimary
                ),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedContainerColor = AdGuardDarkSurfaceVariant,
                    unfocusedContainerColor = AdGuardDarkSurfaceVariant,
                    focusedBorderColor = AdGuardGreenPrimary,
                    unfocusedBorderColor = AdGuardDarkOutline
                )
            )

            Spacer(modifier = Modifier.height(10.dp))

            // Action row: Format & Clean + Save All
            val linesCount = rawText.lines().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("!") }.size

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Button(
                    onClick = {
                        val cleaned = rawText.lines()
                            .map { it.trim() }
                            .filter { it.isNotEmpty() }
                            .distinct()
                        rawText = cleaned.joinToString("\n")
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = AdGuardDarkSurfaceVariant),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Icon(Icons.Default.AutoFixHigh, contentDescription = null, tint = AdGuardTextSecondary, modifier = Modifier.size(14.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Dọn trùng lặp", fontSize = 11.sp, color = AdGuardTextSecondary)
                }

                Button(
                    onClick = {
                        val newRules = rawText.lines().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("!") }
                        rulesList = newRules
                        onSaveAll(newRules)
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = AdGuardGreenPrimary),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Icon(Icons.Default.Check, contentDescription = null, tint = Color.Black, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Lưu $linesCount quy tắc", color = Color.Black, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))
    }
}

@Composable
fun QuickSyntaxChip(label: String, onClick: () -> Unit) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(6.dp))
            .background(AdGuardDarkSurfaceVariant)
            .clickable { onClick() }
            .padding(horizontal = 8.dp, vertical = 4.dp)
    ) {
        Text(text = label, fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = AdGuardGreenLight, fontWeight = FontWeight.SemiBold)
    }
}
