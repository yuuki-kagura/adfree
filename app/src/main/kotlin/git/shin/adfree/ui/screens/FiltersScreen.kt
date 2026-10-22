package git.shin.adfree.ui.screens

import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.NotificationsOff
import androidx.compose.material.icons.filled.OpenInBrowser
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Science
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material.icons.filled.UploadFile
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.data.FilterGroup
import git.shin.adfree.data.ModuleGate
import git.shin.adfree.data.moduleGate
import git.shin.adfree.model.FilterList
import git.shin.adfree.model.assetSizeLabel
import git.shin.adfree.model.filterUrlError
import git.shin.adfree.ui.AdGuardIntent
import git.shin.adfree.ui.AdGuardViewModel
import git.shin.adfree.ui.theme.AdGuardBlueDns
import git.shin.adfree.ui.theme.AdGuardDarkBg
import git.shin.adfree.ui.theme.AdGuardDarkOutline
import git.shin.adfree.ui.theme.AdGuardDarkSurface
import git.shin.adfree.ui.theme.AdGuardDarkSurfaceVariant
import git.shin.adfree.ui.theme.AdGuardGreenLight
import git.shin.adfree.ui.theme.AdGuardGreenPrimary
import git.shin.adfree.ui.theme.AdGuardRedBlocked
import git.shin.adfree.ui.theme.AdGuardTextMuted
import git.shin.adfree.ui.theme.AdGuardTextPrimary
import git.shin.adfree.ui.theme.AdGuardTextSecondary
import git.shin.adfree.AdGuardApplication

/**
 * The "Bộ lọc" tab: the filter catalogue, custom lists and userscripts.
 *
 * Layout mirrors AdGuard's Filters screen: the catalogue is grouped (ads,
 * privacy, annoyances…) with a switch per list, every group shows an
 * "enabled/total" counter, and search flattens everything. What each list does
 * is one tap away in a detail sheet, which also carries refresh/delete.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FiltersScreen(
    viewModel: AdGuardViewModel,
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsState()
    val context = LocalContext.current
    var expandedGroups by remember { mutableStateOf(setOf(FilterGroup.ADS.id)) }
    var showOverflow by remember { mutableStateOf(false) }
    // "Khôi phục mặc định" deletes a chunk of configuration; the confirm
    // (AdGuard pattern) says what resets and what survives, so a stray tap
    // in the overflow menu cannot silently rebind the enabled sets.
    var showResetConfirm by remember { mutableStateOf(false) }
    // The detail sheet asks before deleting a user-added list and can open
    // the name/URL editor; both hang off the sheet, so a mis-tap cannot
    // silently remove or mangle a list.
    var showDeleteConfirm by remember { mutableStateOf(false) }
    var showEditFilter by remember { mutableStateOf(false) }
    // Extensions: import from file, create new, edit source, and confirm
    // deletion (the sheet is one tap away from the list otherwise).
    var showCreateScript by remember { mutableStateOf(false) }
    var editScriptTarget by remember { mutableStateOf<git.shin.adfree.model.UserScriptInfo?>(null) }
    var deleteScriptTarget by remember { mutableStateOf<git.shin.adfree.model.UserScriptInfo?>(null) }

    // Local files are imported through the system picker; the URI is read once
    // and copied into the app's own directory (SAF permissions are not trusted
    // to survive).
    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            runCatching {
                context.contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION,
                )
            }
            viewModel.onIntent(AdGuardIntent.ImportLocalFilter(uri.toString()))
        }
    }
    val scriptFilePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            runCatching {
                context.contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION,
                )
            }
            viewModel.onIntent(AdGuardIntent.ImportLocalScript(uri.toString()))
        }
    }

    val query = state.filterSearchQuery
    val matchesQuery: (FilterList) -> Boolean = {
        query.isBlank() ||
            it.name.contains(query, ignoreCase = true) ||
            it.description.contains(query, ignoreCase = true)
    }
    val catalogLists = state.filterLists.filter { !it.isCustom && !it.isUserAdded }
    val customLists = state.filterLists.filter { it.isUserAdded }
    val visibleCatalog = catalogLists.filter(matchesQuery)
    val visibleCustom = customLists.filter(matchesQuery)
    val userRulesCount = state.filterLists.firstOrNull { it.isCustom }?.ruleCount ?: 0
    val enabledCount = state.filterLists.count { it.isEnabled && !it.isCustom }
    val totalRules = state.filterLists.filter { it.isEnabled && !it.isCustom }.sumOf { it.ruleCount }

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(AdGuardDarkBg),
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp, vertical = 12.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Bộ lọc",
                        fontSize = 19.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardTextPrimary,
                    )
                    Text(
                        text = "$enabledCount bộ lọc đang bật • ${"%,d".format(totalRules)} quy tắc",
                        fontSize = 12.sp,
                        color = AdGuardTextMuted,
                    )
                }
                Box {
                    IconButton(onClick = { showOverflow = true }) {
                        Icon(Icons.Default.MoreVert, contentDescription = "Tuỳ chọn", tint = AdGuardTextSecondary)
                    }
                    DropdownMenu(expanded = showOverflow, onDismissRequest = { showOverflow = false }) {
                        DropdownMenuItem(
                            text = { Text("Khôi phục mặc định", fontSize = 13.sp) },
                            onClick = {
                                showOverflow = false
                                showResetConfirm = true
                            },
                            leadingIcon = {
                                Icon(Icons.Default.Refresh, contentDescription = null, tint = AdGuardTextSecondary, modifier = Modifier.size(18.dp))
                            },
                        )
                    }
                }
            }

            state.loadingMessage?.let { message ->
                Spacer(modifier = Modifier.height(8.dp))
                Surface(
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("filter_status_banner"),
                    shape = RoundedCornerShape(10.dp),
                    color = AdGuardDarkSurfaceVariant,
                    border = BorderStroke(1.dp, AdGuardBlueDns.copy(alpha = 0.35f)),
                ) {
                    Row(
                        modifier = Modifier.padding(start = 12.dp, top = 6.dp, bottom = 6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(
                            Icons.Default.Info,
                            contentDescription = null,
                            tint = AdGuardBlueDns,
                            modifier = Modifier.size(16.dp),
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = message,
                            fontSize = 11.sp,
                            color = AdGuardTextPrimary,
                            modifier = Modifier.weight(1f),
                        )
                        IconButton(
                            onClick = { viewModel.onIntent(AdGuardIntent.DismissLoading) },
                            modifier = Modifier.size(32.dp),
                        ) {
                            Icon(
                                Icons.Default.Close,
                                contentDescription = "Đóng thông báo",
                                tint = AdGuardTextMuted,
                                modifier = Modifier.size(16.dp),
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Actions on their own row: two labelled buttons never fit next to
            // the title on a narrow screen.
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = { viewModel.onIntent(AdGuardIntent.ShowAddFilterDialog(true)) },
                    shape = RoundedCornerShape(10.dp),
                    border = BorderStroke(1.dp, AdGuardDarkOutline),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                    modifier = Modifier.testTag("add_online_filter_btn"),
                ) {
                    Icon(Icons.Default.Add, contentDescription = null, tint = AdGuardBlueDns, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Thêm bộ lọc", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = AdGuardTextPrimary)
                }

                OutlinedButton(
                    onClick = { viewModel.onIntent(AdGuardIntent.RefreshAllSubscriptions) },
                    enabled = state.loadingMessage == null,
                    shape = RoundedCornerShape(10.dp),
                    border = BorderStroke(1.dp, AdGuardDarkOutline),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                ) {
                    Icon(
                        imageVector = Icons.Default.Sync,
                        contentDescription = "Cập nhật",
                        tint = AdGuardGreenLight,
                        modifier = Modifier.size(16.dp),
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = if (state.loadingMessage == null) "Cập nhật" else "Đang tải…",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardGreenLight,
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            OutlinedTextField(
                value = query,
                onValueChange = { viewModel.onIntent(AdGuardIntent.FilterSearchQueryChanged(it)) },
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("filter_search_field"),
                singleLine = true,
                placeholder = { Text("Tìm bộ lọc theo tên…", color = AdGuardTextMuted, fontSize = 13.sp) },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = AdGuardTextMuted, modifier = Modifier.size(18.dp)) },
                shape = RoundedCornerShape(10.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedContainerColor = AdGuardDarkSurface,
                    unfocusedContainerColor = AdGuardDarkSurface,
                    focusedBorderColor = AdGuardGreenPrimary,
                    unfocusedBorderColor = AdGuardDarkOutline,
                    focusedTextColor = AdGuardTextPrimary,
                    unfocusedTextColor = AdGuardTextPrimary,
                ),
            )

            Spacer(modifier = Modifier.height(12.dp))

            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                for (group in FilterGroup.entries) {
                    val items = visibleCatalog.filter { it.groupId == group.id }
                    if (items.isEmpty()) continue
                    item(key = "group_${group.id}") {
                        val gate = group.moduleGate
                        FilterGroupCard(
                            group = group,
                            lists = items,
                            expanded = query.isNotBlank() || group.id in expandedGroups,
                            moduleEnabled = when (gate) {
                                null -> true
                                ModuleGate.AD_BLOCKING -> state.settings.isAdBlockingEnabled
                                ModuleGate.TRACKING -> state.settings.isTrackingProtectionEnabled
                            },
                            onEnableModule = {
                                when (gate) {
                                    ModuleGate.TRACKING -> viewModel.onIntent(AdGuardIntent.ToggleTracking)
                                    null -> Unit
                                    ModuleGate.AD_BLOCKING -> viewModel.onIntent(AdGuardIntent.ToggleAdBlocking)
                                }
                            },
                            onToggleExpand = {
                                expandedGroups = if (group.id in expandedGroups) {
                                    expandedGroups - group.id
                                } else {
                                    expandedGroups + group.id
                                }
                            },
                            onToggleList = { viewModel.onIntent(AdGuardIntent.ToggleFilterList(it.id, !it.isEnabled)) },
                            onOpenList = { viewModel.onIntent(AdGuardIntent.InspectFilter(it.id)) },
                        )
                    }
                }

                item(key = "custom_filters") {
                    CustomFiltersCard(
                        lists = visibleCustom,
                        onAdd = { viewModel.onIntent(AdGuardIntent.ShowAddFilterDialog(true)) },
                        onToggleList = { viewModel.onIntent(AdGuardIntent.ToggleFilterList(it.id, !it.isEnabled)) },
                        onOpenList = { viewModel.onIntent(AdGuardIntent.InspectFilter(it.id)) },
                    )
                }

                item(key = "extensions") {
                    ExtensionsSection(
                        scripts = state.userscripts,
                        masterEnabled = state.scriptsMasterEnabled,
                        onToggleMaster = { viewModel.onIntent(AdGuardIntent.ToggleScriptsMaster(it)) },
                        onToggleScript = { script, enabled ->
                            viewModel.onIntent(AdGuardIntent.ToggleScript(script.id, enabled))
                        },
                        onOpenScript = { viewModel.onIntent(AdGuardIntent.InspectScript(it.id)) },
                        onAddScript = { viewModel.onIntent(AdGuardIntent.ShowAddScriptDialog(true)) },
                        onOpenStore = { viewModel.onIntent(AdGuardIntent.ShowScriptStore(true)) },
                    )
                }

                item(key = "user_rules") {
                    UserRulesCard(
                        count = userRulesCount,
                        onOpen = { viewModel.onIntent(AdGuardIntent.ShowCustomRuleEditor(true)) },
                    )
                }

                item { Spacer(modifier = Modifier.height(72.dp)) }
            }
        }
    }

    // ------------------------------------------------------------- dialogs

    if (state.showAddFilterDialog) {
        AddFilterDialog(
            onDismiss = { viewModel.onIntent(AdGuardIntent.ShowAddFilterDialog(false)) },
            onAdd = { name, url -> viewModel.onIntent(AdGuardIntent.AddCustomFilter(name, url)) },
            onPickFile = {
                viewModel.onIntent(AdGuardIntent.ShowAddFilterDialog(false))
                filePicker.launch(arrayOf("text/plain", "text/*", "*/*"))
            },
        )
    }

    state.inspectedFilterId?.let { id ->
        val list = state.filterLists.firstOrNull { it.id == id }
        if (list?.isUserAdded == true) {
            if (showDeleteConfirm) {
                AlertDialog(
                    onDismissRequest = { showDeleteConfirm = false },
                    title = { Text("Xóa bộ lọc?", fontSize = 17.sp, fontWeight = FontWeight.Bold, color = AdGuardTextPrimary) },
                    text = {
                        Text(
                            "Bộ lọc «${list.name}» và nội dung đã tải của nó bị xóa, không thể hoàn tác.",
                            fontSize = 12.sp,
                            color = AdGuardTextSecondary,
                        )
                    },
                    confirmButton = {
                        TextButton(onClick = {
                            showDeleteConfirm = false
                            viewModel.onIntent(AdGuardIntent.DeleteFilterList(list.id))
                            viewModel.onIntent(AdGuardIntent.InspectFilter(null))
                        }) {
                            Text("Xóa", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = AdGuardRedBlocked)
                        }
                    },
                    dismissButton = {
                        TextButton(onClick = { showDeleteConfirm = false }) {
                            Text("Hủy", fontSize = 13.sp, color = AdGuardTextSecondary)
                        }
                    },
                )
            }
            if (showEditFilter) {
                EditCustomFilterDialog(
                    list = list,
                    onDismiss = { showEditFilter = false },
                    onSave = { name, url ->
                        showEditFilter = false
                        viewModel.onIntent(AdGuardIntent.UpdateCustomFilter(list.id, name, url))
                    },
                )
            }
        }
    }

    if (showResetConfirm) {
        AlertDialog(
            onDismissRequest = { showResetConfirm = false },
            title = { Text("Khôi phục mặc định?", fontSize = 17.sp, fontWeight = FontWeight.Bold, color = AdGuardTextPrimary) },
            text = {
                Column {
                    // AdGuard lists the scope and the consequences before the
                    // destructive word; here the reset is honestly narrow.
                    Text(
                        "Các danh sách catalogue sẽ bật/tắt về đúng cấu hình mặc định của ứng dụng.",
                        fontSize = 12.sp,
                        color = AdGuardTextSecondary,
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        "Danh sách được bật lại sẽ tự tải về nếu máy chưa có nội dung.",
                        fontSize = 12.sp,
                        color = AdGuardTextSecondary,
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        "Bộ lọc tùy chỉnh, tiện ích và Quy tắc của bạn không bị thay đổi.",
                        fontSize = 12.sp,
                        color = AdGuardTextMuted,
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    showResetConfirm = false
                    viewModel.onIntent(AdGuardIntent.RestoreDefaultFilters)
                }) {
                    Text("Khôi phục", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = AdGuardRedBlocked)
                }
            },
            dismissButton = {
                TextButton(onClick = { showResetConfirm = false }) {
                    Text("Hủy", fontSize = 13.sp, color = AdGuardTextSecondary)
                }
            },
        )
    }

    if (state.showAddScriptDialog) {
        AddScriptDialog(
            onDismiss = { viewModel.onIntent(AdGuardIntent.ShowAddScriptDialog(false)) },
            onAdd = { name, url -> viewModel.onIntent(AdGuardIntent.AddScript(name, url)) },
            onImportFile = {
                viewModel.onIntent(AdGuardIntent.ShowAddScriptDialog(false))
                scriptFilePicker.launch(arrayOf("text/javascript", "application/x-javascript", "text/plain", "application/javascript", "*/*"))
            },
            onCreate = {
                viewModel.onIntent(AdGuardIntent.ShowAddScriptDialog(false))
                showCreateScript = true
            },
        )
    }

    if (showCreateScript) {
        ScriptTextEditorDialog(
            title = "Tạo tiện ích mới",
            initialName = "",
            initialText = "// ==UserScript==\n// @name         Tiện ích của tôi\n// @match        *://*/*\n// @grant        none\n// ==/UserScript==\n\n",
            confirmText = "Tạo",
            onDismiss = { showCreateScript = false },
            onConfirm = { name, text ->
                showCreateScript = false
                viewModel.onIntent(AdGuardIntent.CreateScript(name, text))
            },
        )
    }

    editScriptTarget?.let { target ->
        if (target.isUserAdded) {
            ScriptTextEditorDialog(
                title = "Sửa mã tiện ích",
                initialName = target.name,
                initialText = "",
                confirmText = "Lưu",
                onDismiss = { editScriptTarget = null },
                onConfirm = { name, text ->
                    editScriptTarget = null
                    viewModel.onIntent(AdGuardIntent.UpdateScriptText(target.id, name, text))
                },
                loadText = { AdGuardApplication.instance.container.coreEngine.scriptText(target.id).orEmpty() },
            )
        }
    }

    deleteScriptTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { deleteScriptTarget = null },
            title = { Text("Xóa tiện ích?", fontSize = 17.sp, fontWeight = FontWeight.Bold, color = AdGuardTextPrimary) },
            text = {
                Text(
                    "Tiện ích «${target.name}» và nội dung đã lưu sẽ bị xóa, không thể hoàn tác.",
                    fontSize = 12.sp,
                    color = AdGuardTextSecondary,
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    deleteScriptTarget = null
                    viewModel.onIntent(AdGuardIntent.DeleteScript(target.id))
                }) {
                    Text("Xóa", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = AdGuardRedBlocked)
                }
            },
            dismissButton = {
                TextButton(onClick = { deleteScriptTarget = null }) {
                    Text("Hủy", fontSize = 13.sp, color = AdGuardTextSecondary)
                }
            },
        )
    }

    if (state.showScriptStore) {
        val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        val installedByUrl = state.userscripts
            .filter { it.url.isNotBlank() }
            .associateBy { it.url }
        ModalBottomSheet(
            onDismissRequest = { viewModel.onIntent(AdGuardIntent.ShowScriptStore(false)) },
            sheetState = sheetState,
            containerColor = AdGuardDarkSurface,
            contentColor = AdGuardTextPrimary,
        ) {
            UserScriptStoreSheet(
                state = state.scriptStore,
                installedByUrl = installedByUrl,
                onQueryChange = { viewModel.onIntent(AdGuardIntent.SearchScriptStore(it)) },
                onSortChange = { sort -> viewModel.onIntent(AdGuardIntent.SortScriptStore(sort)) },
                onLoadMore = { viewModel.onIntent(AdGuardIntent.LoadMoreScriptStore) },
                onInstall = { item ->
                    viewModel.onIntent(
                        AdGuardIntent.InstallStoreScript(item.name, item.url, item.description),
                    )
                },
                onEnable = { script -> viewModel.onIntent(AdGuardIntent.ToggleScript(script.id, true)) },
                onOpenPage = { url ->
                    if (url.startsWith("https://") || url.startsWith("http://")) {
                        runCatching {
                            context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                        }
                    }
                },
                onRetry = {
                    viewModel.onIntent(AdGuardIntent.SearchScriptStore(state.scriptStore.query))
                },
            )
        }
    }

    if (state.showCustomRuleEditor) {
        val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        val currentRules = state.filterLists.firstOrNull { it.isCustom }?.customRules ?: emptyList()
        ModalBottomSheet(
            onDismissRequest = { viewModel.onIntent(AdGuardIntent.ShowCustomRuleEditor(false)) },
            sheetState = sheetState,
            containerColor = AdGuardDarkSurface,
            contentColor = AdGuardTextPrimary,
        ) {
            FriendlyCustomRuleEditorSheet(
                initialRules = currentRules,
                onSaveAll = { newRules -> viewModel.onIntent(AdGuardIntent.UpdateAllCustomRules(newRules)) },
                onClose = { viewModel.onIntent(AdGuardIntent.ShowCustomRuleEditor(false)) },
            )
        }
    }

    state.inspectedFilterId?.let { id ->
        val list = state.filterLists.firstOrNull { it.id == id }
        if (list != null) {
            val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
            ModalBottomSheet(
                onDismissRequest = { viewModel.onIntent(AdGuardIntent.InspectFilter(null)) },
                sheetState = sheetState,
                containerColor = AdGuardDarkSurface,
                contentColor = AdGuardTextPrimary,
            ) {
                FilterDetailSheet(
                    list = list,
                    isBuilding = state.stats.isFilterBuilding,
                    onToggle = { viewModel.onIntent(AdGuardIntent.ToggleFilterList(list.id, !list.isEnabled)) },
                    onTrustChanged = { viewModel.onIntent(AdGuardIntent.SetFilterTrusted(list.id, it)) },
                    onRefresh = { viewModel.onIntent(AdGuardIntent.RefreshSubscription(list.id)) },
                    onDelete = {
                        showDeleteConfirm = true
                    },
                    onEdit = { showEditFilter = true },
                    onOpenHomepage = { url ->
                        runCatching {
                            context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                        }
                    },
                    onOpenSource = { url ->
                        runCatching {
                            context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                        }
                    },
                )
            }
        }
    }

    state.inspectedScriptId?.let { id ->
        val script = state.userscripts.firstOrNull { it.id == id }
        if (script != null) {
            val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
            ModalBottomSheet(
                onDismissRequest = { viewModel.onIntent(AdGuardIntent.InspectScript(null)) },
                sheetState = sheetState,
                containerColor = AdGuardDarkSurface,
                contentColor = AdGuardTextPrimary,
            ) {
                ScriptDetailSheet(
                    script = script,
                    masterEnabled = state.scriptsMasterEnabled,
                    onToggle = { viewModel.onIntent(AdGuardIntent.ToggleScript(script.id, !script.isEnabled)) },
                    onRefresh = { viewModel.onIntent(AdGuardIntent.RefreshScript(script.id)) },
                    onEdit = {
                        // The editor is its own sheet: close the detail sheet
                        // first so two modals never stack.
                        editScriptTarget = script
                        viewModel.onIntent(AdGuardIntent.InspectScript(null))
                    },
                    onDelete = {
                        deleteScriptTarget = script
                        viewModel.onIntent(AdGuardIntent.InspectScript(null))
                    },
                )
            }
        }
    }
}

// ------------------------------------------------------------- catalogue

private fun groupIcon(group: FilterGroup): ImageVector = when (group) {
    FilterGroup.ADS -> Icons.Default.Block
    FilterGroup.PRIVACY -> Icons.Default.Lock
    FilterGroup.SOCIAL -> Icons.Default.Share
    FilterGroup.ANNOYANCES -> Icons.Default.NotificationsOff
    FilterGroup.SECURITY -> Icons.Default.Shield
    FilterGroup.OTHER -> Icons.Default.Science
    FilterGroup.LANGUAGE -> Icons.Default.Language
}

@Composable
private fun FilterGroupCard(
    group: FilterGroup,
    lists: List<FilterList>,
    expanded: Boolean,
    /** False when the engine module gating this group is switched off. */
    moduleEnabled: Boolean = true,
    onEnableModule: () -> Unit = {},
    onToggleExpand: () -> Unit,
    onToggleList: (FilterList) -> Unit,
    onOpenList: (FilterList) -> Unit,
) {
    val enabled = lists.count { it.isEnabled }
    // AdGuard shows "These filters aren't active because …" with an Enable
    // action: the count keeps the configuration state and the note explains
    // why none of it applies right now.
    val gate = group.moduleGate
    val inactive = gate != null && enabled > 0 && lists.any { it.isEnabled } && !moduleEnabled

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("filter_group_${group.id}"),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        border = BorderStroke(1.dp, AdGuardDarkOutline),
    ) {
        Column {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onToggleExpand() }
                    .padding(14.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Box(
                    modifier = Modifier
                        .size(38.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(AdGuardGreenPrimary.copy(alpha = 0.12f)),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(groupIcon(group), contentDescription = null, tint = AdGuardGreenPrimary, modifier = Modifier.size(20.dp))
                }
                Spacer(modifier = Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(group.title, fontSize = 13.sp, fontWeight = FontWeight.Bold, color = AdGuardTextPrimary)
                    Text(group.subtitle, fontSize = 10.sp, color = AdGuardTextMuted)
                }
                Text(
                    text = "$enabled/${lists.size}",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = if (enabled > 0) AdGuardGreenPrimary else AdGuardTextMuted,
                )
                Spacer(modifier = Modifier.width(4.dp))
                Icon(
                    imageVector = if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                    contentDescription = null,
                    tint = AdGuardTextMuted,
                    modifier = Modifier.size(20.dp),
                )
            }

            if (inactive) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(AdGuardRedBlocked.copy(alpha = 0.10f))
                        .padding(start = 14.dp, end = 8.dp, top = 8.dp, bottom = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            "Không hoạt động",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            color = AdGuardRedBlocked,
                        )
                        Text(
                            "«${group.title}» có bộ lọc đang bật nhưng module " +
                                "«${gate?.title}» đang tắt — không req nào của nhóm này bị lọc",
                            fontSize = 10.sp,
                            color = AdGuardTextMuted,
                        )
                    }
                    TextButton(onClick = onEnableModule) {
                        Text("Bật", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = AdGuardGreenLight)
                    }
                }
            }

            if (expanded) {
                for (list in lists) {
                    FilterRow(
                        list = list,
                        onToggle = { onToggleList(list) },
                        onClick = { onOpenList(list) },
                    )
                }
                Spacer(modifier = Modifier.height(4.dp))
            }
        }
    }
}

@Composable
private fun FilterRow(
    list: FilterList,
    onToggle: () -> Unit,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() }
            .padding(start = 14.dp, end = 8.dp, top = 6.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = list.name,
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold,
                color = AdGuardTextPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = "${"%,d".format(list.ruleCount)} quy tắc • ${list.lastUpdatedText}",
                fontSize = 10.sp,
                color = AdGuardTextMuted,
            )
            // AdGuard rows carry "Version: … / Updated: …"; we only show a
            // version once the list's own metadata provided one (empty
            // before the first download, no more faked "standard").
            if (list.version.isNotBlank()) {
                Text(
                    text = "Phiên bản ${list.version}",
                    fontSize = 10.sp,
                    color = AdGuardTextMuted,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            // The honest-state line: a list that says "on" but failed to
            // download keeps its reason right on the row, like AdGuard's
            // inactive-filters banner.
            if (list.lastError.isNotBlank()) {
                Text(
                    text = "Lỗi: ${list.lastError}",
                    fontSize = 10.sp,
                    color = AdGuardRedBlocked,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        Switch(
            checked = list.isEnabled,
            onCheckedChange = { onToggle() },
            colors = SwitchDefaults.colors(checkedTrackColor = AdGuardGreenPrimary),
        )
    }
}

// --------------------------------------------------------- custom + rules

@Composable
private fun CustomFiltersCard(
    lists: List<FilterList>,
    onAdd: () -> Unit,
    onToggleList: (FilterList) -> Unit,
    onOpenList: (FilterList) -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("custom_filters_section"),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        border = BorderStroke(1.dp, AdGuardDarkOutline),
    ) {
        Column {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(14.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Box(
                    modifier = Modifier
                        .size(38.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(AdGuardBlueDns.copy(alpha = 0.12f)),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(Icons.Default.Public, contentDescription = null, tint = AdGuardBlueDns, modifier = Modifier.size(20.dp))
                }
                Spacer(modifier = Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text("Bộ lọc tùy chỉnh", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = AdGuardTextPrimary)
                    Text(
                        "Danh sách bạn tự thêm từ URL hoặc tệp trong máy",
                        fontSize = 10.sp,
                        color = AdGuardTextMuted,
                    )
                }
            }

            if (lists.isEmpty()) {
                Text(
                    text = "Chưa có bộ lọc tùy chỉnh nào.",
                    fontSize = 11.sp,
                    color = AdGuardTextMuted,
                    modifier = Modifier.padding(horizontal = 14.dp),
                )
            } else {
                for (list in lists) {
                    FilterRow(
                        list = list,
                        onToggle = { onToggleList(list) },
                        onClick = { onOpenList(list) },
                    )
                }
            }

            TextButton(
                onClick = onAdd,
                modifier = Modifier.padding(start = 6.dp, bottom = 4.dp),
            ) {
                Icon(Icons.Default.Add, contentDescription = null, tint = AdGuardBlueDns, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text("Thêm bộ lọc", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = AdGuardBlueDns)
            }
        }
    }
}

@Composable
private fun UserRulesCard(
    count: Int,
    onOpen: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onOpen() }
            .testTag("open_custom_rules_editor_fab"),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        border = BorderStroke(1.dp, AdGuardDarkOutline),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(38.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(AdGuardGreenPrimary.copy(alpha = 0.12f)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(Icons.Default.Edit, contentDescription = null, tint = AdGuardGreenPrimary, modifier = Modifier.size(20.dp))
            }
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text("Quy tắc của bạn", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = AdGuardTextPrimary)
                Text("$count quy tắc chặn / cho phép tự viết", fontSize = 10.sp, color = AdGuardTextMuted)
            }
            Icon(Icons.Default.ChevronRight, contentDescription = null, tint = AdGuardTextMuted, modifier = Modifier.size(20.dp))
        }
    }
}

// ---------------------------------------------------------------- dialogs

@Composable
private fun AddFilterDialog(
    onDismiss: () -> Unit,
    onAdd: (String, String) -> Unit,
    onPickFile: () -> Unit,
) {
    var name by remember { mutableStateOf("") }
    var url by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Public, contentDescription = null, tint = AdGuardBlueDns, modifier = Modifier.size(22.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text("Thêm bộ lọc tùy chỉnh", fontSize = 17.sp, fontWeight = FontWeight.Bold, color = AdGuardTextPrimary)
            }
        },
        text = {
            Column {
                Text(
                    text = "Dán đường dẫn danh sách lọc (AdGuard, EasyList, hosts…) hoặc chọn tệp có sẵn trong máy.",
                    fontSize = 12.sp,
                    color = AdGuardTextSecondary,
                )

                Spacer(modifier = Modifier.height(12.dp))

                Text("Gợi ý phổ biến (chạm để điền nhanh):", fontSize = 11.sp, color = AdGuardTextMuted)
                Spacer(modifier = Modifier.height(6.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    QuickSyntaxChip("ABPVN") {
                        name = "ABPVN List"
                        url = "https://raw.githubusercontent.com/abpvn/abpvn/master/filter/abpvn_adguard.txt"
                    }
                    QuickSyntaxChip("OISD Big") {
                        name = "OISD Big"
                        url = "https://big.oisd.nl/dnsmasq2"
                    }
                    QuickSyntaxChip("EasyList") {
                        name = "EasyList"
                        url = "https://easylist.to/easylist/easylist.txt"
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Tên (không bắt buộc)", fontSize = 12.sp) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = AdGuardGreenPrimary,
                        unfocusedBorderColor = AdGuardDarkOutline,
                        focusedTextColor = AdGuardTextPrimary,
                        unfocusedTextColor = AdGuardTextPrimary,
                    ),
                )

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedTextField(
                    value = url,
                    onValueChange = { url = it },
                    label = { Text("Đường dẫn (URL)", fontSize = 12.sp) },
                    placeholder = { Text("https://…", fontSize = 12.sp, color = AdGuardTextMuted) },
                    singleLine = true,
                    isError = url.isNotBlank() && filterUrlError(url) != null,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = AdGuardGreenPrimary,
                        unfocusedBorderColor = AdGuardDarkOutline,
                        focusedTextColor = AdGuardTextPrimary,
                        unfocusedTextColor = AdGuardTextPrimary,
                    ),
                )

                // Inline validation like AdGuard's "Enter a valid URL or file
                // path": reported at the field, not only after pressing Add.
                filterUrlError(url)?.let { error ->
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(error, fontSize = 11.sp, color = AdGuardRedBlocked)
                }

                Spacer(modifier = Modifier.height(4.dp))

                TextButton(onClick = onPickFile) {
                    Icon(Icons.Default.UploadFile, contentDescription = null, tint = AdGuardGreenLight, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Chọn tệp từ máy", fontSize = 12.sp, color = AdGuardGreenLight)
                }
            }
        },
        confirmButton = {
            Button(
                onClick = { if (filterUrlError(url) == null) onAdd(name, url) },
                enabled = filterUrlError(url) == null,
                colors = ButtonDefaults.buttonColors(containerColor = AdGuardBlueDns),
                shape = RoundedCornerShape(8.dp),
            ) {
                Text("Thêm", color = Color.Black, fontWeight = FontWeight.Bold)
            }
        },
        dismissButton = {
            OutlinedButton(onClick = onDismiss, shape = RoundedCornerShape(8.dp)) {
                Text("Hủy", color = AdGuardTextSecondary)
            }
        },
    )
}

/** Editor for a user-added list: rename it or point it at another source. */
@Composable
private fun EditCustomFilterDialog(
    list: FilterList,
    onDismiss: () -> Unit,
    onSave: (String, String) -> Unit,
) {
    var name by remember { mutableStateOf(list.name) }
    var url by remember { mutableStateOf(list.subscriptionUrl.orEmpty()) }
    // A list imported from a file has no URL at all: leaving the field
    // empty is valid there, an invalid URL never is.
    val urlError = if (url.isBlank()) null else filterUrlError(url)

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Sửa bộ lọc", fontSize = 17.sp, fontWeight = FontWeight.Bold, color = AdGuardTextPrimary) },
        text = {
            Column {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Tên", fontSize = 12.sp) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = AdGuardGreenPrimary,
                        unfocusedBorderColor = AdGuardDarkOutline,
                        focusedTextColor = AdGuardTextPrimary,
                        unfocusedTextColor = AdGuardTextPrimary,
                    ),
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = url,
                    onValueChange = { url = it },
                    label = { Text("Đường dẫn (URL)", fontSize = 12.sp) },
                    placeholder = { Text("https://…", fontSize = 12.sp, color = AdGuardTextMuted) },
                    singleLine = true,
                    isError = urlError != null,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = AdGuardGreenPrimary,
                        unfocusedBorderColor = AdGuardDarkOutline,
                        focusedTextColor = AdGuardTextPrimary,
                        unfocusedTextColor = AdGuardTextPrimary,
                    ),
                )
                urlError?.let {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(it, fontSize = 11.sp, color = AdGuardRedBlocked)
                }
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    "Đổi URL sẽ tải lại nội dung của bộ lọc.",
                    fontSize = 10.sp,
                    color = AdGuardTextMuted,
                )
            }
        },
        confirmButton = {
            Button(
                onClick = { onSave(name, url) },
                enabled = urlError == null,
                colors = ButtonDefaults.buttonColors(containerColor = AdGuardBlueDns),
                shape = RoundedCornerShape(8.dp),
            ) {
                Text("Lưu", color = Color.Black, fontWeight = FontWeight.Bold)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Hủy", fontSize = 13.sp, color = AdGuardTextSecondary)
            }
        },
    )
}

/** Bottom sheet with everything we know about one filter list. */
@Composable
fun FilterDetailSheet(
    list: FilterList,
    /** True while the core is still compiling the lists (stats tick drives it). */
    isBuilding: Boolean = false,
    onToggle: () -> Unit,
    onTrustChanged: (Boolean) -> Unit,
    onRefresh: () -> Unit,
    /** Opens the name/URL editor; wired only for user-added lists. */
    onEdit: () -> Unit = {},
    onDelete: () -> Unit,
    onOpenHomepage: (String) -> Unit,
    onOpenSource: (String) -> Unit,
) {
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp, vertical = 12.dp),
    ) {
        Text(list.name, fontSize = 16.sp, fontWeight = FontWeight.Black, color = AdGuardTextPrimary)
        if (list.description.isNotBlank()) {
            Spacer(modifier = Modifier.height(4.dp))
            Text(list.description, fontSize = 12.sp, color = AdGuardTextSecondary)
        }

        Spacer(modifier = Modifier.height(14.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text("Bật bộ lọc này", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = AdGuardTextPrimary)
                Text(
                    text = when {
                        // The switch follows the engine, so an in-flight compile
                        // has to be said out loud or the user wonders why a
                        // freshly enabled list is not filtering yet.
                        isBuilding -> "Đang biên dịch quy tắc…"
                        list.isEnabled -> "Đang lọc"
                        else -> "Đang tắt"
                    },
                    fontSize = 11.sp,
                    color = AdGuardTextMuted,
                )
            }
            Switch(
                checked = list.isEnabled,
                onCheckedChange = { onToggle() },
                colors = SwitchDefaults.colors(checkedTrackColor = AdGuardGreenPrimary),
            )
        }

        if (list.isUserAdded) {
            Spacer(modifier = Modifier.height(12.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Bộ lọc tin cậy", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = AdGuardTextPrimary)
                    Text(
                        text = "Cho phép list chạy JavaScript rule, scriptlet và các modifier " +
                            "(\$removeparam, \$replace, \$urltransform, \$hls, \$removeheader) — " +
                            "chỉ bật khi bạn tin nguồn list",
                        fontSize = 11.sp,
                        color = AdGuardTextMuted,
                    )
                }
                Switch(
                    checked = list.trusted,
                    onCheckedChange = { onTrustChanged(it) },
                    colors = SwitchDefaults.colors(checkedTrackColor = AdGuardGreenPrimary),
                )
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        InfoRow("Nhóm", FilterGroup.fromId(list.groupId)?.title ?: "Tùy chỉnh")
        InfoRow("Định dạng", if (list.format.equals("hosts", ignoreCase = true)) "Hosts" else "AdGuard / EasyList")
        InfoRow("Quy tắc", "%,d".format(list.ruleCount))
        if (list.sizeBytes > 0L) {
            InfoRow("Dung lượng", assetSizeLabel(list.sizeBytes))
        }
        InfoRow("Cập nhật", list.lastUpdatedText)
        if (list.version.isNotBlank()) {
            InfoRow("Phiên bản", list.version.take(24))
        }
        if (list.lastError.isNotBlank()) {
            InfoRow("Lỗi", list.lastError.take(160), AdGuardRedBlocked)
        }

        if (!list.subscriptionUrl.isNullOrBlank()) {
            val url = list.subscriptionUrl
            Spacer(modifier = Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = url,
                    fontSize = 9.sp,
                    fontFamily = FontFamily.Monospace,
                    color = AdGuardTextMuted,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                IconButton(
                    onClick = {
                        clipboard.setText(AnnotatedString(url))
                        Toast.makeText(context, "Đã sao chép URL", Toast.LENGTH_SHORT).show()
                    },
                    modifier = Modifier.size(32.dp),
                ) {
                    Icon(
                        Icons.Default.ContentCopy,
                        contentDescription = "Sao chép nguồn",
                        tint = AdGuardTextSecondary,
                        modifier = Modifier.size(16.dp),
                    )
                }
                IconButton(
                    onClick = { onOpenSource(url) },
                    modifier = Modifier.size(32.dp),
                ) {
                    Icon(
                        Icons.Default.OpenInBrowser,
                        contentDescription = "Mở nguồn",
                        tint = AdGuardTextSecondary,
                        modifier = Modifier.size(16.dp),
                    )
                }
            }
        } else if (list.ruleCount > 0) {
            Spacer(modifier = Modifier.height(8.dp))
            InfoRow("Nguồn", "Nội dung cục bộ")
        }

        Spacer(modifier = Modifier.height(16.dp))

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (!list.subscriptionUrl.isNullOrBlank()) {
                OutlinedButton(onClick = onRefresh, shape = RoundedCornerShape(10.dp)) {
                    Icon(Icons.Default.Sync, contentDescription = null, tint = AdGuardGreenLight, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Cập nhật", fontSize = 12.sp, color = AdGuardGreenLight)
                }
            }
            if (list.isUserAdded) {
                OutlinedButton(onClick = onEdit, shape = RoundedCornerShape(10.dp)) {
                    Icon(Icons.Default.Edit, contentDescription = null, tint = AdGuardGreenLight, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Sửa", fontSize = 12.sp, color = AdGuardGreenLight)
                }
                OutlinedButton(onClick = onDelete, shape = RoundedCornerShape(10.dp)) {
                    Icon(Icons.Default.Delete, contentDescription = null, tint = AdGuardRedBlocked, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Xóa", fontSize = 12.sp, color = AdGuardRedBlocked)
                }
            }
            if (!list.homepage.isNullOrBlank()) {
                OutlinedButton(onClick = { onOpenHomepage(list.homepage) }, shape = RoundedCornerShape(10.dp)) {
                    Icon(Icons.Default.Public, contentDescription = null, tint = AdGuardBlueDns, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Trang chủ", fontSize = 12.sp, color = AdGuardBlueDns)
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))
    }
}

@Composable
private fun InfoRow(label: String, value: String, valueColor: Color = AdGuardTextPrimary) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp),
    ) {
        Text(label, fontSize = 12.sp, color = AdGuardTextMuted, modifier = Modifier.width(110.dp))
        Text(value, fontSize = 12.sp, color = valueColor, modifier = Modifier.weight(1f))
    }
}
