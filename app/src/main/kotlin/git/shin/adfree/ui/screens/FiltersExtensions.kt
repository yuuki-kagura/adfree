package git.shin.adfree.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Extension
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.model.UserScriptInfo
import git.shin.adfree.model.UserScriptStoreItem
import git.shin.adfree.model.UserScriptStoreSort
import git.shin.adfree.model.UserScriptStoreState
import git.shin.adfree.ui.theme.AdGuardBlueDns
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
import kotlinx.coroutines.withContext
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.LaunchedEffect

/**
 * Simple text editor for creating or editing userscript source.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScriptTextEditorDialog(
    title: String,
    initialName: String,
    initialText: String,
    confirmText: String,
    onDismiss: () -> Unit,
    onConfirm: (String, String) -> Unit,
    loadText: (() -> String)? = null,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var name by remember { mutableStateOf(initialName) }
    var text by remember { mutableStateOf(initialText) }
    LaunchedEffect(Unit) {
        if (loadText != null && initialText.isBlank()) {
            // A userscript can be tens of KB; read it off the main thread.
            text = withContext(kotlinx.coroutines.Dispatchers.IO) { loadText() }
        }
    }
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = AdGuardDarkSurface,
        contentColor = AdGuardTextPrimary,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 10.dp)
                .verticalScroll(rememberScrollState()),
        ) {
            Text(title, fontSize = 17.sp, fontWeight = FontWeight.Bold, color = AdGuardTextPrimary)
            Spacer(modifier = Modifier.height(10.dp))
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text("Tên tiện ích", fontSize = 12.sp) },
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
                value = text,
                onValueChange = { text = it },
                label = { Text("Mã nguồn (.user.js)", fontSize = 12.sp) },
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 260.dp),
                shape = RoundedCornerShape(10.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = AdGuardGreenPrimary,
                    unfocusedBorderColor = AdGuardDarkOutline,
                    focusedTextColor = AdGuardTextPrimary,
                    unfocusedTextColor = AdGuardTextPrimary,
                ),
            )
            Spacer(modifier = Modifier.height(10.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = { onConfirm(name, text) },
                    enabled = text.isNotBlank(),
                    colors = ButtonDefaults.buttonColors(containerColor = AdGuardGreenPrimary),
                    shape = RoundedCornerShape(8.dp),
                ) {
                    Text(confirmText, color = Color.Black, fontWeight = FontWeight.Bold)
                }
                TextButton(onClick = onDismiss) {
                    Text("Hủy", color = AdGuardTextSecondary)
                }
            }
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

/**
 * The Extensions block of the "Bộ lọc" tab: userscripts that run on filtered
 * pages, behind a single master switch. The core reads each script's
 * Tampermonkey header, so a script only runs where its `@match` / `@include`
 * says it should.
 *
 * A script is only pushed to the core once its body is on disk, so the same
 * switch silently downloads a catalogue entry the first time it is turned on.
 */
@Composable
fun ExtensionsSection(
    scripts: List<UserScriptInfo>,
    masterEnabled: Boolean,
    onToggleMaster: (Boolean) -> Unit,
    onToggleScript: (UserScriptInfo, Boolean) -> Unit,
    onOpenScript: (UserScriptInfo) -> Unit,
    onAddScript: () -> Unit,
    onOpenStore: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("extensions_section"),
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
                        .background(AdGuardPurpleAI.copy(alpha = 0.12f)),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(Icons.Default.Extension, contentDescription = null, tint = AdGuardPurpleAI, modifier = Modifier.size(20.dp))
                }
                Spacer(modifier = Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text("Tiện ích", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = AdGuardTextPrimary)
                    Text(
                        "Script theo phạm vi @match / @include",
                        fontSize = 11.sp,
                        color = AdGuardTextMuted,
                    )
                    // AdGuard shows "Enabled: 1 of 2" on the hub row; the
                    // honest count belongs next to the master switch that
                    // ultimately decides if any of them run.
                    if (scripts.isNotEmpty()) {
                        Text(
                            text = if (masterEnabled) {
                                "Bật: ${scripts.count { it.isEnabled }}/${scripts.size} script"
                            } else {
                                "Tắt tổng — không script nào chạy"
                            },
                            fontSize = 11.sp,
                            color = AdGuardTextMuted,
                        )
                    }
                }
                Switch(
                    checked = masterEnabled,
                    onCheckedChange = { onToggleMaster(it) },
                    colors = SwitchDefaults.colors(checkedTrackColor = AdGuardGreenPrimary),
                )
            }

            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(1.dp)
                    .background(AdGuardDarkOutline),
            )

            if (scripts.isEmpty()) {
                Text(
                    text = "Chưa có tiện ích nào. Thêm một userscript (.user.js) để bắt đầu.",
                    fontSize = 11.sp,
                    color = AdGuardTextMuted,
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
                )
            } else {
                for (script in scripts) {
                    ScriptRow(
                        script = script,
                        masterEnabled = masterEnabled,
                        onToggle = { onToggleScript(script, !script.isEnabled) },
                        onClick = { onOpenScript(script) },
                    )
                }
            }

            Row(
                modifier = Modifier.padding(start = 6.dp, bottom = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                TextButton(
                    onClick = onAddScript,
                    modifier = Modifier.testTag("add_script_btn"),
                ) {
                    Icon(Icons.Default.Add, contentDescription = null, tint = AdGuardGreenLight, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Thêm tiện ích", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = AdGuardGreenLight)
                }
                TextButton(
                    onClick = onOpenStore,
                    modifier = Modifier.testTag("script_store_btn"),
                ) {
                    Icon(Icons.Default.Search, contentDescription = null, tint = AdGuardBlueDns, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Kho tiện ích", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = AdGuardBlueDns)
                }
            }
        }
    }
}

/**
 * Greasy Fork search sheet. Installing is an explicit tap per row; the store
 * never turns a script on by itself. Installed rows show the live state from
 * the userscript list instead of a separate copy.
 */
@Composable
fun UserScriptStoreSheet(
    state: UserScriptStoreState,
    installedByUrl: Map<String, UserScriptInfo>,
    onQueryChange: (String) -> Unit,
    onSortChange: (UserScriptStoreSort) -> Unit,
    onLoadMore: () -> Unit,
    onFirstPage: () -> Unit,
    onInstall: (UserScriptStoreItem) -> Unit,
    onEnable: (UserScriptInfo) -> Unit,
    onOpenPage: (String) -> Unit,
    onRetry: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp, vertical = 8.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Search, contentDescription = null, tint = AdGuardBlueDns, modifier = Modifier.size(22.dp))
            Spacer(modifier = Modifier.width(8.dp))
            Column {
                Text("Kho tiện ích", fontSize = 17.sp, fontWeight = FontWeight.Bold, color = AdGuardTextPrimary)
                Text(
                    "Tìm trên Greasy Fork • script tự chạy theo @match",
                    fontSize = 11.sp,
                    color = AdGuardTextMuted,
                )
            }
        }

        Spacer(modifier = Modifier.height(10.dp))
        Text(
            "Script chạy mã của tác giả trong trang. Chỉ cài khi bạn tin tưởng nguồn; " +
                "GM_xmlhttpRequest/GM_download vẫn theo CORS của trang, GM_setValue và @resource chưa hỗ trợ.",
            fontSize = 11.sp,
            color = AdGuardTextMuted,
        )
        Spacer(modifier = Modifier.height(10.dp))

        OutlinedTextField(
            value = state.query,
            onValueChange = onQueryChange,
            placeholder = { Text("Tìm script…", fontSize = 12.sp, color = AdGuardTextMuted) },
            leadingIcon = {
                Icon(Icons.Default.Search, contentDescription = null, tint = AdGuardTextMuted, modifier = Modifier.size(18.dp))
            },
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

        Spacer(modifier = Modifier.height(10.dp))

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            listOf(
                UserScriptStoreSort.RELEVANCE to "Mặc định",
                UserScriptStoreSort.DAILY_INSTALLS to "Cài/ngày",
                UserScriptStoreSort.TOTAL_INSTALLS to "Tổng cài",
                UserScriptStoreSort.RATINGS to "Đánh giá",
                UserScriptStoreSort.UPDATED to "Mới cập nhật",
                UserScriptStoreSort.NAME to "Tên A-Z",
            ).forEach { (sort, label) ->
                FilterChip(
                    selected = state.sort == sort,
                    onClick = { onSortChange(sort) },
                    label = { Text(label, fontSize = 10.sp) },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = AdGuardGreenPrimary,
                        selectedLabelColor = Color.Black,
                        containerColor = AdGuardDarkSurface,
                        labelColor = AdGuardTextSecondary,
                    ),
                )
            }
        }

        if (state.page > 1) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text("Trang ${state.page}", fontSize = 10.sp, color = AdGuardTextMuted)
                TextButton(
                    onClick = onFirstPage,
                    modifier = Modifier.testTag("script_store_first_page"),
                ) {
                    Text("Về trang 1", fontSize = 11.sp, color = AdGuardGreenLight)
                }
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        when {
            state.loading && state.items.isEmpty() -> {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(140.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    CircularProgressIndicator(
                        color = AdGuardGreenPrimary,
                        strokeWidth = 2.dp,
                        modifier = Modifier.size(28.dp),
                    )
                }
            }

            state.error != null && state.items.isEmpty() -> {
                Text(state.error, fontSize = 11.sp, color = AdGuardRedBlocked)
                TextButton(onClick = onRetry) {
                    Text("Thử lại", fontSize = 12.sp, color = AdGuardGreenLight)
                }
            }

            state.items.isEmpty() -> {
                Text(
                    "Không tìm thấy tiện ích phù hợp.",
                    fontSize = 11.sp,
                    color = AdGuardTextMuted,
                    modifier = Modifier.padding(vertical = 16.dp),
                )
            }

            else -> {
                if (state.loading) {
                    LinearProgressIndicator(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(2.dp),
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                }
                if (state.error != null) {
                    Text(state.error, fontSize = 11.sp, color = AdGuardRedBlocked)
                    Spacer(modifier = Modifier.height(6.dp))
                }
                LazyColumn(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 470.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    items(state.items, key = { it.url }) { item ->
                        StoreScriptRow(
                            item = item,
                            installed = installedByUrl[item.url],
                            onInstall = { onInstall(item) },
                            onEnable = onEnable,
                            onOpenPage = { onOpenPage(item.pageUrl) },
                        )
                    }
                    if (state.hasMore || state.loadingMore) {
                        item(key = "load_more") {
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 8.dp),
                                contentAlignment = Alignment.Center,
                            ) {
                                if (state.loadingMore) {
                                    CircularProgressIndicator(
                                        color = AdGuardGreenPrimary,
                                        strokeWidth = 2.dp,
                                        modifier = Modifier.size(24.dp),
                                    )
                                } else {
                                    OutlinedButton(
                                        onClick = onLoadMore,
                                        modifier = Modifier.testTag("script_store_load_more"),
                                    ) {
                                        Text("Tải thêm", fontSize = 12.sp, color = AdGuardGreenLight)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))
    }
}

@Composable
private fun StoreScriptRow(
    item: UserScriptStoreItem,
    installed: UserScriptInfo?,
    onInstall: () -> Unit,
    onEnable: (UserScriptInfo) -> Unit,
    onOpenPage: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurfaceVariant),
        border = BorderStroke(1.dp, AdGuardDarkOutline),
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.Top) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = item.name,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = AdGuardTextPrimary,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                    if (item.description.isNotBlank()) {
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = item.description,
                            fontSize = 11.sp,
                            color = AdGuardTextSecondary,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    Spacer(modifier = Modifier.height(5.dp))
                    val bits = buildList {
                        if (item.version.isNotBlank()) add("v${item.version}")
                        if (item.totalInstalls > 0) add("${storeInstallsText(item.totalInstalls)} lượt cài")
                        if (item.codeSizeBytes > 0) add("${item.codeSizeBytes / 1024} KB")
                        if (item.license.isNotBlank()) add(item.license)
                    }
                    if (bits.isNotEmpty()) {
                        Text(
                            text = bits.joinToString(" • "),
                            fontSize = 10.sp,
                            color = AdGuardTextMuted,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
                Spacer(modifier = Modifier.width(8.dp))
                when {
                    installed == null -> Button(
                        onClick = onInstall,
                        colors = ButtonDefaults.buttonColors(containerColor = AdGuardGreenPrimary),
                        shape = RoundedCornerShape(8.dp),
                    ) {
                        Text("Cài", color = Color.Black, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }

                    installed.isEnabled && installed.sizeBytes > 0 -> OutlinedButton(
                        onClick = {},
                        enabled = false,
                        shape = RoundedCornerShape(8.dp),
                    ) {
                        Text("Đang bật", fontSize = 11.sp)
                    }

                    else -> OutlinedButton(
                        onClick = { onEnable(installed) },
                        shape = RoundedCornerShape(8.dp),
                    ) {
                        Text(
                            if (installed.isEnabled) "Tải lại" else "Bật",
                            fontSize = 11.sp,
                            color = AdGuardGreenLight,
                        )
                    }
                }
            }
            if (item.pageUrl.isNotBlank()) {
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Nguồn Greasy Fork",
                    fontSize = 10.sp,
                    color = AdGuardBlueDns,
                    modifier = Modifier.clickable { onOpenPage() },
                )
            }
        }
    }
}

private fun storeInstallsText(count: Int): String = when {
    count >= 1_000_000 -> "${count / 1_000_000}M"
    count >= 1_000 -> "${count / 1_000}k"
    else -> count.toString()
}

@Composable
private fun ScriptRow(
    script: UserScriptInfo,
    /** When the master switch is off, this row cannot turn anything on. */
    masterEnabled: Boolean,
    onToggle: () -> Unit,
    onClick: () -> Unit,
) {
    val meta = when {
        script.isBuiltin -> "Cài sẵn trong ứng dụng • ${script.lastUpdatedText}"
        script.sizeBytes > 0 -> "${script.sizeBytes / 1024} KB • ${script.lastUpdatedText}"
        else -> "Chưa tải • Bật để tải về"
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() }
            .padding(start = 14.dp, end = 8.dp, top = 6.dp, bottom = 6.dp)
            .alpha(if (masterEnabled) 1f else 0.55f),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = script.name,
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold,
                color = AdGuardTextPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(text = meta, fontSize = 10.sp, color = AdGuardTextMuted)
        }
        Switch(
            checked = script.isEnabled,
            enabled = masterEnabled,
            onCheckedChange = { onToggle() },
            colors = SwitchDefaults.colors(checkedTrackColor = AdGuardGreenPrimary),
        )
    }
}

/** Dialog for adding a userscript by URL, from file, or by creating text. */
@Composable
fun AddScriptDialog(
    onDismiss: () -> Unit,
    onAdd: (String, String) -> Unit,
    onImportFile: () -> Unit = {},
    onCreate: () -> Unit = {},
) {
    var name by remember { mutableStateOf("") }
    var url by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Extension, contentDescription = null, tint = AdGuardPurpleAI, modifier = Modifier.size(22.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text("Thêm tiện ích", fontSize = 17.sp, fontWeight = FontWeight.Bold, color = AdGuardTextPrimary)
            }
        },
        text = {
            Column {
                Text(
                    text = "Dán đường dẫn tới tệp userscript (.user.js). AdFree đọc @match, " +
                        "@include, @exclude, @run-at, @noframes và tải @require khi cài từ URL " +
                        "(tệp nhập tay giữ nguyên nội dung, @require không tự tải). " +
                        "Hỗ trợ unsafeWindow, GM_addStyle, GM_log, GM_info, GM_xmlhttpRequest/" +
                        "GM_download (theo CORS của trang), GM_openInTab, GM_notification, " +
                        "GM_setClipboard, GM_addElement; GM_setValue và @resource chưa hỗ trợ.",
                    fontSize = 12.sp,
                    color = AdGuardTextSecondary,
                )
                Spacer(modifier = Modifier.height(8.dp))
                // AdGuard shows the same warning before installing an
                // extension: a userscript sees the page it runs on.
                Row(verticalAlignment = Alignment.Top) {
                    Icon(
                        Icons.Default.Warning,
                        contentDescription = null,
                        tint = AdGuardOrangeWarning,
                        modifier = Modifier.size(14.dp),
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "Tiện ích đọc và sửa được nội dung trang nó chạy trên. " +
                            "Chỉ cài từ nguồn bạn tin cậy.",
                        fontSize = 11.sp,
                        color = AdGuardOrangeWarning,
                    )
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
                    label = { Text("Đường dẫn (.user.js)", fontSize = 12.sp) },
                    placeholder = { Text("https://…", fontSize = 12.sp, color = AdGuardTextMuted) },
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
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    OutlinedButton(onClick = onImportFile, shape = RoundedCornerShape(8.dp)) {
                        Text("Chọn tệp", fontSize = 11.sp, color = AdGuardGreenLight)
                    }
                    OutlinedButton(onClick = onCreate, shape = RoundedCornerShape(8.dp)) {
                        Text("Tạo mới", fontSize = 11.sp, color = AdGuardBlueDns)
                    }
                }
                Text(
                    "Lưu ý: tiện ích có thể truy cập dữ liệu trang — chỉ cài những script bạn hiểu và tin cậy.",
                    fontSize = 11.sp,
                    color = AdGuardTextMuted,
                )
            }
        },
        confirmButton = {
            Button(
                onClick = { if (url.isNotBlank()) onAdd(name, url) },
                enabled = url.isNotBlank(),
                colors = ButtonDefaults.buttonColors(containerColor = AdGuardGreenPrimary),
                shape = RoundedCornerShape(8.dp),
            ) {
                Text("Thêm và tải", color = Color.Black, fontWeight = FontWeight.Bold)
            }
        },
        dismissButton = {
            OutlinedButton(onClick = onDismiss, shape = RoundedCornerShape(8.dp)) {
                Text("Hủy", color = AdGuardTextSecondary)
            }
        },
    )
}

/** Bottom sheet with everything we know about one userscript. */
@Composable
fun ScriptDetailSheet(
    script: UserScriptInfo,
    /** With the master switch off, even an enabled script cannot run. */
    masterEnabled: Boolean = true,
    onToggle: () -> Unit,
    onRefresh: () -> Unit,
    onEdit: () -> Unit = {},
    onDelete: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp, vertical = 12.dp),
    ) {
        Text(script.name, fontSize = 16.sp, fontWeight = FontWeight.Black, color = AdGuardTextPrimary)
        if (script.description.isNotBlank()) {
            Spacer(modifier = Modifier.height(4.dp))
            Text(script.description, fontSize = 12.sp, color = AdGuardTextSecondary)
        }

        Spacer(modifier = Modifier.height(14.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text("Bật tiện ích này", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = AdGuardTextPrimary)
                Text(
                    text = when {
                        // The master gate beats the per-script flag: say it
                        // out loud instead of "Đang chạy" with nothing running.
                        !masterEnabled -> "Tiện ích bị tắt tổng — không script nào chạy"
                        script.isEnabled -> "Đang chạy khi lọc HTTPS bật"
                        else -> "Đang tắt"
                    },
                    fontSize = 11.sp,
                    color = AdGuardTextMuted,
                )
            }
            Switch(
                checked = script.isEnabled,
                enabled = masterEnabled,
                onCheckedChange = { onToggle() },
                colors = SwitchDefaults.colors(checkedTrackColor = AdGuardGreenPrimary),
            )
        }

        Spacer(modifier = Modifier.height(12.dp))

        ScriptInfoRow("Kích thước", if (script.sizeBytes > 0) "${script.sizeBytes / 1024} KB" else "Chưa tải")
        ScriptInfoRow("Cập nhật", script.lastUpdatedText)

        // Header fields are what tells a user whether a script touches more
        // than the page it was installed for. Show them only when present.
        if (script.metadata.version.isNotBlank()) {
            ScriptInfoRow("Phiên bản", script.metadata.version)
        }
        if (script.metadata.runAt.isNotBlank()) {
            ScriptInfoRow("Chạy ở", runAtLabel(script.metadata.runAt))
        }
        if (script.metadata.patterns.isNotEmpty()) {
            val shown = script.metadata.patterns.take(3)
            val extra = script.metadata.patterns.size - shown.size
            ScriptInfoRow(
                "Trang áp dụng",
                buildString {
                    append(shown.joinToString("\n"))
                    if (extra > 0) append("\n+$extra mẫu nữa")
                },
            )
        }
        val grants = script.metadata.grants.filter { it != "none" }
        if (grants.isNotEmpty()) {
            ScriptInfoRow("Quyền", grants.joinToString(" · "))
        }
        if (script.metadata.hasBroadAccess) {
            Spacer(modifier = Modifier.height(6.dp))
            Row(verticalAlignment = Alignment.Top) {
                Icon(
                    Icons.Default.Warning,
                    contentDescription = null,
                    tint = AdGuardOrangeWarning,
                    modifier = Modifier.size(14.dp),
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = "Script dùng API vượt phạm vi trang (GM_xmlhttpRequest, unsafeWindow…). " +
                        "Chỉ nên bật khi bạn tin nguồn phát hành.",
                    fontSize = 11.sp,
                    color = AdGuardOrangeWarning,
                )
            }
        }

        Spacer(modifier = Modifier.height(6.dp))
        if (script.isBuiltin) {
            Text(
                text = "Đi kèm ứng dụng, cập nhật theo bản phát hành.",
                fontSize = 11.sp,
                color = AdGuardTextMuted,
            )
        } else {
            Text(
                text = script.url,
                fontSize = 10.sp,
                fontFamily = FontFamily.Monospace,
                color = AdGuardTextMuted,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (!script.isBuiltin && script.url.isNotBlank()) {
                OutlinedButton(onClick = onRefresh, shape = RoundedCornerShape(10.dp)) {
                    Icon(Icons.Default.Sync, contentDescription = null, tint = AdGuardGreenLight, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Cập nhật", fontSize = 12.sp, color = AdGuardGreenLight)
                }
            }
            if (script.isUserAdded) {
                OutlinedButton(onClick = onEdit, shape = RoundedCornerShape(10.dp)) {
                    Icon(Icons.Default.Edit, contentDescription = null, tint = AdGuardBlueDns, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Sửa mã", fontSize = 12.sp, color = AdGuardBlueDns)
                }
                OutlinedButton(onClick = onDelete, shape = RoundedCornerShape(10.dp)) {
                    Icon(Icons.Default.Delete, contentDescription = null, tint = AdGuardRedBlocked, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Xóa", fontSize = 12.sp, color = AdGuardRedBlocked)
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))
    }
}

@Composable
private fun ScriptInfoRow(label: String, value: String) {
    Row(modifier = Modifier
        .fillMaxWidth()
        .padding(vertical = 3.dp)) {
        Text(label, fontSize = 12.sp, color = AdGuardTextMuted, modifier = Modifier.width(110.dp))
        Text(value, fontSize = 12.sp, color = AdGuardTextPrimary, modifier = Modifier.weight(1f))
    }
}

/** `@run-at` value → words a user can act on. */
private fun runAtLabel(value: String): String = when (value.lowercase()) {
    "document-start" -> "Trước khi trang tải"
    "document-end" -> "Sau khi trang tải"
    "document-idle" -> "Khi trang rảnh"
    "document-body" -> "Khi trang có <body>"
    else -> value
}
