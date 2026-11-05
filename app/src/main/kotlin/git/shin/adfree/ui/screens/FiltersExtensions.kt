package git.shin.adfree.ui.screens

import git.shin.adfree.l10n.L10n
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.R
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
import git.shin.adfree.ui.theme.AdGuardOnAccent
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
                label = { Text(stringResource(R.string.ext_editor_name_label), fontSize = 12.sp) },
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
                label = { Text(stringResource(R.string.ext_editor_code_label), fontSize = 12.sp) },
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
                    Text(confirmText, color = AdGuardOnAccent, fontWeight = FontWeight.Bold)
                }
                TextButton(onClick = onDismiss) {
                    Text(stringResource(R.string.common_cancel), color = AdGuardTextSecondary)
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
                        .size(36.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(AdGuardPurpleAI.copy(alpha = 0.12f)),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(Icons.Default.Extension, contentDescription = null, tint = AdGuardPurpleAI, modifier = Modifier.size(18.dp))
                }
                Spacer(modifier = Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        stringResource(R.string.hub_extensions_title),
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardTextPrimary,
                    )
                    Text(
                        stringResource(R.string.ext_section_subtitle),
                        fontSize = 11.sp,
                        color = AdGuardTextMuted,
                    )
                    // AdGuard shows "Enabled: 1 of 2" on the hub row; the
                    // honest count belongs next to the master switch that
                    // ultimately decides if any of them run.
                    if (scripts.isNotEmpty()) {
                        Text(
                            text = if (masterEnabled) {
                                stringResource(
                                    R.string.ext_enabled_count,
                                    scripts.count { it.isEnabled },
                                    scripts.size,
                                )
                            } else {
                                stringResource(R.string.hub_extensions_master_off)
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
                    text = stringResource(R.string.ext_empty),
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
                    Text(
                        stringResource(R.string.ext_add),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardGreenLight,
                    )
                }
                TextButton(
                    onClick = onOpenStore,
                    modifier = Modifier.testTag("script_store_btn"),
                ) {
                    Icon(Icons.Default.Search, contentDescription = null, tint = AdGuardBlueDns, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        stringResource(R.string.ext_store),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardBlueDns,
                    )
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
                Text(
                    stringResource(R.string.ext_store),
                    fontSize = 17.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextPrimary,
                )
                Text(
                    stringResource(R.string.ext_store_subtitle),
                    fontSize = 11.sp,
                    color = AdGuardTextMuted,
                )
            }
        }

        Spacer(modifier = Modifier.height(10.dp))
        Text(
            stringResource(R.string.ext_store_note),
            fontSize = 11.sp,
            color = AdGuardTextMuted,
        )
        Spacer(modifier = Modifier.height(10.dp))

        OutlinedTextField(
            value = state.query,
            onValueChange = onQueryChange,
            placeholder = {
                Text(
                    stringResource(R.string.ext_store_search_hint),
                    fontSize = 12.sp,
                    color = AdGuardTextMuted,
                )
            },
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
                UserScriptStoreSort.RELEVANCE to R.string.ext_sort_relevance,
                UserScriptStoreSort.DAILY_INSTALLS to R.string.ext_sort_daily,
                UserScriptStoreSort.TOTAL_INSTALLS to R.string.ext_sort_total,
                UserScriptStoreSort.RATINGS to R.string.ext_sort_ratings,
                UserScriptStoreSort.UPDATED to R.string.ext_sort_updated,
                UserScriptStoreSort.NAME to R.string.ext_sort_name,
            ).forEach { (sort, label) ->
                FilterChip(
                    selected = state.sort == sort,
                    onClick = { onSortChange(sort) },
                    label = { Text(stringResource(label), fontSize = 10.sp) },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = AdGuardGreenPrimary,
                        selectedLabelColor = AdGuardOnAccent,
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
                Text(
                    stringResource(R.string.ext_store_page, state.page),
                    fontSize = 10.sp,
                    color = AdGuardTextMuted,
                )
                TextButton(
                    onClick = onFirstPage,
                    modifier = Modifier.testTag("script_store_first_page"),
                ) {
                    Text(
                        stringResource(R.string.ext_store_first_page),
                        fontSize = 11.sp,
                        color = AdGuardGreenLight,
                    )
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
                Text(state.error ?: "", fontSize = 11.sp, color = AdGuardRedBlocked)
                TextButton(onClick = onRetry) {
                    Text(
                        stringResource(R.string.ext_retry),
                        fontSize = 12.sp,
                        color = AdGuardGreenLight,
                    )
                }
            }

            state.items.isEmpty() -> {
                Text(
                    stringResource(R.string.ext_store_empty),
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
                state.error?.let { error ->
                    Text(error, fontSize = 11.sp, color = AdGuardRedBlocked)
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
                                        Text(
                                            stringResource(R.string.ext_load_more),
                                            fontSize = 12.sp,
                                            color = AdGuardGreenLight,
                                        )
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
                        if (item.totalInstalls > 0) add(
                            stringResource(
                                R.string.ext_installs,
                                storeInstallsText(item.totalInstalls),
                            )
                        )
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
                        Text(
                            stringResource(R.string.ext_install),
                            color = AdGuardOnAccent,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                        )
                    }

                    installed.isEnabled && installed.sizeBytes > 0 -> OutlinedButton(
                        onClick = {},
                        enabled = false,
                        shape = RoundedCornerShape(8.dp),
                    ) {
                        Text(stringResource(R.string.ext_enabled), fontSize = 11.sp)
                    }

                    else -> OutlinedButton(
                        onClick = { onEnable(installed) },
                        shape = RoundedCornerShape(8.dp),
                    ) {
                        Text(
                            if (installed.isEnabled) stringResource(R.string.ext_reload)
                            else stringResource(R.string.ext_turn_on),
                            fontSize = 11.sp,
                            color = AdGuardGreenLight,
                        )
                    }
                }
            }
            if (item.pageUrl.isNotBlank()) {
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = stringResource(R.string.ext_store_source),
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

/** Catalogue scripts carry string keys; imported/created ones keep their text. */
@Composable
private fun scriptDisplayName(script: UserScriptInfo): String =
    script.nameKey?.let { L10n.get(it) } ?: script.name

@Composable
private fun scriptDisplayDescription(script: UserScriptInfo): String =
    script.descriptionKey?.let { L10n.get(it) } ?: script.description

@Composable
private fun ScriptRow(
    script: UserScriptInfo,
    /** When the master switch is off, this row cannot turn anything on. */
    masterEnabled: Boolean,
    onToggle: () -> Unit,
    onClick: () -> Unit,
) {
    val updatedText = script.lastUpdatedText.ifBlank {
        stringResource(R.string.filter_not_loaded)
    }
    val meta = when {
        script.isBuiltin -> stringResource(R.string.ext_builtin_meta, updatedText)
        script.sizeBytes > 0 -> stringResource(
            R.string.ext_size_meta,
            script.sizeBytes / 1024,
            updatedText,
        )
        else -> stringResource(R.string.ext_not_downloaded_meta)
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
                text = scriptDisplayName(script),
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
                Text(
                    stringResource(R.string.ext_add),
                    fontSize = 17.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextPrimary,
                )
            }
        },
        text = {
            Column {
                Text(
                    text = stringResource(R.string.ext_add_body),
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
                        text = stringResource(R.string.ext_security_warning),
                        fontSize = 11.sp,
                        color = AdGuardOrangeWarning,
                    )
                }
                Spacer(modifier = Modifier.height(12.dp))
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text(stringResource(R.string.ext_name_optional), fontSize = 12.sp) },
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
                    label = { Text(stringResource(R.string.ext_url_label), fontSize = 12.sp) },
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
                        Text(
                            stringResource(R.string.ext_pick_file),
                            fontSize = 11.sp,
                            color = AdGuardGreenLight,
                        )
                    }
                    OutlinedButton(onClick = onCreate, shape = RoundedCornerShape(8.dp)) {
                        Text(
                            stringResource(R.string.ext_create_new),
                            fontSize = 11.sp,
                            color = AdGuardBlueDns,
                        )
                    }
                }
                Text(
                    stringResource(R.string.ext_add_footnote),
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
                Text(
                    stringResource(R.string.ext_add_download),
                    color = AdGuardOnAccent,
                    fontWeight = FontWeight.Bold,
                )
            }
        },
        dismissButton = {
            OutlinedButton(onClick = onDismiss, shape = RoundedCornerShape(8.dp)) {
                Text(stringResource(R.string.common_cancel), color = AdGuardTextSecondary)
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
        Text(
            scriptDisplayName(script),
            fontSize = 16.sp,
            fontWeight = FontWeight.Black,
            color = AdGuardTextPrimary,
        )
        val description = scriptDisplayDescription(script)
        if (description.isNotBlank()) {
            Spacer(modifier = Modifier.height(4.dp))
            Text(description, fontSize = 12.sp, color = AdGuardTextSecondary)
        }

        Spacer(modifier = Modifier.height(14.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    stringResource(R.string.ext_detail_enable_title),
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextPrimary,
                )
                Text(
                    text = when {
                        // The master gate beats the per-script flag: say it
                        // out loud instead of "Đang chạy" with nothing running.
                        !masterEnabled -> stringResource(R.string.ext_detail_master_off)
                        script.isEnabled -> stringResource(R.string.ext_detail_running)
                        else -> stringResource(R.string.ext_detail_off)
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

        ScriptInfoRow(
            stringResource(R.string.ext_detail_size),
            if (script.sizeBytes > 0) "${script.sizeBytes / 1024} KB"
            else stringResource(R.string.filter_not_loaded),
        )
        ScriptInfoRow(
            stringResource(R.string.ext_detail_updated),
            script.lastUpdatedText.ifBlank { stringResource(R.string.filter_not_loaded) },
        )

        // Header fields are what tells a user whether a script touches more
        // than the page it was installed for. Show them only when present.
        if (script.metadata.version.isNotBlank()) {
            ScriptInfoRow(stringResource(R.string.ext_detail_version), script.metadata.version)
        }
        if (script.metadata.runAt.isNotBlank()) {
            ScriptInfoRow(
                stringResource(R.string.ext_detail_run_at),
                runAtLabel(script.metadata.runAt),
            )
        }
        if (script.metadata.patterns.isNotEmpty()) {
            val shown = script.metadata.patterns.take(3)
            val extra = script.metadata.patterns.size - shown.size
            ScriptInfoRow(
                stringResource(R.string.ext_detail_patterns),
                buildString {
                    append(shown.joinToString("\n"))
                    if (extra > 0) {
                        append('\n')
                        append(stringResource(R.string.ext_detail_more_patterns, extra))
                    }
                },
            )
        }
        val grants = script.metadata.grants.filter { it != "none" }
        if (grants.isNotEmpty()) {
            ScriptInfoRow(stringResource(R.string.ext_detail_grants), grants.joinToString(" · "))
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
                    text = stringResource(R.string.ext_broad_warning),
                    fontSize = 11.sp,
                    color = AdGuardOrangeWarning,
                )
            }
        }

        Spacer(modifier = Modifier.height(6.dp))
        if (script.isBuiltin) {
            Text(
                text = stringResource(R.string.ext_bundled),
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
                    Text(
                        stringResource(R.string.ext_update),
                        fontSize = 12.sp,
                        color = AdGuardGreenLight,
                    )
                }
            }
            if (script.isUserAdded) {
                OutlinedButton(onClick = onEdit, shape = RoundedCornerShape(10.dp)) {
                    Icon(Icons.Default.Edit, contentDescription = null, tint = AdGuardBlueDns, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        stringResource(R.string.ext_edit_code),
                        fontSize = 12.sp,
                        color = AdGuardBlueDns,
                    )
                }
                OutlinedButton(onClick = onDelete, shape = RoundedCornerShape(10.dp)) {
                    Icon(Icons.Default.Delete, contentDescription = null, tint = AdGuardRedBlocked, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        stringResource(R.string.ext_delete),
                        fontSize = 12.sp,
                        color = AdGuardRedBlocked,
                    )
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
@Composable
private fun runAtLabel(value: String): String = when (value.lowercase()) {
    "document-start" -> stringResource(R.string.ext_run_at_start)
    "document-end" -> stringResource(R.string.ext_run_at_end)
    "document-idle" -> stringResource(R.string.ext_run_at_idle)
    "document-body" -> stringResource(R.string.ext_run_at_body)
    else -> value
}
