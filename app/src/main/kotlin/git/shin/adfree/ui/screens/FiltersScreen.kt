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
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.CheckCircle
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
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.R
import git.shin.adfree.data.FilterGroup
import git.shin.adfree.data.ModuleGate
import git.shin.adfree.data.moduleGate
import git.shin.adfree.model.FilterList
import git.shin.adfree.model.assetSizeLabel
import git.shin.adfree.model.filterMatchesQuery
import git.shin.adfree.model.filterUrlError
import git.shin.adfree.ui.AdGuardIntent
import git.shin.adfree.ui.AdGuardViewModel
import git.shin.adfree.ui.CoreText
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
import git.shin.adfree.ui.theme.AdGuardOnAccent
import git.shin.adfree.ui.theme.AdGuardTextSecondary

/**
 * The filter-list destination inside the filtering hub: catalogue, custom
 * lists and user rules.
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
    onBack: (() -> Unit)? = null,
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsState()
    val context = LocalContext.current
    val uriHandler = LocalUriHandler.current
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

    // Local files are imported through the system picker; the URI is read once
    // and copied into the app's own directory (SAF permissions are not trusted
    // to survive). The same picker serves both add sheets.
    var pickFileForDns by remember { mutableStateOf(false) }
    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            runCatching {
                context.contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION,
                )
            }
            viewModel.onIntent(
                AdGuardIntent.ImportLocalFilter(uri.toString(), dnsOnly = pickFileForDns),
            )
        }
        pickFileForDns = false
    }
    val query = state.filterSearchQuery
    // Catalogue text is localized at render time; search has to see the same
    // words the user does, not the stable brand/filename fields.
    val displayNames = state.filterLists.associate { it.id to filterDisplayName(it) }
    val displayDescriptions = state.filterLists.associate { it.id to filterDisplayDescription(it) }
    val matchesQuery: (FilterList) -> Boolean = { list ->
        filterMatchesQuery(
            list = list,
            query = query,
            name = displayNames[list.id] ?: list.name,
            description = displayDescriptions[list.id] ?: list.description,
        )
    }
    val catalogLists = state.filterLists.filter { !it.isCustom && !it.isUserAdded }
    // DNS filters block name lookups only and live in their own card, so the
    // web-filter counters above must not count their rules.
    val customLists = state.filterLists.filter { it.isUserAdded && !it.isDnsOnly }
    val dnsLists = state.filterLists.filter { it.isDnsOnly }
    val visibleCatalog = catalogLists.filter(matchesQuery)
    val visibleCustom = customLists.filter(matchesQuery)
    val visibleDns = dnsLists.filter(matchesQuery)
    val userRules = state.filterLists.firstOrNull { it.isCustom }?.customRules.orEmpty()
    val userRulesCount = userRules.size
    val allowCount = userRules.count { it.startsWith("@@") }
    val webLists = state.filterLists.filter { !it.isCustom && !it.isDnsOnly }
    val enabledCount = webLists.count { it.isEnabled }
    val totalRules = webLists.filter { it.isEnabled }.sumOf { it.ruleCount }

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
                onBack?.let {
                    IconButton(onClick = it) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.hub_back),
                            tint = AdGuardTextPrimary,
                        )
                    }
                }
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.nav_filters),
                        fontSize = 19.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardTextPrimary,
                    )
                    Text(
                        text = stringResource(
                            R.string.hub_filters_subtitle,
                            enabledCount,
                            "%,d".format(totalRules),
                        ),
                        fontSize = 12.sp,
                        color = AdGuardTextMuted,
                    )
                }
                Box {
                    IconButton(onClick = { showOverflow = true }) {
                        Icon(
                            Icons.Default.MoreVert,
                            contentDescription = stringResource(R.string.filters_more_options),
                            tint = AdGuardTextSecondary,
                        )
                    }
                    DropdownMenu(expanded = showOverflow, onDismissRequest = { showOverflow = false }) {
                        DropdownMenuItem(
                            text = {
                                Text(
                                    stringResource(R.string.filters_restore_defaults),
                                    fontSize = 13.sp,
                                )
                            },
                            onClick = {
                                showOverflow = false
                                showResetConfirm = true
                            },
                            leadingIcon = {
                                Icon(Icons.Default.Refresh, contentDescription = null, tint = AdGuardTextSecondary, modifier = Modifier.size(18.dp))
                            },
                        )
                        DropdownMenuItem(
                            text = {
                                Text(
                                    stringResource(R.string.filters_help_design),
                                    fontSize = 13.sp,
                                )
                            },
                            onClick = {
                                showOverflow = false
                                runCatching {
                                    uriHandler.openUri("https://github.com/tachibana-shin/adfree/blob/main/DESIGN.md")
                                }
                            },
                            leadingIcon = {
                                Icon(Icons.Default.Info, contentDescription = null, tint = AdGuardTextSecondary, modifier = Modifier.size(18.dp))
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
                            text = message.asString(),
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
                                contentDescription = stringResource(R.string.filters_dismiss_banner),
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
                    Text(
                        stringResource(R.string.filters_add),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardTextPrimary,
                    )
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
                        contentDescription = stringResource(R.string.filters_refresh),
                        tint = AdGuardGreenLight,
                        modifier = Modifier.size(16.dp),
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = if (state.loadingMessage == null) {
                            stringResource(R.string.filters_refresh)
                        } else {
                            stringResource(R.string.filters_refreshing)
                        },
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
                placeholder = {
                    Text(
                        stringResource(R.string.filters_search_hint),
                        color = AdGuardTextMuted,
                        fontSize = 13.sp,
                    )
                },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = AdGuardTextMuted, modifier = Modifier.size(18.dp)) },
                trailingIcon = if (query.isBlank()) {
                    null
                } else {
                    {
                        // AdGuard's field carries an explicit clear action; a
                        // long query is otherwise deleted one character at a time.
                        IconButton(
                            onClick = { viewModel.onIntent(AdGuardIntent.FilterSearchQueryChanged("")) },
                            modifier = Modifier.size(32.dp),
                        ) {
                            Icon(
                                Icons.Default.Close,
                                contentDescription = stringResource(R.string.filters_clear_search),
                                tint = AdGuardTextMuted,
                                modifier = Modifier.size(16.dp),
                            )
                        }
                    }
                },
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
                                ModuleGate.ANNOYANCES -> state.settings.isAnnoyancesEnabled
                                ModuleGate.TRACKING -> state.settings.isTrackingProtectionEnabled
                                ModuleGate.BROWSING_SECURITY -> state.settings.isBrowsingSecurityEnabled
                            },
                            onEnableModule = {
                                when (gate) {
                                    ModuleGate.TRACKING -> viewModel.onIntent(AdGuardIntent.ToggleTracking)
                                    ModuleGate.ANNOYANCES -> viewModel.onIntent(AdGuardIntent.ToggleAnnoyances)
                                    ModuleGate.BROWSING_SECURITY ->
                                        viewModel.onIntent(AdGuardIntent.ToggleBrowsingSecurity)
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

                if (query.isNotBlank() && visibleCatalog.isEmpty() && visibleCustom.isEmpty() && visibleDns.isEmpty()) {
                    // The screen used to end at the last group card with no
                    // word about the query, which reads like a loading glitch.
                    item(key = "no_results") {
                        SearchEmptyCard(
                            query = query,
                            onClear = { viewModel.onIntent(AdGuardIntent.FilterSearchQueryChanged("")) },
                        )
                    }
                } else {
                    item(key = "custom_filters") {
                        CustomFiltersCard(
                            lists = visibleCustom,
                            onAdd = { viewModel.onIntent(AdGuardIntent.ShowAddFilterDialog(true)) },
                            onToggleList = { viewModel.onIntent(AdGuardIntent.ToggleFilterList(it.id, !it.isEnabled)) },
                            onOpenList = { viewModel.onIntent(AdGuardIntent.InspectFilter(it.id)) },
                        )
                    }

                    item(key = "dns_filters") {
                        CustomFiltersCard(
                            lists = visibleDns,
                            onAdd = { viewModel.onIntent(AdGuardIntent.ShowAddDnsFilterDialog(true)) },
                            onToggleList = { viewModel.onIntent(AdGuardIntent.ToggleFilterList(it.id, !it.isEnabled)) },
                            onOpenList = { viewModel.onIntent(AdGuardIntent.InspectFilter(it.id)) },
                            titleRes = R.string.filters_dns_title,
                            subtitleRes = R.string.filters_dns_subtitle,
                            emptyRes = R.string.filters_dns_empty,
                            icon = Icons.Default.Language,
                            tag = "dns_filters_section",
                        )
                    }
                }

                item(key = "user_rules") {
                    UserRulesCard(
                        count = userRulesCount,
                        allowCount = allowCount,
                        onOpen = { viewModel.onIntent(AdGuardIntent.ShowCustomRuleEditor(true)) },
                    )
                }

                item(key = "services_table") {
                    val table by viewModel.servicesTableState.collectAsState()
                    ServicesTableCard(
                        url = state.settings.servicesTableUrl,
                        downloadedSize = table?.let { assetSizeLabel(it.sizeBytes) },
                        breakdownOn = state.settings.showServicesBreakdown,
                        onToggleBreakdown = {
                            viewModel.onIntent(AdGuardIntent.SetServicesBreakdown(it))
                        },
                        onSetUrl = { viewModel.onIntent(AdGuardIntent.SetServicesTableUrl(it)) },
                        onRefresh = { viewModel.onIntent(AdGuardIntent.RefreshServicesTable) },
                        onImportFile = { viewModel.onIntent(AdGuardIntent.ImportServicesTable(it)) },
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

    if (state.showAddDnsFilterDialog) {
        AddDnsFilterDialog(
            onDismiss = { viewModel.onIntent(AdGuardIntent.ShowAddDnsFilterDialog(false)) },
            onAdd = { name, url -> viewModel.onIntent(AdGuardIntent.AddDnsFilter(name, url)) },
            onPickFile = {
                pickFileForDns = true
                viewModel.onIntent(AdGuardIntent.ShowAddDnsFilterDialog(false))
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
                    title = {
                        Text(
                            stringResource(R.string.filters_delete_title),
                            fontSize = 17.sp,
                            fontWeight = FontWeight.Bold,
                            color = AdGuardTextPrimary,
                        )
                    },
                    text = {
                        Text(
                            stringResource(R.string.filters_delete_body, filterDisplayName(list)),
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
                            Text(
                                stringResource(R.string.ext_delete),
                                fontSize = 13.sp,
                                fontWeight = FontWeight.Bold,
                                color = AdGuardRedBlocked,
                            )
                        }
                    },
                    dismissButton = {
                        TextButton(onClick = { showDeleteConfirm = false }) {
                            Text(
                                stringResource(R.string.common_cancel),
                                fontSize = 13.sp,
                                color = AdGuardTextSecondary,
                            )
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
            title = {
                Text(
                    stringResource(R.string.filters_reset_title),
                    fontSize = 17.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextPrimary,
                )
            },
            text = {
                Column {
                    // AdGuard lists the scope and the consequences before the
                    // destructive word; here the reset is honestly narrow.
                    Text(
                        stringResource(R.string.filters_reset_scope),
                        fontSize = 12.sp,
                        color = AdGuardTextSecondary,
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        stringResource(R.string.filters_reset_download),
                        fontSize = 12.sp,
                        color = AdGuardTextSecondary,
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        stringResource(R.string.filters_reset_keep),
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
                    Text(
                        stringResource(R.string.filters_reset_confirm),
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardRedBlocked,
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { showResetConfirm = false }) {
                    Text(
                        stringResource(R.string.common_cancel),
                        fontSize = 13.sp,
                        color = AdGuardTextSecondary,
                    )
                }
            },
        )
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
                    Text(
                        stringResource(group.titleRes),
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardTextPrimary,
                    )
                    Text(stringResource(group.subtitleRes), fontSize = 11.sp, color = AdGuardTextMuted)
                    // AdGuard names the configuration state in words rather
                    // than as a bare ratio on the right of the row.
                    Text(
                        stringResource(R.string.filters_group_enabled, enabled, lists.size),
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = if (enabled > 0) AdGuardGreenPrimary else AdGuardTextMuted,
                    )
                }
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
                            stringResource(R.string.filters_inactive_title),
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            color = AdGuardRedBlocked,
                        )
                        Text(
                            stringResource(
                                R.string.filters_inactive_body,
                                stringResource(group.titleRes),
                                gate?.let { stringResource(it.titleRes) }.orEmpty(),
                            ),
                            fontSize = 11.sp,
                            color = AdGuardTextMuted,
                        )
                    }
                    TextButton(onClick = onEnableModule) {
                        Text(
                            stringResource(R.string.filters_enable_module),
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            color = AdGuardGreenLight,
                        )
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

/** Catalogue rows carry a resource id; user-added lists keep their own text. */
@Composable
private fun filterDisplayName(list: FilterList): String =
    if (list.nameRes != 0) stringResource(list.nameRes) else list.name

@Composable
private fun filterDisplayDescription(list: FilterList): String =
    if (list.descriptionRes != 0) stringResource(list.descriptionRes) else list.description

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
                text = filterDisplayName(list),
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold,
                color = AdGuardTextPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = stringResource(
                    R.string.filters_row_meta,
                    "%,d".format(list.ruleCount),
                    list.lastUpdatedText.ifBlank { stringResource(R.string.filter_not_updated) },
                ),
                fontSize = 11.sp,
                color = AdGuardTextMuted,
            )
            // AdGuard rows carry "Version: … / Updated: …"; we only show a
            // version once the list's own metadata provided one (empty
            // before the first download, no more faked "standard").
            if (list.version.isNotBlank()) {
                Text(
                    text = stringResource(R.string.filters_row_version, list.version),
                    fontSize = 11.sp,
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
                    text = stringResource(R.string.filters_row_error, list.lastError),
                    fontSize = 11.sp,
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

/** Shown when the query matches no catalogue or custom list. */
@Composable
private fun SearchEmptyCard(
    query: String,
    onClear: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("filter_search_empty"),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        border = BorderStroke(1.dp, AdGuardDarkOutline),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = stringResource(R.string.filters_search_empty_title),
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextPrimary,
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = stringResource(R.string.filters_search_empty_body, query),
                fontSize = 11.sp,
                color = AdGuardTextMuted,
            )
            TextButton(
                onClick = onClear,
                modifier = Modifier.padding(top = 4.dp),
            ) {
                Text(
                    stringResource(R.string.filters_clear_search),
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardGreenLight,
                )
            }
        }
    }
}

@Composable
private fun CustomFiltersCard(
    lists: List<FilterList>,
    onAdd: () -> Unit,
    onToggleList: (FilterList) -> Unit,
    onOpenList: (FilterList) -> Unit,
    titleRes: Int = R.string.filters_custom_title,
    subtitleRes: Int = R.string.filters_custom_subtitle,
    emptyRes: Int = R.string.filters_custom_empty,
    icon: ImageVector = Icons.Default.Public,
    tag: String = "custom_filters_section",
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(tag),
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
                    Icon(icon, contentDescription = null, tint = AdGuardBlueDns, modifier = Modifier.size(20.dp))
                }
                Spacer(modifier = Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        stringResource(titleRes),
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardTextPrimary,
                    )
                    Text(
                        stringResource(subtitleRes),
                        fontSize = 11.sp,
                        color = AdGuardTextMuted,
                    )
                }
            }

            if (lists.isEmpty()) {
                Text(
                    text = stringResource(emptyRes),
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
                Text(
                    stringResource(R.string.filters_add),
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardBlueDns,
                )
            }
        }
    }
}

@Composable
private fun UserRulesCard(
    count: Int,
    allowCount: Int,
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
                Text(
                    stringResource(R.string.filters_user_rules_title),
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextPrimary,
                )
                Text(
                    stringResource(R.string.filters_user_rules_meta, count, allowCount),
                    fontSize = 11.sp,
                    color = AdGuardTextMuted,
                )
            }
            Icon(Icons.Default.ChevronRight, contentDescription = null, tint = AdGuardTextMuted, modifier = Modifier.size(20.dp))
        }
    }
}

/**
 * The domain-to-company table behind the Statistics breakdown. The switch
 * stays off by default: the group-by is a whole-window query and the labels
 * cost a disk read. A subscription is optional — with the URL empty the table
 * this build ships is used and nothing is downloaded. A file can be imported
 * instead, which is how a dataset published as a directory (DuckDuckGo's radar)
 * reaches the app.
 */
@Composable
private fun ServicesTableCard(
    url: String,
    downloadedSize: String?,
    breakdownOn: Boolean,
    onToggleBreakdown: (Boolean) -> Unit,
    onSetUrl: (String) -> Unit,
    onRefresh: () -> Unit,
    onImportFile: (String) -> Unit,
) {
    var draft by remember(url) { mutableStateOf(url) }
    val draftUrl = draft.trim()
    val draftError = if (draftUrl.isEmpty()) null else filterUrlError(draftUrl)
    // The picker serves the merged-file case only: the core converts whatever
    // body it is handed, so a JSON dataset and a plain table both arrive here.
    val tablePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) onImportFile(uri.toString())
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("services_table_card"),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        border = BorderStroke(1.dp, AdGuardDarkOutline),
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(38.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(AdGuardBlueDns.copy(alpha = 0.12f)),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        Icons.Default.Language,
                        contentDescription = null,
                        tint = AdGuardBlueDns,
                        modifier = Modifier.size(20.dp),
                    )
                }
                Spacer(modifier = Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        stringResource(R.string.services_table_title),
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardTextPrimary,
                    )
                    Text(
                        stringResource(R.string.services_table_subtitle),
                        fontSize = 11.sp,
                        color = AdGuardTextMuted,
                    )
                }
                Switch(
                    checked = breakdownOn,
                    onCheckedChange = onToggleBreakdown,
                    modifier = Modifier.testTag("services_breakdown_switch"),
                    colors = SwitchDefaults.colors(checkedTrackColor = AdGuardGreenPrimary),
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            OutlinedTextField(
                value = draft,
                onValueChange = { draft = it },
                label = { Text(stringResource(R.string.services_table_url_label), fontSize = 12.sp) },
                placeholder = { Text("https://…", fontSize = 12.sp, color = AdGuardTextMuted) },
                singleLine = true,
                isError = draftError != null,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("services_table_url_field"),
                shape = RoundedCornerShape(10.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = AdGuardGreenPrimary,
                    unfocusedBorderColor = AdGuardDarkOutline,
                    focusedTextColor = AdGuardTextPrimary,
                    unfocusedTextColor = AdGuardTextPrimary,
                ),
            )
            draftError?.let { error ->
                Text(
                    text = CoreText.filterUrlError(error).asString(),
                    fontSize = 11.sp,
                    color = AdGuardRedBlocked,
                    modifier = Modifier.padding(start = 6.dp, top = 4.dp),
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (url.isNotBlank()) {
                    TextButton(
                        onClick = { onSetUrl("") },
                        modifier = Modifier.testTag("services_table_reset"),
                    ) {
                        Text(
                            stringResource(R.string.services_table_reset),
                            fontSize = 12.sp,
                            color = AdGuardTextMuted,
                        )
                    }
                }
                // Import is not tied to a subscription: a dataset published as a
                // directory arrives as a file, whether or not a URL is set.
                TextButton(
                    onClick = { tablePicker.launch(arrayOf("application/json", "text/plain", "text/*", "*/*")) },
                    modifier = Modifier.testTag("services_table_import"),
                ) {
                    Icon(
                        Icons.Default.UploadFile,
                        contentDescription = null,
                        tint = AdGuardBlueDns,
                        modifier = Modifier.size(16.dp),
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        stringResource(R.string.services_table_import),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardBlueDns,
                    )
                }
                if (url.isNotBlank()) {
                    TextButton(
                        onClick = onRefresh,
                        modifier = Modifier.testTag("services_table_refresh"),
                    ) {
                        Icon(
                            Icons.Default.Refresh,
                            contentDescription = null,
                            tint = AdGuardBlueDns,
                            modifier = Modifier.size(16.dp),
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            stringResource(R.string.filters_refresh),
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            color = AdGuardBlueDns,
                        )
                    }
                }
                Button(
                    onClick = { onSetUrl(draftUrl) },
                    enabled = draftError == null && draftUrl != url,
                    modifier = Modifier.testTag("services_table_save"),
                    colors = ButtonDefaults.buttonColors(containerColor = AdGuardGreenPrimary),
                    contentPadding = PaddingValues(horizontal = 14.dp, vertical = 6.dp),
                ) {
                    Text(
                        stringResource(R.string.filters_save),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                    )
                }
            }

            Text(
                text = downloadedSize?.let {
                    stringResource(R.string.services_table_downloaded, it)
                } ?: stringResource(R.string.services_table_shipped),
                fontSize = 11.sp,
                color = AdGuardTextMuted,
            )
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
                Text(
                    stringResource(R.string.filters_add_title),
                    fontSize = 17.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextPrimary,
                )
            }
        },
        text = {
            Column {
                Text(
                    text = stringResource(R.string.filters_add_body),
                    fontSize = 12.sp,
                    color = AdGuardTextSecondary,
                )

                Spacer(modifier = Modifier.height(12.dp))

                Text(
                    stringResource(R.string.filters_add_suggestions),
                    fontSize = 11.sp,
                    color = AdGuardTextMuted,
                )
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
                    label = { Text(stringResource(R.string.filters_url_label), fontSize = 12.sp) },
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
                    Text(
                        CoreText.filterUrlError(error).asString(),
                        fontSize = 11.sp,
                        color = AdGuardRedBlocked,
                    )
                }

                Spacer(modifier = Modifier.height(4.dp))

                TextButton(onClick = onPickFile) {
                    Icon(Icons.Default.UploadFile, contentDescription = null, tint = AdGuardGreenLight, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        stringResource(R.string.filters_pick_file),
                        fontSize = 12.sp,
                        color = AdGuardGreenLight,
                    )
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
                Text(
                    stringResource(R.string.common_add),
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

/**
 * Adds a DNS filter subscription: a name and a source URL. Its rules are
 * matched against resolved names only, so nothing else about it mirrors the
 * web-filter dialog (no file import, no syntax examples).
 */
@Composable
private fun AddDnsFilterDialog(
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
                Icon(Icons.Default.Language, contentDescription = null, tint = AdGuardBlueDns, modifier = Modifier.size(22.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    stringResource(R.string.filters_dns_add_title),
                    fontSize = 17.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextPrimary,
                )
            }
        },
        text = {
            Column {
                Text(
                    text = stringResource(R.string.filters_dns_add_body),
                    fontSize = 12.sp,
                    color = AdGuardTextSecondary,
                )

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
                    label = { Text(stringResource(R.string.filters_url_label), fontSize = 12.sp) },
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

                filterUrlError(url)?.let { error ->
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        CoreText.filterUrlError(error).asString(),
                        fontSize = 11.sp,
                        color = AdGuardRedBlocked,
                    )
                }

                Spacer(modifier = Modifier.height(4.dp))

                TextButton(onClick = onPickFile) {
                    Icon(Icons.Default.UploadFile, contentDescription = null, tint = AdGuardGreenLight, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        stringResource(R.string.filters_pick_file),
                        fontSize = 12.sp,
                        color = AdGuardGreenLight,
                    )
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
                Text(
                    stringResource(R.string.common_add),
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
        title = {
            Text(
                stringResource(R.string.filters_edit_title),
                fontSize = 17.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextPrimary,
            )
        },
        text = {
            Column {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text(stringResource(R.string.filters_name_label), fontSize = 12.sp) },
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
                    label = { Text(stringResource(R.string.filters_url_label), fontSize = 12.sp) },
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
                    Text(
                        CoreText.filterUrlError(it).asString(),
                        fontSize = 11.sp,
                        color = AdGuardRedBlocked,
                    )
                }
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    stringResource(R.string.filters_edit_reload),
                    fontSize = 11.sp,
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
                Text(
                    stringResource(R.string.filters_save),
                    color = AdGuardOnAccent,
                    fontWeight = FontWeight.Bold,
                )
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(
                    stringResource(R.string.common_cancel),
                    fontSize = 13.sp,
                    color = AdGuardTextSecondary,
                )
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
    val displayName = filterDisplayName(list)
    val displayDescription = filterDisplayDescription(list)
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp, vertical = 12.dp),
    ) {
        Text(displayName, fontSize = 16.sp, fontWeight = FontWeight.Black, color = AdGuardTextPrimary)
        if (displayDescription.isNotBlank()) {
            Spacer(modifier = Modifier.height(4.dp))
            Text(displayDescription, fontSize = 12.sp, color = AdGuardTextSecondary)
        }

        Spacer(modifier = Modifier.height(10.dp))
        val features = buildList {
            add(
                if (list.format.equals("hosts", ignoreCase = true)) {
                    R.string.filters_feature_hosts
                } else {
                    R.string.filters_feature_rule_syntax
                },
            )
            add(
                if (!list.subscriptionUrl.isNullOrBlank()) {
                    R.string.filters_feature_auto_update
                } else {
                    R.string.filters_feature_static
                },
            )
            if (list.isUserAdded) {
                add(
                    if (list.trusted) R.string.filters_feature_trusted
                    else R.string.filters_feature_untrusted,
                )
            }
        }
        features.forEach { feature ->
            Row(
                modifier = Modifier.padding(vertical = 2.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(
                    Icons.Default.CheckCircle,
                    contentDescription = null,
                    tint = AdGuardGreenLight,
                    modifier = Modifier.size(13.dp),
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(stringResource(feature), fontSize = 11.sp, color = AdGuardTextSecondary)
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    stringResource(R.string.filters_detail_enable_title),
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextPrimary,
                )
                Text(
                    text = when {
                        // The switch follows the engine, so an in-flight compile
                        // has to be said out loud or the user wonders why a
                        // freshly enabled list is not filtering yet.
                        isBuilding -> stringResource(R.string.filters_detail_building)
                        list.isEnabled -> stringResource(R.string.home_status_filtering)
                        else -> stringResource(R.string.ext_detail_off)
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
                    Text(
                        stringResource(R.string.filters_trusted_title),
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardTextPrimary,
                    )
                    Text(
                        text = stringResource(R.string.filters_trusted_body),
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

        InfoRow(
            stringResource(R.string.filters_info_group),
            FilterGroup.fromId(list.groupId)?.let { stringResource(it.titleRes) }
                ?: stringResource(R.string.filters_info_custom_group),
        )
        InfoRow(
            stringResource(R.string.filters_info_format),
            if (list.format.equals("hosts", ignoreCase = true)) "Hosts" else "AdGuard / EasyList",
        )
        InfoRow(stringResource(R.string.filters_info_rules), "%,d".format(list.ruleCount))
        if (list.sizeBytes > 0L) {
            InfoRow(stringResource(R.string.filters_info_size), assetSizeLabel(list.sizeBytes))
        }
        InfoRow(
            stringResource(R.string.ext_detail_updated),
            list.lastUpdatedText.ifBlank { stringResource(R.string.filter_not_updated) },
        )
        if (list.version.isNotBlank()) {
            InfoRow(stringResource(R.string.ext_detail_version), list.version.take(24))
        }
        if (list.lastError.isNotBlank()) {
            InfoRow(
                stringResource(R.string.filters_info_error),
                list.lastError.take(160),
                AdGuardRedBlocked,
            )
        }

        val subscriptionUrl = list.subscriptionUrl
        if (!subscriptionUrl.isNullOrBlank()) {
            val url = subscriptionUrl
            Spacer(modifier = Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = url,
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = AdGuardTextMuted,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                IconButton(
                    onClick = {
                        clipboard.setText(AnnotatedString(url))
                        Toast.makeText(
                            context,
                            context.getString(R.string.filters_copy_url),
                            Toast.LENGTH_SHORT,
                        ).show()
                    },
                    modifier = Modifier.size(32.dp),
                ) {
                    Icon(
                        Icons.Default.ContentCopy,
                        contentDescription = stringResource(R.string.filters_copy_source),
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
                        contentDescription = stringResource(R.string.filters_open_source),
                        tint = AdGuardTextSecondary,
                        modifier = Modifier.size(16.dp),
                    )
                }
            }
        } else if (list.ruleCount > 0) {
            Spacer(modifier = Modifier.height(8.dp))
            InfoRow(
                stringResource(R.string.filters_info_source),
                stringResource(R.string.filters_source_local),
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (!list.subscriptionUrl.isNullOrBlank()) {
                OutlinedButton(onClick = onRefresh, shape = RoundedCornerShape(10.dp)) {
                    Icon(Icons.Default.Sync, contentDescription = null, tint = AdGuardGreenLight, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(stringResource(R.string.ext_update), fontSize = 12.sp, color = AdGuardGreenLight)
                }
            }
            if (list.isUserAdded) {
                OutlinedButton(onClick = onEdit, shape = RoundedCornerShape(10.dp)) {
                    Icon(Icons.Default.Edit, contentDescription = null, tint = AdGuardGreenLight, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(stringResource(R.string.filters_edit), fontSize = 12.sp, color = AdGuardGreenLight)
                }
                OutlinedButton(onClick = onDelete, shape = RoundedCornerShape(10.dp)) {
                    Icon(Icons.Default.Delete, contentDescription = null, tint = AdGuardRedBlocked, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(stringResource(R.string.ext_delete), fontSize = 12.sp, color = AdGuardRedBlocked)
                }
            }
            val homepage = list.homepage
            if (!homepage.isNullOrBlank()) {
                OutlinedButton(onClick = { onOpenHomepage(homepage) }, shape = RoundedCornerShape(10.dp)) {
                    Icon(Icons.Default.Public, contentDescription = null, tint = AdGuardBlueDns, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(stringResource(R.string.filters_homepage), fontSize = 12.sp, color = AdGuardBlueDns)
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
