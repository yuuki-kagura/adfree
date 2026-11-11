package git.shin.adfree.ui.screens

import git.shin.adfree.l10n.Strings
import git.shin.adfree.l10n.L10n
import git.shin.adfree.platform.currentFileHost
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.ui.draw.scale
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.FileUpload
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.data.AdGuardRepository
import git.shin.adfree.model.FilterList
import git.shin.adfree.model.FilterStatus
import git.shin.adfree.model.LogRuleSwitch
import git.shin.adfree.model.LogTypeTab
import git.shin.adfree.model.NetworkRequestLog
import git.shin.adfree.model.NetworkTransport
import git.shin.adfree.model.assetSizeLabel
import git.shin.adfree.model.logDurationLabel
import git.shin.adfree.model.logRuleSwitches
import git.shin.adfree.model.logUrlOpenable
import git.shin.adfree.model.requestTypeLabel
import git.shin.adfree.model.ProtocolType
import git.shin.adfree.model.RequestCategory
import git.shin.adfree.model.RuleDraft
import git.shin.adfree.model.RuleDraftKind
import git.shin.adfree.model.appScopeSupported
import git.shin.adfree.platform.currentPlatformHost
import git.shin.adfree.ui.AdGuardIntent
import git.shin.adfree.ui.AdGuardUiState
import git.shin.adfree.ui.AdGuardTab
import git.shin.adfree.ui.AdGuardViewModel
import git.shin.adfree.ui.rememberAppIcon
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
import git.shin.adfree.ui.theme.AdGuardOnAccent
import git.shin.adfree.ui.theme.AdGuardTextSecondary
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The label to show for a log row's package: the installed app's name when
 * the package is still installed, the raw package otherwise.
 */
private fun appLabelFor(appNames: Map<String, String>, packageName: String?): String? =
    packageName?.let { pkg -> appNames[pkg] ?: pkg }

/** One screen of filtered cards; past that the scroll trigger takes over. */
private const val MIN_FILTERED_ROWS = 15

// The log table's column widths, shared by the header and the rows so the two
// can never drift apart. AdGuard's own order — Name, Rule, Filter, Type,
// Source, Process — with the time first: this log is the durable seven-day one,
// not AdGuard's session-only list, so which moment a row is from is information
// the user needs here rather than in a detail pane.
private const val COL_TIME = 1.1f
private const val COL_NAME = 3.8f
private const val COL_RULE = 2.6f
private const val COL_FILTER = 1.6f
private const val COL_TYPE = 1.2f
private const val COL_SOURCE = 2.0f
private const val COL_PROCESS = 1.8f
private const val COL_STATUS = 1.1f

// AdGuard's log is a table with the selected request's details docked beside
// it. Two widths decide the surface: the table needs one to be a table at all,
// and the pane needs a little more so the table beside it keeps its columns.
// The sheet that stands in for the pane is gated on the same numbers — get the
// two to disagree and a window of the awkward size shows both surfaces, or
// neither.
private val TABLE_MIN_WIDTH = 720.dp
private val SIDE_PANE_MIN_WIDTH = 880.dp
private val DETAIL_PANE_WIDTH = 360.dp
private val SCREEN_PADDING_HORIZONTAL = 16.dp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FilteringLogScreen(
    viewModel: AdGuardViewModel,
    modifier: Modifier = Modifier,
    /**
     * The AdGuard-for-Windows shape: request-type tabs across the top and a
     * table of columns once the pane is wide enough.
     *
     * Off by default, because the Activity tab is the app's own screen and
     * keeps the card list it has always had. The desktop's separate Filtering
     * log window turns it on: that window exists to be the AdGuard-style log,
     * and it is a popup beside the tabbed UI rather than a replacement for it.
     */
    adGuardLayout: Boolean = false,
) {
    val state by viewModel.uiState.collectAsState()
    val listState = rememberLazyListState()
    var showClearConfirm by remember { mutableStateOf(false) }
    val files = currentFileHost()
    val exportScope = rememberCoroutineScope()
    // Set while the screen shows a file the user opened instead of the store.
    val importedName = state.importedLogName

    // The selected row's details: a pane docked under the table once the window
    // is wide enough, and the sheet this screen always used when it is not. The
    // rule editor opens inside whichever of the two the user is looking at, so
    // the draft lives beside the selection rather than in either surface.
    val inspected = state.inspectedLog
    var ruleDraft by remember(inspected) { mutableStateOf<RuleDraft?>(null) }

    // While the list sits at its top it follows incoming rows; scrolling into
    // history tells the repository to freeze the window instead, or fresh rows
    // would keep pushing the rows under the user's finger.
    LaunchedEffect(listState) {
        snapshotFlow { listState.firstVisibleItemIndex == 0 }
            .distinctUntilChanged()
            .collect { viewModel.onIntent(AdGuardIntent.SetLogTailing(it)) }
    }

    // Infinite scroll: when the last rows come into view, ask for one more
    // page. Keyed on the loaded size so a page that still cannot fill the
    // viewport asks again instead of stalling.
    LaunchedEffect(listState, state.logs.size) {
        snapshotFlow {
            val info = listState.layoutInfo
            val last = info.visibleItemsInfo.lastOrNull()?.index ?: -1
            last >= info.totalItemsCount - 4
        }
            .distinctUntilChanged()
            .collect { nearEnd -> if (nearEnd) viewModel.onIntent(AdGuardIntent.LoadMoreLogs) }
    }

    // Status and search filtering run over the mirrored window, so a query
    // whose matches are rarer than a page would leave too few rows to scroll
    // (or none at all). Pull older pages until the matches fill a few screens.
    val filterActive = state.statusFilter != null ||
        state.logTypeFilter != LogTypeTab.ALL ||
        state.selectedAppFilter != null || state.searchQuery.isNotBlank()
    LaunchedEffect(filterActive, state.filteredLogs.size, state.logs.size, state.logTotal) {
        if (filterActive && state.filteredLogs.size < MIN_FILTERED_ROWS &&
            state.logs.size < state.logTotal
        ) {
            viewModel.onIntent(AdGuardIntent.LoadMoreLogs)
        }
    }

    if (showClearConfirm) {
        AlertDialog(
            onDismissRequest = { showClearConfirm = false },
            containerColor = AdGuardDarkSurface,
            titleContentColor = AdGuardTextPrimary,
            textContentColor = AdGuardTextSecondary,
            title = { Text(L10n.get(Strings.log_clear_title)) },
            text = {
                Text(
                    L10n.format(Strings.log_clear_body, state.logTotal),
                    fontSize = 13.sp,
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    showClearConfirm = false
                    viewModel.onIntent(AdGuardIntent.ClearLogs)
                }) {
                    Text(L10n.get(Strings.log_clear_confirm), fontSize = 13.sp, fontWeight = FontWeight.Bold, color = AdGuardRedBlocked)
                }
            },
            dismissButton = {
                TextButton(onClick = { showClearConfirm = false }) {
                    Text(L10n.get(Strings.common_cancel), fontSize = 13.sp, color = AdGuardTextSecondary)
                }
            },
        )
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(AdGuardDarkBg)
            // A desktop window is measured in rows read, not in thumb-sized
            // gaps: the AdGuard-shaped surface keeps the density its own log
            // has, and the card surface keeps the padding the phone screen
            // wants.
            .padding(
                horizontal = if (adGuardLayout) 10.dp else SCREEN_PADDING_HORIZONTAL,
                vertical = if (adGuardLayout) 8.dp else 12.dp,
            )
    ) {
        // One toolbar, the way AdGuard for Windows has one: the search field
        // and the row's own actions on the left, the filters floated to the
        // right. The title, the retention note and the three chip rows this
        // screen used to stack are gone — a window that exists to be read has
        // no room for a paragraph above the list, and every row of chrome that
        // is not a control costs a row of requests.
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            // A plain text field, not an OutlinedTextField: the Material one
            // is 56dp tall before it holds a single character, which next to
            // 20dp switches reads as a search box from a different program.
            BasicTextField(
                value = state.searchQuery,
                onValueChange = { viewModel.onIntent(AdGuardIntent.SearchQueryChanged(it)) },
                singleLine = true,
                textStyle = TextStyle(fontSize = 12.sp, color = AdGuardTextPrimary),
                cursorBrush = SolidColor(AdGuardGreenPrimary),
                modifier = Modifier
                    .weight(1f)
                    .testTag("log_search_input"),
                decorationBox = { inner ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .clip(RoundedCornerShape(8.dp))
                            .background(AdGuardDarkSurface)
                            .border(1.dp, AdGuardDarkOutline, RoundedCornerShape(8.dp))
                            .padding(horizontal = 8.dp, vertical = 5.dp),
                    ) {
                        Icon(
                            Icons.Default.Search,
                            contentDescription = null,
                            tint = AdGuardTextMuted,
                            modifier = Modifier.size(15.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Box(modifier = Modifier.weight(1f)) {
                            if (state.searchQuery.isEmpty()) {
                                Text(
                                    text = L10n.get(Strings.log_search_hint),
                                    fontSize = 12.sp,
                                    color = AdGuardTextMuted,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                            inner()
                        }
                        if (state.searchQuery.isNotEmpty()) {
                            Icon(
                                imageVector = Icons.Default.Clear,
                                contentDescription = L10n.get(Strings.common_clear_search),
                                tint = AdGuardTextMuted,
                                modifier = Modifier
                                    .size(15.dp)
                                    .clip(RoundedCornerShape(4.dp))
                                    .clickable {
                                        viewModel.onIntent(AdGuardIntent.SearchQueryChanged(""))
                                    },
                            )
                        }
                    }
                },
            )

            if (importedName != null) {
                // Reading somebody else's file: the only action that means
                // anything here is going back.
                IconButton(
                    onClick = { viewModel.onIntent(AdGuardIntent.CloseImportedLogs) },
                    modifier = Modifier.size(34.dp).testTag("close_imported_logs_button")
                ) {
                    Icon(
                        Icons.Default.Close,
                        contentDescription = L10n.get(Strings.log_import_close),
                        tint = AdGuardTextSecondary,
                        modifier = Modifier.size(18.dp)
                    )
                }
            } else {
                IconButton(
                    onClick = {
                        exportScope.launch {
                            files.openText()?.let { viewModel.onIntent(AdGuardIntent.ImportLogs(it)) }
                        }
                    },
                    modifier = Modifier.size(34.dp).testTag("import_logs_button")
                ) {
                    Icon(
                        Icons.Default.FileUpload,
                        contentDescription = L10n.get(Strings.log_import_action),
                        tint = AdGuardTextSecondary,
                        modifier = Modifier.size(18.dp)
                    )
                }

                IconButton(
                    onClick = {
                        exportScope.launch {
                            files.createDocument("adfree-activity.csv", "text/csv")?.let {
                                viewModel.onIntent(AdGuardIntent.ExportLogs(it))
                            }
                        }
                    },
                    modifier = Modifier.size(34.dp).testTag("export_logs_button")
                ) {
                    Icon(
                        Icons.Default.FileDownload,
                        contentDescription = L10n.get(Strings.log_export_action),
                        tint = AdGuardTextSecondary,
                        modifier = Modifier.size(18.dp)
                    )
                }

                IconButton(
                    onClick = { showClearConfirm = true },
                    modifier = Modifier.size(34.dp).testTag("clear_logs_button")
                ) {
                    Icon(
                        Icons.Default.DeleteSweep,
                        contentDescription = L10n.get(Strings.log_clear_action),
                        tint = AdGuardTextSecondary,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }

            if (adGuardLayout) {
                // The status filter, floated right as three switches rather
                // than a chip row: the same three answers in the space of one
                // line, which is what AdGuard's own log does with its toolbar.
                LogStatusSwitches(state) { status ->
                    viewModel.onIntent(AdGuardIntent.FilterStatusChanged(status))
                }
            }
        }

        if (!adGuardLayout) {
            // A phone has no room to float the three beside the title, but it
            // has the same question to ask of the same list: "what was
            // blocked". They take a line of their own and scroll, so a narrow
            // screen gets the filters instead of a longer scroll.
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                LogStatusSwitches(state) { status ->
                    viewModel.onIntent(AdGuardIntent.FilterStatusChanged(status))
                }
            }
            Spacer(modifier = Modifier.height(6.dp))
        }

        // The type row is a filter, not a tablet affordance: it scrolls, so a
        // phone reads the same eleven types the window does. Only the table and
        // the docked pane are shapes a phone cannot hold.
        LogTypeRow(
            selected = state.logTypeFilter,
            onSelect = { viewModel.onIntent(AdGuardIntent.FilterLogTypeChanged(it)) },
        )

        if (importedName != null) {
            // Says plainly that what follows is a file, not this machine's
            // traffic — the same rows, the same columns, and nothing to do
            // with what the filter is deciding right now. It sits under the
            // toolbar because it is a state of the whole list, not an action.
            Text(
                text = L10n.format(Strings.log_imported_viewing, state.logTotal, importedName),
                fontSize = 12.sp,
                color = AdGuardTextSecondary,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .background(AdGuardDarkSurfaceVariant)
                    .padding(horizontal = 10.dp, vertical = 6.dp)
                    .testTag("log_imported_banner")
            )
            Spacer(modifier = Modifier.height(8.dp))
        }

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
                            text = L10n.format(Strings.log_filter_by_app, appDisplayName),
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
                            contentDescription = L10n.get(Strings.log_filter_by_app_clear),
                            tint = AdGuardTextMuted,
                            modifier = Modifier.size(16.dp)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(10.dp))
        }

        // Logs List
        BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
            // AdGuard's log is a table. Its columns only fit once the window is
            // a window, so the AdGuard-shaped surface gets the table and a
            // phone keeps the cards it already reads well. The Activity tab is
            // not that surface: it keeps its cards at every width.
            val asTable = adGuardLayout && maxWidth >= TABLE_MIN_WIDTH
            // The selected request's details dock beside the table, which is
            // the shape AdGuard for Windows uses and the only one that leaves
            // both halves usable: under the table the pane fights the rows for
            // height, and at the window sizes this log opens in it lost, so the
            // details arrived as a sliver that had to be scrolled inside the
            // very thing it was covering.
            val asPane = asTable && inspected != null && maxWidth >= SIDE_PANE_MIN_WIDTH
            Row(modifier = Modifier.fillMaxSize()) {
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxHeight(),
                ) {
                    Box(modifier = Modifier.weight(1f)) {
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
                                    // "No traffic yet" is wrong when rows exist but the query
                                    // filters them all out; say which case this is.
                                    Text(
                                        text = L10n.get(if (filterActive) Strings.log_empty_filtered_title
                                            else Strings.log_empty_title
                                        ),
                                        fontSize = 15.sp,
                                        fontWeight = FontWeight.SemiBold,
                                        color = AdGuardTextSecondary
                                    )
                                    Text(
                                        text = L10n.get(if (filterActive) Strings.log_empty_filtered_body
                                            else Strings.log_empty_body
                                        ),
                                        fontSize = 12.sp,
                                        color = AdGuardTextMuted
                                    )
                                }
                            }
                        } else {
                            LazyColumn(
                                state = listState,
                                modifier = Modifier.fillMaxSize(),
                                verticalArrangement = Arrangement.spacedBy(if (asTable) 0.dp else 8.dp)
                            ) {
                                if (asTable) {
                                    // The header is a row of the list: it scrolls with the
                                    // rows it names, exactly as AdGuard's does, and it keeps
                                    // its place when the last row is pulled in.
                                    item(key = "log_table_header") { LogTableHeader() }
                                }
                                items(state.filteredLogs, key = { it.id }) { log ->
                                    if (asTable) {
                                        LogTableRow(
                                            log = log,
                                            appLabel = appLabelFor(state.appNames, log.appPackage),
                                            onClick = { viewModel.onIntent(AdGuardIntent.InspectLog(log)) }
                                        )
                                    } else {
                                        LogItemCard(
                                            log = log,
                                            appLabel = appLabelFor(state.appNames, log.appPackage),
                                            onClick = { viewModel.onIntent(AdGuardIntent.InspectLog(log)) }
                                        )
                                    }
                                }

                                // The screen mirrors a window of the database log; the scroll
                                // trigger above grows it, so the tail is a quiet hint. Once
                                // the in-RAM cap is hit, say so instead of spinning forever.
                                if (state.logs.size < state.logTotal) {
                                    item(key = "log_infinite_footer") {
                                        Column(
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .padding(vertical = 10.dp)
                                                .testTag("log_infinite_footer"),
                                            horizontalAlignment = Alignment.CenterHorizontally
                                        ) {
                                            if (state.logs.size >= AdGuardRepository.LOG_ROW_CAP) {
                                                Text(
                                                    text = L10n.format(Strings.log_window_capped,
                                                        state.logs.size,
                                                        state.logTotal,
                                                    ),
                                                    fontSize = 11.sp,
                                                    color = AdGuardTextMuted
                                                )
                                            } else {
                                                CircularProgressIndicator(
                                                    modifier = Modifier.size(18.dp),
                                                    color = AdGuardGreenPrimary,
                                                    strokeWidth = 2.dp
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if (asPane) {
                    Box(
                        modifier = Modifier
                            .fillMaxHeight()
                            .padding(start = 12.dp)
                            .width(DETAIL_PANE_WIDTH)
                            .clip(RoundedCornerShape(12.dp))
                            .background(AdGuardDarkSurface)
                            .border(1.dp, AdGuardDarkOutline, RoundedCornerShape(12.dp))
                            .testTag("log_detail_pane"),
                    ) {
                        LogDetailBody(
                            log = inspected,
                            appNames = state.appNames,
                            filterLists = state.filterLists,
                            ruleDraft = ruleDraft,
                            onOpenRuleEditor = { draft -> ruleDraft = draft },
                            onCloseRuleEditor = { ruleDraft = null },
                            onSubmitRule = { rule ->
                                viewModel.onIntent(AdGuardIntent.AddCustomRule(rule))
                                viewModel.onIntent(AdGuardIntent.InspectLog(null))
                            },
                            onSwitchRule = { rule, enabled ->
                                viewModel.onIntent(AdGuardIntent.SwitchLogRule(rule, enabled))
                            },
                            onAnalyzeWithAi = { domain ->
                                viewModel.onIntent(AdGuardIntent.InspectLog(null))
                                viewModel.onIntent(AdGuardIntent.SelectTab(AdGuardTab.AI_LAB))
                                viewModel.onIntent(AdGuardIntent.RunThreatScan(domain))
                            },
                            onClose = { viewModel.onIntent(AdGuardIntent.InspectLog(null)) },
                        )
                    }
                }
            }
        }
    }

    // A narrow window has no room to dock the pane, so the same detail body
    // arrives as the sheet this screen always used. The gate is the pane's own
    // width, measured the same way the pane measures it: get the two to
    // disagree by a pixel and a window shows a sheet over a pane, or a row that
    // answers a click with nothing at all.
    if (inspected != null) {
        BoxWithConstraints {
            val asTable = adGuardLayout && maxWidth >= TABLE_MIN_WIDTH
            val asPane = asTable && maxWidth >= SIDE_PANE_MIN_WIDTH
            if (!asPane) {
                val sheetState = rememberModalBottomSheetState()
                ModalBottomSheet(
                    onDismissRequest = {
                        if (ruleDraft != null) ruleDraft = null
                        else viewModel.onIntent(AdGuardIntent.InspectLog(null))
                    },
                    sheetState = sheetState,
                    containerColor = AdGuardDarkSurface,
                    contentColor = AdGuardTextPrimary,
                ) {
                    LogDetailBody(
                        log = inspected,
                        appNames = state.appNames,
                        filterLists = state.filterLists,
                        ruleDraft = ruleDraft,
                        onOpenRuleEditor = { draft -> ruleDraft = draft },
                        onCloseRuleEditor = { ruleDraft = null },
                        onSubmitRule = { rule ->
                            viewModel.onIntent(AdGuardIntent.AddCustomRule(rule))
                            viewModel.onIntent(AdGuardIntent.InspectLog(null))
                        },
                        onSwitchRule = { rule, enabled ->
                            viewModel.onIntent(AdGuardIntent.SwitchLogRule(rule, enabled))
                        },
                        onAnalyzeWithAi = { domain ->
                            viewModel.onIntent(AdGuardIntent.InspectLog(null))
                            viewModel.onIntent(AdGuardIntent.SelectTab(AdGuardTab.AI_LAB))
                            viewModel.onIntent(AdGuardIntent.RunThreatScan(domain))
                        },
                        onClose = { viewModel.onIntent(AdGuardIntent.InspectLog(null)) },
                    )
                }
            }
        }
    }
}

@Composable
private fun logStatusLabel(status: FilterStatus): String = when (status) {
    FilterStatus.BLOCKED -> L10n.get(Strings.log_status_blocked)
    FilterStatus.ALLOWED -> L10n.get(Strings.log_status_allowed)
    FilterStatus.WHITELISTED -> L10n.get(Strings.log_status_whitelisted)
}

@Composable
private fun logActionLabel(status: FilterStatus): String = when (status) {
    FilterStatus.BLOCKED -> L10n.get(Strings.log_action_blocked)
    FilterStatus.ALLOWED -> L10n.get(Strings.log_action_allowed)
    FilterStatus.WHITELISTED -> L10n.get(Strings.log_action_whitelisted)
}

@Composable
private fun protocolLabel(protocol: ProtocolType): String = L10n.get(when (protocol) {
        ProtocolType.DNS_UDP -> Strings.protocol_dns_udp
        ProtocolType.DNS_DOT -> Strings.protocol_dns_dot
        ProtocolType.DNS_DOH -> Strings.protocol_dns_doh
        ProtocolType.HTTPS -> Strings.protocol_https
        ProtocolType.QUIC -> Strings.protocol_quic
        ProtocolType.TCP -> Strings.protocol_tcp
        ProtocolType.UDP -> Strings.protocol_udp
    }
)

@Composable
private fun requestCategoryLabel(category: RequestCategory): String = when (category) {
    RequestCategory.AD -> L10n.get(Strings.log_category_ad)
    RequestCategory.TRACKER -> L10n.get(Strings.log_category_tracker)
    RequestCategory.ANALYTICS -> L10n.get(Strings.log_category_analytics)
    RequestCategory.SOCIAL -> L10n.get(Strings.log_category_social)
    RequestCategory.ANNOYANCE -> L10n.get(Strings.log_category_annoyance)
    RequestCategory.MALWARE -> L10n.get(Strings.log_category_malware)
    RequestCategory.CUSTOM -> L10n.get(Strings.log_category_custom)
}

/**
 * The request-type strip along the top of the log — AdGuard's own navigation,
 * one tab per kind of request with `All requests` first. Every row belongs to
 * exactly one tab, so this is a partition of the log rather than a filter that
 * hides rows the user still wants to count.
 */
/**
 * Which kind of request the table holds — HTML, CSS, JS, image, … — as one
 * row of buttons.
 *
 * A drop-down here would hide the list behind a click and, worse, hide the
 * fact that the list exists at all: the row is the log's own vocabulary and
 * it should be readable at a glance. It scrolls sideways when the window is
 * too narrow to hold the eleven of them.
 */
@Composable
private fun LogTypeRow(selected: LogTypeTab, onSelect: (LogTypeTab) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(bottom = 6.dp)
            .testTag("log_type_row"),
        horizontalArrangement = Arrangement.spacedBy(4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        for (tab in LogTypeTab.ordered) {
            val active = tab == selected
            // Colour, not a filled button: eleven pills across one line read
            // as a toolbar of its own, and this row is a filter, not a set of
            // commands. The chosen type is green and bold; the rest are the
            // same muted grey as the column headers above them.
            Text(
                text = L10n.get(tab.labelKey),
                fontSize = 11.sp,
                fontWeight = if (active) FontWeight.Bold else FontWeight.Medium,
                color = if (active) AdGuardGreenLight else AdGuardTextMuted,
                maxLines = 1,
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .clickable { onSelect(tab) }
                    .padding(horizontal = 8.dp, vertical = 5.dp)
                    .testTag("log_type_tab_${tab.key}"),
            )
        }
    }
}

/**
 * The three status filters as one sequence, so the window can float them at its
 * right edge and the phone can put them on a line of their own without either
 * surface owning a copy of what they mean.
 */
@Composable
private fun LogStatusSwitches(state: AdGuardUiState, onFilter: (FilterStatus?) -> Unit) {
    LogFilterSwitch(
        tag = "log_filter_switch_all",
        label = L10n.format(Strings.log_filter_all, state.logTotal),
        checked = state.statusFilter == null,
        tint = AdGuardGreenPrimary,
        onCheckedChange = { onFilter(null) },
    )
    LogFilterSwitch(
        tag = "log_filter_switch_blocked",
        label = L10n.format(Strings.log_filter_blocked, state.logBlockedTotal),
        checked = state.statusFilter == FilterStatus.BLOCKED,
        tint = AdGuardRedBlocked,
        onCheckedChange = { checked -> onFilter(if (checked) FilterStatus.BLOCKED else null) },
    )
    LogFilterSwitch(
        tag = "log_filter_switch_allowed",
        label = L10n.format(Strings.log_filter_allowed, state.logAllowedTotal),
        checked = state.statusFilter == FilterStatus.ALLOWED,
        tint = AdGuardGreenLight,
        onCheckedChange = { checked -> onFilter(if (checked) FilterStatus.ALLOWED else null) },
    )
}

/**
 * One status filter, as a switch rather than a chip: the toolbar keeps three
 * of these at its right edge, and a switch is the control a Windows user reads
 * as "this filter is on" without the row growing to the height of a button.
 */
@Composable
private fun LogFilterSwitch(
    tag: String,
    label: String,
    checked: Boolean,
    tint: Color,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .clip(RoundedCornerShape(8.dp))
            .clickable { onCheckedChange(!checked) }
            .padding(start = 6.dp, end = 2.dp)
            .testTag(tag),
    ) {
        Text(
            text = label,
            fontSize = 11.sp,
            fontWeight = if (checked) FontWeight.Bold else FontWeight.Medium,
            color = if (checked) tint else AdGuardTextMuted,
            maxLines = 1,
        )
        Spacer(modifier = Modifier.width(5.dp))
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            modifier = Modifier
                .scale(0.68f)
                .width(38.dp),
            colors = SwitchDefaults.colors(
                checkedThumbColor = AdGuardOnAccent,
                checkedTrackColor = tint,
                checkedBorderColor = tint,
                uncheckedThumbColor = AdGuardTextMuted,
                uncheckedTrackColor = AdGuardDarkSurfaceVariant,
                uncheckedBorderColor = AdGuardDarkOutline,
            ),
        )
    }
}

/** One cell of the log table, holding its column's share of the width. */
@Composable
private fun RowScope.LogCell(weight: Float, content: @Composable () -> Unit) {
    Box(modifier = Modifier.weight(weight), contentAlignment = Alignment.CenterStart) {
        content()
    }
}

@Composable
private fun RowScope.LogColumnTitle(text: String) {
    Text(
        text = text,
        fontSize = 11.sp,
        fontWeight = FontWeight.Bold,
        color = AdGuardTextMuted,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
        modifier = Modifier.fillMaxWidth()
    )
}

@Composable
private fun RowScope.LogCellValue(
    value: String,
    color: Color = AdGuardTextSecondary,
    monospace: Boolean = false,
) {
    Text(
        text = value,
        fontSize = 11.5.sp,
        color = color,
        fontFamily = if (monospace) FontFamily.Monospace else FontFamily.Default,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
        modifier = Modifier.fillMaxWidth()
    )
}

@Composable
private fun LogTableHeader() {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp, vertical = 5.dp)
            .testTag("log_table_header"),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        LogCell(COL_TIME) { LogColumnTitle(L10n.get(Strings.log_detail_time)) }
        LogCell(COL_NAME) { LogColumnTitle(L10n.get(Strings.log_col_name)) }
        LogCell(COL_RULE) { LogColumnTitle(L10n.get(Strings.log_col_rule)) }
        LogCell(COL_FILTER) { LogColumnTitle(L10n.get(Strings.log_col_filter)) }
        LogCell(COL_TYPE) { LogColumnTitle(L10n.get(Strings.log_col_type)) }
        LogCell(COL_SOURCE) { LogColumnTitle(L10n.get(Strings.log_col_source)) }
        LogCell(COL_PROCESS) { LogColumnTitle(L10n.get(Strings.log_col_process)) }
        LogCell(COL_STATUS) { LogColumnTitle(L10n.get(Strings.log_col_status)) }
    }
}

/**
 * One log row in AdGuard's table: the address the request went to, the rule
 * that answered it, the list that rule came from, the kind of request it was,
 * the page that asked, and the process that asked for it. A cell with nothing
 * to say stays blank rather than filling the column with a placeholder — the
 * columns are read as a set, and an invented value is harder to trust.
 */
@Composable
fun LogTableRow(
    log: NetworkRequestLog,
    appLabel: String? = null,
    onClick: () -> Unit
) {
    val statusColor = when (log.status) {
        FilterStatus.BLOCKED -> AdGuardRedBlocked
        FilterStatus.ALLOWED -> AdGuardGreenPrimary
        FilterStatus.WHITELISTED -> AdGuardBlueDns
    }
    // AdGuard colours a blocked row red and a modified or whitelisted one
    // green; the same signal here, kept faint enough for a screen of rows.
    val rowTint = when (log.status) {
        FilterStatus.BLOCKED -> AdGuardRedBlocked.copy(alpha = 0.07f)
        FilterStatus.WHITELISTED -> AdGuardBlueDns.copy(alpha = 0.06f)
        FilterStatus.ALLOWED -> Color.Transparent
    }
    val timeFormat = remember { SimpleDateFormat("HH:mm:ss", Locale.getDefault()) }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(6.dp))
            .background(rowTint)
            .clickable { onClick() }
            .padding(horizontal = 8.dp, vertical = 4.dp)
            .testTag("log_row_${log.id}"),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        LogCell(COL_TIME) {
            LogCellValue(timeFormat.format(Date(log.timestampMs)), AdGuardTextMuted, monospace = true)
        }
        LogCell(COL_NAME) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(7.dp)
                        .clip(CircleShape)
                        .background(statusColor)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = log.displayName,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Medium,
                    color = AdGuardTextPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )
            }
        }
        LogCell(COL_RULE) { LogCellValue(log.matchedRule.orEmpty()) }
        LogCell(COL_FILTER) { LogCellValue(log.filterListName.orEmpty()) }
        LogCell(COL_TYPE) { LogCellValue(requestTypeLabel(log.requestType)) }
        LogCell(COL_SOURCE) { LogCellValue(log.source.orEmpty()) }
        LogCell(COL_PROCESS) {
            // The program's own mark, the way AdGuard's log carries one: a
            // column of process names has to be read, a column of icons is
            // scanned, and this log is read by glancing at it.
            val icon = rememberAppIcon(log.appPackage)
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (icon != null) {
                    Image(
                        bitmap = icon,
                        contentDescription = null,
                        modifier = Modifier.size(14.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                }
                LogCellValue(appLabel ?: log.appPackage.orEmpty())
            }
        }
        LogCell(COL_STATUS) { LogCellValue(logStatusLabel(log.status), statusColor) }
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

    val timeFormat = remember { SimpleDateFormat("HH:mm:ss", Locale.getDefault()) }
    val timeStr = timeFormat.format(Date(log.timestampMs))
    val appIcon = rememberAppIcon(log.appPackage)

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
            // Which app asked: the log names it, and a launcher icon makes it
            // scannable at a glance instead of reading every package name.
            Box(
                modifier = Modifier
                    .size(34.dp)
                    .clip(RoundedCornerShape(9.dp))
                    .background(AdGuardDarkSurfaceVariant),
                contentAlignment = Alignment.Center
            ) {
                if (appIcon != null) {
                    Image(
                        bitmap = appIcon,
                        contentDescription = null,
                        modifier = Modifier.size(26.dp)
                    )
                } else {
                    Icon(
                        imageVector = Icons.Default.Public,
                        contentDescription = null,
                        tint = AdGuardTextMuted,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.width(10.dp))

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
                        text = log.displayName,
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
                    // The same classification the desktop table gives a column
                    // of its own, first in the line on a phone.
                    Text(
                        text = requestTypeLabel(log.requestType),
                        fontSize = 11.sp,
                        color = AdGuardTextSecondary
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
                    val matchedRule = log.matchedRule
                    if (matchedRule != null) {
                        Text(
                            text = "•",
                            fontSize = 11.sp,
                            color = AdGuardTextMuted
                        )
                        Text(
                            text = matchedRule,
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
                    text = logStatusLabel(log.status),
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    color = statusColor
                )
            }
        }
    }
}

/**
 * AdGuard's view of one request: what was asked, what answered it, which rules
 * spoke for it, and what to do about it next. The sheet a phone gets and the
 * pane a window docks both render this, so neither can drift from the other.
 */
@Composable
private fun LogDetailBody(
    log: NetworkRequestLog,
    appNames: Map<String, String>,
    filterLists: List<FilterList>,
    ruleDraft: RuleDraft?,
    onOpenRuleEditor: (RuleDraft) -> Unit,
    onCloseRuleEditor: () -> Unit,
    onSubmitRule: (String) -> Unit,
    onSwitchRule: (LogRuleSwitch, Boolean) -> Unit,
    onAnalyzeWithAi: (String) -> Unit,
    onClose: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val platform = currentPlatformHost()
    val clipboard = LocalClipboardManager.current
    val appLabel = appLabelFor(appNames, log.appPackage)
    // "App" on a phone, where the owner is an installed application; "Process"
    // on a desktop, where the name belongs to one running process.
    val ownerLabel = L10n.get(
        if (platform.supportsAppCatalogue()) Strings.log_detail_app else Strings.log_col_process,
    )
    val openableUrl = log.url?.takeIf { logUrlOpenable(it) }

    if (ruleDraft != null) {
        RuleFromLogSheetContent(
            draft = ruleDraft,
            appLabel = appLabelFor(appNames, ruleDraft.appPackage),
            existingRules = filterLists.firstOrNull { it.isCustom }?.customRules.orEmpty(),
            onSubmit = onSubmitRule,
            onCancel = onCloseRuleEditor,
        )
        return
    }

    Column(
        modifier = modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp, vertical = 16.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = L10n.get(Strings.log_detail_title),
                fontSize = 17.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f)
            )
            IconButton(onClick = onClose) {
                Icon(Icons.Default.Close, contentDescription = L10n.get(Strings.common_close), tint = AdGuardTextSecondary)
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Destination Header Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurfaceVariant)
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Text(
                    text = L10n.get(Strings.log_dest_header),
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextMuted
                )
                Text(
                    text = log.displayName,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                    fontFamily = FontFamily.Monospace,
                    color = AdGuardTextPrimary,
                    lineHeight = 16.sp,
                )
                Spacer(modifier = Modifier.height(4.dp))
                // Two pieces side by side rather than one sentence: joined
                // into a line of prose they wrap in the middle of a word and
                // leave "Giao / thức:" hanging under the address.
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (log.ipAddress.isNotBlank()) {
                        Text(
                            text = log.ipAddress,
                            fontSize = 11.sp,
                            color = AdGuardTextSecondary,
                            fontFamily = FontFamily.Monospace,
                        )
                    }
                    Text(
                        text = protocolLabel(log.protocol),
                        fontSize = 11.sp,
                        color = AdGuardTextMuted,
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        LogDetailSection(L10n.get(Strings.log_detail_section_general)) {
            DetailRow(
                label = L10n.get(Strings.log_detail_url),
                value = log.displayName,
            )
            DetailRow(
                label = L10n.get(Strings.log_col_status),
                value = logActionLabel(log.status)
            )
            DetailRow(
                label = L10n.get(Strings.log_col_type),
                value = requestTypeLabel(log.requestType),
            )
            // What the origin answered with travels on the request row, not on
            // a row of its own.
            log.httpResponseStatus?.let { code ->
                DetailRow(label = L10n.get(Strings.log_detail_http_status), value = code.toString())
            }
            log.contentType?.let { mime ->
                DetailRow(label = L10n.get(Strings.log_detail_content_type), value = mime)
            }
            DetailRow(label = L10n.get(Strings.log_detail_category), value = requestCategoryLabel(log.category))
            // AdGuard names the page that asked for a request its log's
            // Source; here it is the referrer the request really carried.
            log.source?.let { referrer ->
                DetailRow(label = L10n.get(Strings.log_col_source), value = referrer)
            }
            log.dnsAnswer?.let { dnsAnswer ->
                DetailRow(label = L10n.get(Strings.log_detail_dns_answer), value = dnsAnswer)
            }
            log.tlsVersion?.let { version ->
                DetailRow(label = L10n.get(Strings.log_detail_tls_version), value = version)
            }
            log.cipher?.let { suite ->
                DetailRow(label = L10n.get(Strings.log_detail_cipher_suite), value = suite)
            }
            // The leaf the origin handed over. The issuer is the line that
            // answers which authority this machine is really trusting for a
            // given endpoint — the reason AdGuard keeps it beside the cipher.
            log.certSubject?.let { subject ->
                DetailRow(label = L10n.get(Strings.log_detail_cert_subject), value = subject)
            }
            log.certIssuer?.let { issuer ->
                DetailRow(label = L10n.get(Strings.log_detail_cert_issuer), value = issuer)
            }
            val from = log.certValidFrom
            val to = log.certValidTo
            if (from != null && to != null) {
                DetailRow(
                    label = L10n.get(Strings.log_detail_cert_validity),
                    value = SimpleDateFormat("yyyy-MM-dd", Locale.getDefault())
                        .format(Date(from)) + " → " +
                        SimpleDateFormat("yyyy-MM-dd", Locale.getDefault()).format(Date(to)),
                )
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = ownerLabel,
                    fontSize = 12.sp,
                    color = AdGuardTextSecondary,
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    val appIcon = rememberAppIcon(log.appPackage)
                    if (appIcon != null) {
                        Image(
                            bitmap = appIcon,
                            contentDescription = null,
                            modifier = Modifier.size(20.dp),
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                    }
                    Text(
                        text = appLabel ?: L10n.get(Strings.log_app_unknown),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = AdGuardTextPrimary,
                        fontFamily = FontFamily.Monospace,
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        LogDetailSection(L10n.get(Strings.log_detail_section_rules)) {
            val switches = logRuleSwitches(log, filterLists)
            if (switches.isEmpty()) {
                // Nothing here can be switched: the rule came from a body that
                // is no longer installed, or nothing filtered the request at
                // all. Say which, rather than showing an empty heading.
                if (log.matchedRule == null && log.filterListName == null) {
                    Text(
                        text = L10n.get(Strings.log_detail_no_rules),
                        fontSize = 12.sp,
                        color = AdGuardTextMuted,
                    )
                }
                log.matchedRule?.let { matchedRule ->
                    DetailRow(label = L10n.get(Strings.log_detail_rule), value = matchedRule)
                }
                log.filterListName?.let { filterListName ->
                    DetailRow(label = L10n.get(Strings.log_detail_list), value = filterListName)
                }
            }
            switches.forEachIndexed { index, rule ->
                LogRuleSwitchRow(rule = rule, index = index, onSwitch = onSwitchRule)
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        LogDetailSection(L10n.get(Strings.settings_group_network)) {
            DetailRow(
                label = L10n.get(Strings.log_detail_time),
                value = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
                    .format(Date(log.timestampMs)),
            )
            logDurationLabel(log.latencyMicros)?.let { duration ->
                DetailRow(label = L10n.get(Strings.log_detail_latency), value = duration)
            }
            val transportLabel = when (log.transport) {
                NetworkTransport.WIFI -> L10n.get(Strings.log_transport_wifi)
                NetworkTransport.CELLULAR -> L10n.get(Strings.log_transport_cellular)
                NetworkTransport.UNKNOWN -> null
            }
            if (transportLabel != null) {
                DetailRow(
                    label = L10n.get(Strings.log_detail_transport),
                    value = if (log.roaming) {
                        L10n.format(Strings.log_transport_roaming, transportLabel)
                    } else {
                        transportLabel
                    },
                )
            }
            if (log.flowId > 0) {
                DetailRow(
                    label = L10n.get(Strings.log_detail_connection),
                    value = "#${log.flowId}",
                )
            }
            if (log.bytesSent > 0 || log.bytesReceived > 0) {
                DetailRow(
                    label = L10n.get(Strings.log_detail_transfer),
                    value = L10n.format(Strings.log_transfer_value,
                        assetSizeLabel(log.bytesSent),
                        assetSizeLabel(log.bytesReceived),
                    ),
                )
            }
            if (log.dataSavedBytes > 0) {
                DetailRow(
                    label = L10n.get(Strings.log_detail_saved),
                    value = L10n.format(Strings.log_saved_value, log.dataSavedBytes / 1024)
                )
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // Reach the address, take the text along, and then decide what the
        // filter should do next time — AdGuard's own order of wants.
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            openableUrl?.let { url ->
                OutlinedButton(
                    onClick = { platform.openUrl(url) },
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 44.dp)
                        .testTag("log_detail_open_url"),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 10.dp),
                    shape = RoundedCornerShape(10.dp),
                ) {
                    Icon(
                        imageVector = Icons.Default.Public,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp),
                        tint = AdGuardGreenPrimary,
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = L10n.get(Strings.log_open_in_browser),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardGreenPrimary,
                    )
                }
            }

            OutlinedButton(
                onClick = { clipboard.setText(AnnotatedString(log.displayName)) },
                modifier = Modifier
                    .weight(1f)
                    .heightIn(min = 44.dp)
                    .testTag("log_detail_copy"),
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 10.dp),
                shape = RoundedCornerShape(10.dp),
            ) {
                Text(
                    text = L10n.get(Strings.settings_copy),
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextSecondary,
                )
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        // Action Buttons
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            OutlinedButton(
                onClick = {
                    onOpenRuleEditor(
                        RuleDraft(
                            kind = RuleDraftKind.ALLOW,
                            host = log.domain,
                            appPackage = log.appPackage,
                            appScopable = appScopeSupported(log.protocol, log.appPackage),
                        ),
                    )
                },
                modifier = Modifier
                    .weight(1f)
                    .heightIn(min = 48.dp),
                shape = RoundedCornerShape(10.dp),
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 10.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, AdGuardBlueDns)
            ) {
                Text(
                    text = L10n.get(Strings.log_allowlist),
                    color = AdGuardBlueDns,
                    fontWeight = FontWeight.Bold,
                    fontSize = 11.5.sp,
                    maxLines = 2,
                    textAlign = TextAlign.Center,
                )
            }

            OutlinedButton(
                onClick = {
                    onOpenRuleEditor(
                        RuleDraft(
                            kind = RuleDraftKind.BLOCK,
                            host = log.domain,
                            appPackage = log.appPackage,
                            appScopable = appScopeSupported(log.protocol, log.appPackage),
                        ),
                    )
                },
                modifier = Modifier
                    .weight(1f)
                    .heightIn(min = 48.dp),
                shape = RoundedCornerShape(10.dp),
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 10.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, AdGuardRedBlocked)
            ) {
                Text(
                    text = L10n.get(Strings.log_block_domain),
                    color = AdGuardRedBlocked,
                    fontWeight = FontWeight.Bold,
                    fontSize = 11.5.sp,
                    maxLines = 2,
                    textAlign = TextAlign.Center,
                )
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        Button(
            onClick = { onAnalyzeWithAi(log.domain) },
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 48.dp),
            shape = RoundedCornerShape(10.dp),
            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 10.dp),
            colors = ButtonDefaults.buttonColors(containerColor = AdGuardPurpleAI)
        ) {
            Icon(Icons.Default.Search, contentDescription = null, tint = AdGuardOnAccent)
            Spacer(modifier = Modifier.width(8.dp))
            Text(L10n.get(Strings.log_check_safety), color = AdGuardOnAccent, fontWeight = FontWeight.Bold)
        }

        Spacer(modifier = Modifier.height(16.dp))
    }
}

/**
 * AdGuard groups a request's details under their own headings — General,
 * Network, Rules — instead of leaving the user to pick them out of one long
 * list of label and value pairs.
 */
@Composable
private fun LogDetailSection(title: String, content: @Composable ColumnScope.() -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = title,
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextMuted,
            letterSpacing = 0.06.sp,
        )
        content()
    }
}

/**
 * One rule the request fell under, with the switch AdGuard hangs beside it.
 *
 * The two kinds behave differently on purpose: a rule the user wrote parks
 * behind a `!` and comes back with its text intact, a list turns off whole
 * because a single rule inside a downloaded body cannot be edited here.
 */
@Composable
private fun LogRuleSwitchRow(
    rule: LogRuleSwitch,
    index: Int,
    onSwitch: (LogRuleSwitch, Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("log_rule_switch_$index"),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = rule.label,
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                color = if (rule.enabled) AdGuardTextPrimary else AdGuardTextMuted,
                fontFamily = FontFamily.Monospace,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            rule.rule?.let { fired ->
                Text(
                    text = fired,
                    fontSize = 11.sp,
                    color = AdGuardTextMuted,
                    fontFamily = FontFamily.Monospace,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        Switch(
            checked = rule.enabled,
            onCheckedChange = { onSwitch(rule, it) },
            colors = SwitchDefaults.colors(
                checkedTrackColor = AdGuardGreenPrimary,
                checkedThumbColor = AdGuardOnAccent,
            ),
        )
    }
}

@Composable
fun DetailRow(label: String, value: String) {
    // Two columns hold a status or a cipher; they cannot hold a URL, a DNS
    // answer or a certificate subject. Those get the pane's whole width and
    // their label above them — the alternative is what this row used to do,
    // which was to print the label and the value on top of each other and
    // break the words wherever the edge happened to fall.
    if (value.length > 22) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(1.dp),
        ) {
            Text(text = label, fontSize = 11.sp, color = AdGuardTextMuted)
            Text(
                text = value,
                fontSize = 11.5.sp,
                fontWeight = FontWeight.SemiBold,
                color = AdGuardTextPrimary,
                fontFamily = FontFamily.Monospace,
                lineHeight = 15.sp,
            )
        }
    } else {
        Row(modifier = Modifier.fillMaxWidth()) {
            Text(
                text = label,
                fontSize = 11.5.sp,
                color = AdGuardTextSecondary,
                // Wide enough for the longest label this pane has ("Mã trạng
                // thái HTTP", "Chủ thể chứng chỉ") in one line, and allowed
                // to wrap rather than lose its tail when a translation is
                // longer than the one it was measured against.
                maxLines = 2,
                lineHeight = 14.sp,
            )
            Spacer(modifier = Modifier.width(6.dp))
            Text(
                text = value,
                fontSize = 11.5.sp,
                fontWeight = FontWeight.SemiBold,
                color = AdGuardTextPrimary,
                fontFamily = FontFamily.Monospace,
                textAlign = TextAlign.End,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                // Whatever the label does not need: a fixed share of the row
                // was a guess that held for one label and clipped the next
                // one's value ("2026-11-09 12:05:…").
                modifier = Modifier.weight(1f, fill = false),
            )
        }
    }
}
