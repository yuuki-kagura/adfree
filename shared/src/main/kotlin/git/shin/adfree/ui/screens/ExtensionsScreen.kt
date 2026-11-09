package git.shin.adfree.ui.screens

import git.shin.adfree.l10n.Strings
import git.shin.adfree.l10n.L10n
import git.shin.adfree.platform.currentFileHost
import git.shin.adfree.platform.currentPlatformHost
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.model.UserScriptInfo
import git.shin.adfree.ui.AdGuardIntent
import git.shin.adfree.ui.AdGuardViewModel
import git.shin.adfree.ui.theme.AdGuardDarkBg
import kotlinx.coroutines.launch
import git.shin.adfree.ui.theme.AdGuardDarkSurface
import git.shin.adfree.ui.theme.AdGuardRedBlocked
import git.shin.adfree.ui.theme.AdGuardTextMuted
import git.shin.adfree.ui.theme.AdGuardTextPrimary
import git.shin.adfree.ui.theme.AdGuardGreenPrimary
import androidx.compose.foundation.layout.PaddingValues

import git.shin.adfree.ui.theme.AdGuardTextSecondary

/**
 * The AdGuard Assistant is not ours and is not vendored: it is a userscript of
 * AdGuard's, GPL-3, served by their CDN. Installing it here downloads that
 * bundle into this machine's script store exactly like any other userscript —
 * the licence stays AdGuard's and updates stay theirs.
 */
private const val AdGuardAssistantUrl =
    "https://cdn.jsdelivr.net/npm/@adguard/assistant@4.4.16/dist/self.assistant.js"

/** Prefix, so a version bump or a mirror still counts as installed. */
private const val ASSISTANT_URL_PREFIX = "https://cdn.jsdelivr.net/npm/@adguard/assistant"

/**
 * Full-screen home for userscripts. The store, import and editor actions used
 * to sit at the bottom of the filter catalogue; they now have their own
 * destination so the catalogue screen stays about lists.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExtensionsScreen(
    viewModel: AdGuardViewModel,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsState()
    val files = currentFileHost()
    val platform = currentPlatformHost()
    val pickerScope = rememberCoroutineScope()
    var showCreateScript by remember { mutableStateOf(false) }
    var editScriptTarget by remember { mutableStateOf<UserScriptInfo?>(null) }
    var deleteScriptTarget by remember { mutableStateOf<UserScriptInfo?>(null) }

    fun pickScriptFile() {
        pickerScope.launch {
            val uriText = files.openText() ?: return@launch
            files.persistRead(uriText)
            viewModel.onIntent(AdGuardIntent.ImportLocalScript(uriText))
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(AdGuardDarkBg),
    ) {
        Column(modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)) {
            HubDestinationHeader(
                title = L10n.get(Strings.hub_extensions_title),
                subtitle = L10n.get(Strings.ext_screen_subtitle),
                onBack = onBack,
            )
        }

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp),
        ) {
            Text(
                text = L10n.get(Strings.ext_screen_intro),
                fontSize = 11.sp,
                color = AdGuardTextMuted,
            )
            Spacer(modifier = Modifier.height(10.dp))

            AssistantInstallRow(
                installed = state.userscripts.any { it.url.startsWith(ASSISTANT_URL_PREFIX) },
                onInstall = {
                    viewModel.onIntent(
                        AdGuardIntent.AddScript("AdGuard Assistant", AdGuardAssistantUrl),
                    )
                },
            )
            Spacer(modifier = Modifier.height(10.dp))

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

            Spacer(modifier = Modifier.height(72.dp))
        }
    }

    // ------------------------------------------------------------- dialogs

    if (state.showAddScriptDialog) {
        AddScriptDialog(
            onDismiss = { viewModel.onIntent(AdGuardIntent.ShowAddScriptDialog(false)) },
            onAdd = { name, url -> viewModel.onIntent(AdGuardIntent.AddScript(name, url)) },
            onImportFile = {
                viewModel.onIntent(AdGuardIntent.ShowAddScriptDialog(false))
                pickScriptFile()
            },
            onCreate = {
                viewModel.onIntent(AdGuardIntent.ShowAddScriptDialog(false))
                showCreateScript = true
            },
        )
    }

    if (showCreateScript) {
        ScriptTextEditorDialog(
            title = L10n.get(Strings.ext_create_title),
            initialName = "",
            initialText = L10n.get(Strings.ext_create_template),
            confirmText = L10n.get(Strings.ext_create_confirm),
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
                title = L10n.get(Strings.ext_edit_title),
                initialName = target.name,
                initialText = "",
                confirmText = L10n.get(Strings.ext_save),
                onDismiss = { editScriptTarget = null },
                onConfirm = { name, text ->
                    editScriptTarget = null
                    viewModel.onIntent(AdGuardIntent.UpdateScriptText(target.id, name, text))
                },
                loadText = { viewModel.scriptText(target.id) },
            )
        }
    }

    deleteScriptTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { deleteScriptTarget = null },
            title = {
                Text(
                    L10n.get(Strings.ext_delete_title),
                    fontSize = 17.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextPrimary,
                )
            },
            text = {
                Text(
                    L10n.format(Strings.ext_delete_body, target.name),
                    fontSize = 12.sp,
                    color = AdGuardTextSecondary,
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    deleteScriptTarget = null
                    viewModel.onIntent(AdGuardIntent.DeleteScript(target.id))
                }) {
                    Text(
                        L10n.get(Strings.ext_delete),
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardRedBlocked,
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { deleteScriptTarget = null }) {
                    Text(
                        L10n.get(Strings.common_cancel),
                        fontSize = 13.sp,
                        color = AdGuardTextSecondary,
                    )
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
                onFirstPage = {
                    viewModel.onIntent(AdGuardIntent.SearchScriptStore(state.scriptStore.query))
                },
                onInstall = { item ->
                    viewModel.onIntent(
                        AdGuardIntent.InstallStoreScript(item.name, item.url, item.description),
                    )
                },
                onEnable = { script -> viewModel.onIntent(AdGuardIntent.ToggleScript(script.id, true)) },
                onOpenPage = { url ->
                    if (url.startsWith("https://") || url.startsWith("http://")) {
                        platform.openUrl(url)
                    }
                },
                onRetry = {
                    viewModel.onIntent(AdGuardIntent.SearchScriptStore(state.scriptStore.query))
                },
            )
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

/**
 * One row that offers the AdGuard Assistant, or says it is already there.
 *
 * It is a row and not a card stack because the assistant is one extension
 * among many: the list below is where every other script lives, and a user
 * who installed it should see it there, not here.
 */
@Composable
private fun AssistantInstallRow(installed: Boolean, onInstall: () -> Unit) {
    SurfaceCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
            Text(
                text = L10n.get(Strings.ext_assistant_title),
                fontSize = 15.sp,
                fontWeight = FontWeight.SemiBold,
                color = AdGuardTextPrimary,
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = if (installed) {
                    L10n.get(Strings.ext_assistant_installed)
                } else {
                    L10n.get(Strings.ext_assistant_subtitle)
                },
                fontSize = 11.5.sp,
                lineHeight = 16.sp,
                color = AdGuardTextMuted,
            )
            if (!installed) {
                Spacer(modifier = Modifier.height(8.dp))
                // Text-only, like every other action in the app: the row is
                // the control, a filled button here would out-shout the list.
                TextButton(
                    onClick = onInstall,
                    contentPadding = PaddingValues(horizontal = 0.dp, vertical = 2.dp),
                ) {
                    Text(
                        text = L10n.get(Strings.ext_assistant_install),
                        fontSize = 13.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = AdGuardGreenPrimary,
                    )
                }
            }
        }
    }
}
