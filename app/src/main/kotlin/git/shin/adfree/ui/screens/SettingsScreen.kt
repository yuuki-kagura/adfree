package git.shin.adfree.ui.screens

import android.widget.Toast
import androidx.compose.ui.res.stringResource
import git.shin.adfree.R
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.automirrored.filled.HelpOutline
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Science
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import git.shin.adfree.core.DnsRewriteValidation
import git.shin.adfree.core.MitmStatus
import git.shin.adfree.model.AppLanguage
import git.shin.adfree.model.DnsProvider
import git.shin.adfree.model.DnsRewriteRule
import git.shin.adfree.model.ProtectionSettings
import git.shin.adfree.model.ProtocolType
import git.shin.adfree.model.ThemeMode
import git.shin.adfree.model.caNotAfterMs
import git.shin.adfree.model.normalizeHttpsHost
import git.shin.adfree.ui.AdGuardTab
import git.shin.adfree.ui.AdGuardIntent
import git.shin.adfree.ui.AdGuardViewModel
import git.shin.adfree.ui.CoreText
import git.shin.adfree.ui.UiText
import git.shin.adfree.ui.theme.AdGuardBlueDns
import git.shin.adfree.ui.theme.AdGuardDarkBg
import git.shin.adfree.ui.theme.AdGuardDarkOutline
import git.shin.adfree.ui.theme.AdGuardPurpleAI
import git.shin.adfree.ui.theme.AdGuardDarkSurface
import git.shin.adfree.ui.theme.AdGuardDarkSurfaceVariant
import git.shin.adfree.ui.theme.AdGuardGreenLight
import git.shin.adfree.ui.theme.AdGuardGreenPrimary
import git.shin.adfree.ui.theme.AdGuardOrangeWarning
import git.shin.adfree.ui.theme.AdGuardRedBlocked
import git.shin.adfree.ui.theme.AdGuardTextMuted
import git.shin.adfree.ui.theme.AdGuardTextPrimary
import git.shin.adfree.ui.theme.AdGuardOnAccent
import git.shin.adfree.ui.theme.AdGuardTextSecondary

/** Public project page; the README carries the user-facing documentation. */
private const val HELP_URL = "https://github.com/tachibana-shin/adfree#readme"

/**
 * Settings screen.
 *
 * Every switch here maps to one field the Rust core reads on the packet path;
 * there are no decorative options.
 */
@Composable
fun SettingsScreen(
    viewModel: AdGuardViewModel,
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()
    val scrollState = rememberScrollState()
    val uriHandler = LocalUriHandler.current
    var pendingRestoreUri by remember { mutableStateOf<String?>(null) }

    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/json"),
    ) { uri ->
        uri?.let { viewModel.onIntent(AdGuardIntent.ExportBackup(it.toString())) }
    }
    val importLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        // Ask before overwriting; the actual read happens after confirmation.
        uri?.let { pendingRestoreUri = it.toString() }
    }

    // The header lives outside the scrolling column on purpose: it describes
    // where you are, and should not slide away as soon as the list moves.
    Column(
        modifier = modifier
            .fillMaxSize()
            .background(AdGuardDarkBg)
    ) {
        Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
            Text(
                text = stringResource(R.string.nav_settings),
                fontSize = 19.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextPrimary,
            )
            Text(
                text = stringResource(R.string.settings_subtitle),
                fontSize = 12.sp,
                color = AdGuardTextMuted
            )
        }

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(scrollState)
                .padding(horizontal = 16.dp)
        ) {
        Spacer(modifier = Modifier.height(8.dp))

            SettingsGroupHeader(stringResource(R.string.settings_group_general))

            LanguageSection(
                selected = state.settings.appLanguage,
                onSelect = { viewModel.onIntent(AdGuardIntent.SetAppLanguage(it)) },
            )

            Spacer(modifier = Modifier.height(14.dp))

            ThemeSection(
                selected = state.settings.themeMode,
                onSelect = { viewModel.onIntent(AdGuardIntent.SetThemeMode(it)) },
            )

            Spacer(modifier = Modifier.height(12.dp))

            SettingsSwitch(
                icon = Icons.Default.PowerSettingsNew,
                title = stringResource(R.string.settings_autostart_title),
                subtitle = stringResource(R.string.settings_autostart_subtitle),
                checked = state.settings.autoStart,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleAutoStart(it)) },
            )

            Spacer(modifier = Modifier.height(20.dp))

            SettingsGroupHeader(stringResource(R.string.settings_group_logging))

            SettingsSwitch(
                icon = Icons.Default.Visibility,
                title = stringResource(R.string.settings_log_allowed_title),
                subtitle = stringResource(R.string.settings_log_allowed_subtitle),
                checked = state.settings.logAllowedRequests,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleLogAllowed(it)) }
            )

            Spacer(modifier = Modifier.height(20.dp))

            SettingsGroupHeader(stringResource(R.string.settings_group_data))

            BackupSection(
                onExport = { exportLauncher.launch("adfree-backup.json") },
                onImport = {
                    importLauncher.launch(arrayOf("application/json", "text/plain", "*/*"))
                },
            )

            Spacer(modifier = Modifier.height(20.dp))

            SettingsGroupHeader(stringResource(R.string.settings_group_about))

            EngineInfoSection(state.stats.filterBuildMs)

            Spacer(modifier = Modifier.height(10.dp))

            SettingsLink(
                icon = Icons.AutoMirrored.Filled.HelpOutline,
                title = stringResource(R.string.settings_help_title),
                subtitle = stringResource(R.string.settings_help_subtitle),
                onClick = {
                    runCatching { uriHandler.openUri(HELP_URL) }
                },
            )

            Spacer(modifier = Modifier.height(10.dp))

            // A diagnostic screen rather than a daily tab: reachable from here.
            SettingsLink(
                icon = Icons.Default.Science,
                title = stringResource(R.string.settings_lab_title),
                subtitle = stringResource(R.string.settings_lab_subtitle),
                onClick = { viewModel.onIntent(AdGuardIntent.SelectTab(AdGuardTab.AI_LAB)) }
            )

            Spacer(modifier = Modifier.height(72.dp))
    }
    }

    pendingRestoreUri?.let { uri ->
        AlertDialog(
            onDismissRequest = { pendingRestoreUri = null },
            title = { Text(stringResource(R.string.settings_restore_title)) },
            text = {
                Text(
                    stringResource(R.string.settings_restore_body),
                    fontSize = 12.sp,
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        pendingRestoreUri = null
                        viewModel.onIntent(AdGuardIntent.ImportBackup(uri))
                    },
                ) {
                    Text(stringResource(R.string.settings_restore_confirm), color = AdGuardOrangeWarning)
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingRestoreUri = null }) {
                    Text(stringResource(R.string.common_cancel))
                }
            },
        )
    }
}

/** Group label that keeps the flat list of cards from reading as one blob. */
@Composable
private fun SettingsGroupHeader(title: String) {
    Text(
        text = title,
        fontSize = 13.sp,
        fontWeight = FontWeight.Bold,
        color = AdGuardGreenLight,
        modifier = Modifier.padding(top = 4.dp, bottom = 10.dp),
    )
}

/** In-app language; AppCompat recreates the activity when the choice changes. */
@Composable
private fun LanguageSection(
    selected: AppLanguage,
    onSelect: (AppLanguage) -> Unit,
) {
    Text(
        text = stringResource(R.string.settings_language_title),
        fontSize = 12.sp,
        fontWeight = FontWeight.Bold,
        color = AdGuardTextSecondary,
        modifier = Modifier.padding(bottom = 6.dp),
    )
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .testTag("settings_language_chips"),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        AppLanguage.entries.forEach { language ->
            FilterChip(
                selected = selected == language,
                onClick = { onSelect(language) },
                label = { Text(appLanguageLabel(language), fontSize = 11.sp) },
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = AdGuardGreenPrimary,
                    selectedLabelColor = AdGuardOnAccent,
                ),
            )
        }
    }
}

@Composable
private fun appLanguageLabel(language: AppLanguage): String = stringResource(
    when (language) {
        AppLanguage.SYSTEM -> R.string.settings_language_system
        AppLanguage.ENGLISH -> R.string.settings_language_english
        AppLanguage.VIETNAMESE -> R.string.settings_language_vietnamese
    }
)

@Composable
private fun ThemeSection(
    selected: ThemeMode,
    onSelect: (ThemeMode) -> Unit,
) {
    Text(
        text = stringResource(R.string.settings_theme_title),
        fontSize = 12.sp,
        fontWeight = FontWeight.Bold,
        color = AdGuardTextSecondary,
        modifier = Modifier.padding(bottom = 6.dp),
    )
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .testTag("settings_theme_chips"),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        ThemeMode.entries.forEach { mode ->
            FilterChip(
                selected = selected == mode,
                onClick = { onSelect(mode) },
                label = { Text(themeModeLabel(mode), fontSize = 11.sp) },
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = AdGuardGreenPrimary,
                    selectedLabelColor = AdGuardOnAccent,
                ),
            )
        }
    }
}

@Composable
private fun themeModeLabel(mode: ThemeMode): String = stringResource(
    when (mode) {
        ThemeMode.SYSTEM -> R.string.settings_theme_system
        ThemeMode.LIGHT -> R.string.settings_theme_light
        ThemeMode.DARK -> R.string.settings_theme_dark
    }
)

/** Export/restore the two core blobs without including device-local scripts. */@Composable
private fun BackupSection(
    onExport: () -> Unit,
    onImport: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(
                text = stringResource(R.string.settings_backup_title),
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextPrimary,
            )
            Text(
                text = stringResource(R.string.settings_backup_body),
                fontSize = 11.sp,
                color = AdGuardTextMuted,
                modifier = Modifier.padding(top = 2.dp),
            )
            Spacer(modifier = Modifier.height(10.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = onExport,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(8.dp),
                ) {
                    Text(stringResource(R.string.rules_export), fontSize = 11.sp, color = AdGuardGreenLight)
                }
                OutlinedButton(
                    onClick = onImport,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(8.dp),
                ) {
                    Text(stringResource(R.string.settings_restore_confirm), fontSize = 11.sp, color = AdGuardOrangeWarning)
                }
            }
        }
    }
}

/** A settings entry that navigates somewhere instead of toggling a flag. */
@Composable
private fun SettingsLink(
    icon: ImageVector,
    title: String,
    subtitle: String,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() },
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        border = CardDefaults.outlinedCardBorder().copy(
            brush = androidx.compose.ui.graphics.Brush.linearGradient(
                listOf(AdGuardDarkOutline, AdGuardPurpleAI.copy(alpha = 0.2f))
            )
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(36.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(AdGuardPurpleAI.copy(alpha = 0.15f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = AdGuardPurpleAI,
                    modifier = Modifier.size(20.dp)
                )
            }
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = AdGuardTextPrimary
                )
                Text(
                    text = subtitle,
                    fontSize = 11.sp,
                    color = AdGuardTextSecondary
                )
            }
            Icon(
                imageVector = Icons.Default.ChevronRight,
                contentDescription = null,
                tint = AdGuardTextMuted,
                modifier = Modifier.size(20.dp)
            )
        }
    }
}

/**
 * HTTPS filtering (MITM) section: shows the CA state, hands the user an install
 * button, and points at the extensions destination.
 */
@Composable
internal fun HttpsFilterSection(
    viewModel: AdGuardViewModel,
    fullEchEnabled: Boolean,
    onManageScripts: () -> Unit,
) {
    var status by remember { mutableStateOf<MitmStatus?>(null) }
    var showCert by remember { mutableStateOf(false) }
    var showCertGate by remember { mutableStateOf(false) }
    // HTTPS filtering is the persisted setting (the same one the engine config
    // is built from); `scriptsEnabled` only says whether the script set is
    // armed, which is a different thing entirely.
    var httpsEnabled by remember {
        mutableStateOf(viewModel.uiState.value.settings.isHttpsFilteringEnabled)
    }
    // Live view of the trust store: installing the CA while the app sits in
    // the background must flip this without a restart.
    var caTrusted by remember { mutableStateOf(viewModel.isCaTrusted()) }
    // Root mode: whether su is available and whether the system store already
    // carries the CA. Loading it never elevates.
    var rootTrust by remember {
        mutableStateOf<git.shin.adfree.core.RootTrustBinding?>(null)
    }
    var rootBusy by remember { mutableStateOf(false) }
    // The CA is installed by hand, outside the app: its expiry is the only
    // warning the user gets before every TLS connection starts failing.
    val caExpiryMs = remember(status?.caPem) { status?.caPem?.let(::caNotAfterMs) }
    // Set when the gate dialog sends the user off to install the certificate,
    // so coming back with it installed turns filtering on as they intended.
    var pendingEnable by remember { mutableStateOf(false) }
    // Which website list the add dialog is editing; null keeps it closed.
    var addTarget by remember { mutableStateOf<HttpsListTarget?>(null) }
    val ui by viewModel.uiState.collectAsState()

    val context = LocalContext.current

    // Lazily load the status; the core is cheap to query.
    androidx.compose.runtime.LaunchedEffect(Unit) {
        status = viewModel.readMitmStatus()
        caTrusted = viewModel.isCaTrusted()
        rootTrust = viewModel.rootTrustStatus()
    }

    // The system certificate installer lives in another activity: re-check the
    // store and honour the pending enable when we come back to the app.
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        status = viewModel.readMitmStatus()
        caTrusted = viewModel.isCaTrusted()
        rootTrust = viewModel.rootTrustStatus()
        if (pendingEnable && caTrusted && !httpsEnabled) {
            pendingEnable = false
            httpsEnabled = true
            viewModel.setHttpsFiltering(true) { status = it }
        }
    }

    Column {
        SettingsSwitch(
            icon = Icons.Default.Lock,
            title = stringResource(R.string.settings_https_enable_title),
            subtitle = stringResource(R.string.settings_https_enable_subtitle),
            checked = httpsEnabled,
            onCheckedChange = { enabled ->
                if (enabled && !caTrusted) {
                    // Without a trusted CA the engine can only fall back to a
                    // plain relay, so an "on" switch would lie: ask for the
                    // certificate first.
                    pendingEnable = true
                    showCertGate = true
                } else {
                    httpsEnabled = enabled
                    viewModel.setHttpsFiltering(enabled) { status = it }
                }
            }
        )

        Spacer(modifier = Modifier.height(10.dp))

        // QUIC is TCP's alternative transport: with HTTPS filtering on, the
        // engine can terminate it too, so pages that negotiate HTTP/3 keep
        // being filtered instead of falling back to TCP or being dropped.
        SettingsSwitch(
            icon = Icons.Default.Bolt,
            title = stringResource(R.string.settings_http3_title),
            subtitle = stringResource(R.string.settings_http3_subtitle),
            checked = ui.settings.filterHttp3,
            enabled = httpsEnabled,
            onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleFilterHttp3(it)) }
        )

        Spacer(modifier = Modifier.height(10.dp))

        SettingsSwitch(
            icon = Icons.Default.VisibilityOff,
            title = stringResource(R.string.settings_cosmetic_title),
            subtitle = stringResource(R.string.settings_cosmetic_subtitle),
            checked = ui.settings.cosmeticFiltering,
            onCheckedChange = {
                viewModel.onIntent(AdGuardIntent.ToggleCosmeticFiltering(it))
            }
        )

        Spacer(modifier = Modifier.height(10.dp))

        // The opt-in trade: ECH hides the inner name from the proxy, so a host
        // that uses it has to be spliced — unfiltered. Off by default; nothing
        // changes for clients that do not use ECH. Read straight from the
        // collected settings, not a remembered snapshot: the saved switches
        // arrive after the first composition, and a snapshot would keep
        // showing the default until the next tap.
        SettingsSwitch(
            icon = Icons.Default.Visibility,
            title = stringResource(R.string.settings_ech_title),
            subtitle = stringResource(R.string.settings_ech_subtitle),
            checked = fullEchEnabled,
            onCheckedChange = { enabled -> viewModel.setFullEch(enabled) }
        )

        Spacer(modifier = Modifier.height(12.dp))

        // AdGuard's "Filter HTTPS websites" block: an allowlist that keeps TLS
        // intact for banking/client-cert sites, plus the inverse mode that only
        // decrypts named hosts.
        HttpsWebsiteSection(
            settings = ui.settings,
            onAddSkip = { addTarget = HttpsListTarget.SKIP },
            onRemoveSkip = { viewModel.removeHttpsSkipHost(it) },
            onOnlyModeChange = { viewModel.setHttpsOnlyMode(it) },
            onAddOnly = { addTarget = HttpsListTarget.ONLY },
            onRemoveOnly = { viewModel.removeHttpsOnlyHost(it) },
        )

        Spacer(modifier = Modifier.height(10.dp))

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column {
                        Text(
                            text = if (status?.hasCa == true) stringResource(R.string.settings_ca_created)
                            else stringResource(R.string.settings_ca_missing),
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Bold,
                            color = if (status?.hasCa == true) AdGuardGreenLight else AdGuardTextSecondary,
                        )
                        Text(
                            text = status?.fingerprint?.take(23)?.let {
                                stringResource(R.string.settings_ca_fingerprint, it)
                            } ?: stringResource(R.string.settings_ca_create_hint),
                            fontSize = 10.sp,
                            color = AdGuardTextMuted,
                            fontFamily = FontFamily.Monospace,
                        )
                        Text(
                            text = stringResource(
                                if (caTrusted) R.string.settings_ca_trusted else R.string.settings_ca_untrusted
                            ),
                            fontSize = 11.sp,
                            color = if (caTrusted) AdGuardGreenLight else AdGuardOrangeWarning,
                        )
                        if (caExpiryMs != null) {
                            val now = System.currentTimeMillis()
                            // Compare instants for "expired": integer day math
                            // would keep reporting "còn 0 ngày" for the last
                            // day before, and the first day after, expiry.
                            val expired = caExpiryMs <= now
                            val daysLeft = (caExpiryMs - now) / 86_400_000L
                            Text(
                                text = if (expired) {
                                    stringResource(R.string.settings_ca_expired, formatCertDate(caExpiryMs))
                                } else {
                                    stringResource(R.string.settings_ca_expiry, formatCertDate(caExpiryMs), daysLeft)
                                },
                                fontSize = 11.sp,
                                color = when {
                                    expired -> AdGuardRedBlocked
                                    daysLeft < 30 -> AdGuardOrangeWarning
                                    else -> AdGuardTextMuted
                                },
                            )
                        }
                    }
                    OutlinedButton(
                        onClick = {
                            viewModel.createCa { fresh ->
                                status = fresh
                                caTrusted = viewModel.isCaTrusted()
                                rootTrust = viewModel.rootTrustStatus()
                            }
                        },
                        shape = RoundedCornerShape(8.dp),
                    ) {
                        Text(
                            if (status?.hasCa == true) stringResource(R.string.settings_ca_recreate)
                            else stringResource(R.string.settings_ca_create),
                            fontSize = 11.sp,
                        )
                    }
                }

                if (status?.hasCa == true) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            onClick = {
                                // The install is a multi-step trip through
                                // Settings; show the route before leaving.
                                pendingEnable = false
                                showCertGate = true
                            },
                            shape = RoundedCornerShape(8.dp),
                        ) {
                            Text(stringResource(R.string.settings_ca_install), fontSize = 11.sp)
                        }
                        OutlinedButton(
                            onClick = { showCert = true },
                            shape = RoundedCornerShape(8.dp),
                        ) {
                            Text(stringResource(R.string.settings_ca_view_pem), fontSize = 11.sp)
                        }
                    }

                    // Root mode: the user store is ignored by apps targeting
                    // API 24+ (Cronet in Google apps is the visible case), so
                    // offering the system store is the only way to filter
                    // them without splicing their traffic verbatim.
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        text = if (rootBusy) stringResource(R.string.trust_working)
                        else rootTrust?.detailCode?.let { CoreText.trustDetail(it)?.asString() }
                            ?: stringResource(R.string.trust_checking_root),
                        fontSize = 11.sp,
                        color = when {
                            rootBusy -> AdGuardTextMuted
                            rootTrust?.installed == true -> AdGuardGreenLight
                            rootTrust?.needsReboot == true -> AdGuardOrangeWarning
                            else -> AdGuardTextMuted
                        },
                    )
                    rootTrust?.let { trust ->
                        if (trust.suPresent || trust.installed) {
                            Row(
                                modifier = Modifier.padding(top = 6.dp),
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                            ) {
                                OutlinedButton(
                                    enabled = !rootBusy,
                                    onClick = {
                                        rootBusy = true
                                        viewModel.installRootCa { result ->
                                            rootBusy = false
                                            rootTrust = result
                                            caTrusted = viewModel.isCaTrusted()
                                                result?.detailCode?.let { code ->
                                                    CoreText.trustDetail(code)?.let {
                                                        Toast.makeText(
                                                            context,
                                                            it.resolve(context),
                                                            Toast.LENGTH_LONG,
                                                        ).show()
                                                    }
                                                }
                                        }
                                    },
                                    shape = RoundedCornerShape(8.dp),
                                ) {
                                    Text(
                                        stringResource(
                                            if (trust.installed) R.string.settings_ca_reinstall_system
                                            else R.string.settings_ca_install_system
                                        ),
                                        fontSize = 11.sp,
                                    )
                                }
                                if (trust.installed) {
                                    OutlinedButton(
                                        enabled = !rootBusy,
                                        onClick = {
                                            rootBusy = true
                                            viewModel.removeRootCa { result ->
                                                rootBusy = false
                                                rootTrust = result
                                                caTrusted = viewModel.isCaTrusted()
                                                result?.detailCode?.let { code ->
                                                    CoreText.trustDetail(code)?.let {
                                                        Toast.makeText(
                                                            context,
                                                            it.resolve(context),
                                                            Toast.LENGTH_LONG,
                                                        ).show()
                                                    }
                                                }
                                            }
                                        },
                                        shape = RoundedCornerShape(8.dp),
                                    ) {
                                        Text(stringResource(R.string.settings_ca_remove_system), fontSize = 11.sp)
                                    }
                                }
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = stringResource(
                        R.string.settings_ca_stage,
                        status?.stage ?: "—",
                        status?.scriptCount?.toLong() ?: 0L,
                        status?.leavesIssued?.toLong() ?: 0L
                    ),
                    fontSize = 11.sp,
                    color = AdGuardTextMuted,
                )

                OutlinedButton(
                    onClick = onManageScripts,
                    modifier = Modifier.padding(top = 8.dp),
                    shape = RoundedCornerShape(8.dp),
                ) {
                    Text(stringResource(R.string.settings_manage_scripts), fontSize = 11.sp)
                }
            }
        }
    }

    if (showCert) {
        CertificateDialog(status?.caPem.orEmpty()) { showCert = false }
    }
    addTarget?.let { target ->
        HttpsHostDialog(
            title = stringResource(
                if (target == HttpsListTarget.SKIP) R.string.settings_https_dialog_title_skip
                else R.string.settings_https_dialog_title_only
            ),
            onDismiss = { addTarget = null },
            onAdd = { host ->
                if (target == HttpsListTarget.SKIP) {
                    viewModel.addHttpsSkipHost(host)
                } else {
                    viewModel.addHttpsOnlyHost(host)
                }
            },
        )
    }
    if (showCertGate) {
        AlertDialog(
            onDismissRequest = {
                pendingEnable = false
                showCertGate = false
            },
            title = { Text(stringResource(R.string.settings_cert_gate_title), fontSize = 16.sp) },
            text = {
                Column {
                    Text(
                        stringResource(R.string.settings_cert_gate_body),
                        fontSize = 12.sp,
                        color = AdGuardTextSecondary,
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        stringResource(R.string.settings_cert_gate_steps),
                        fontSize = 12.sp,
                        color = AdGuardTextSecondary,
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    showCertGate = false
                    val saved = viewModel.installCertificate()
                    Toast.makeText(
                        context,
                        if (saved != null) {
                            context.getString(R.string.settings_cert_saved, saved)
                        } else {
                            context.getString(R.string.settings_cert_save_failed)
                        },
                        Toast.LENGTH_SHORT,
                    ).show()
                }) {
                    Text(stringResource(R.string.settings_cert_gate_open))
                }
            },
            dismissButton = {
                TextButton(onClick = {
                    pendingEnable = false
                    showCertGate = false
                }) {
                    Text(stringResource(R.string.settings_cert_gate_later))
                }
            },
        )
    }
}

@Composable
private fun CertificateDialog(pem: String, onDismiss: () -> Unit) {
    val clipboard = LocalClipboardManager.current
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.settings_cert_dialog_title), fontSize = 16.sp) },
        text = {
            Column {
                Text(
                    text = stringResource(R.string.settings_cert_dialog_body),
                    fontSize = 12.sp,
                    color = AdGuardTextSecondary,
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = pem,
                    fontSize = 9.sp,
                    fontFamily = FontFamily.Monospace,
                    color = AdGuardTextMuted,
                    modifier = Modifier
                        .heightIn(max = 220.dp)
                        .verticalScroll(rememberScrollState()),
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                clipboard.setText(AnnotatedString(pem))
                onDismiss()
            }) { Text(stringResource(R.string.settings_copy)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.common_close)) } },
    )
}

/**
 * Resolver selection. The list is real state from the repository, including
 * custom resolvers restored from the settings blob; before this section it
 * existed only as an orphan intent with no screen.
 *
 * The Test button sends one query through the selected transport; it runs on
 * the repository's IO dispatcher and reports back through the snackbar.
 */
@Composable
internal fun DnsProviderSection(
    providers: List<DnsProvider>,
    selectedId: String,
    isProbing: Boolean,
    onSelect: (String) -> Unit,
    onAdd: (String, String, ProtocolType) -> Unit,
    onProbe: (String) -> Unit,
) {
    var showDialog by remember { mutableStateOf(false) }
    val selected = providers.firstOrNull { it.id == selectedId } ?: providers.firstOrNull()

    Column {
        Text(
            text = stringResource(R.string.settings_dns_title),
            fontSize = 14.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextPrimary,
        )
        Text(
            text = stringResource(R.string.settings_dns_body),
            fontSize = 11.sp,
            color = AdGuardTextMuted,
        )
        Spacer(modifier = Modifier.height(10.dp))
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { showDialog = true },
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 14.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(
                    imageVector = Icons.Default.Dns,
                    contentDescription = null,
                    tint = AdGuardBlueDns,
                    modifier = Modifier.size(20.dp),
                )
                Spacer(modifier = Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = selected?.name ?: stringResource(R.string.settings_dns_unset_name),
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardTextPrimary,
                    )
                    if (selected != null) {
                        Text(
                            text = stringResource(
                                R.string.settings_dns_summary,
                                protocolLabel(selected.type),
                                selected.address,
                            ),
                            fontSize = 11.sp,
                            color = AdGuardTextMuted,
                        )
                    } else {
                        Text(
                            text = stringResource(R.string.settings_dns_unset_address),
                            fontSize = 11.sp,
                            color = AdGuardTextMuted,
                        )
                    }
                    if (selected?.isCustom == true) {
                        Text(stringResource(R.string.settings_dns_custom), fontSize = 10.sp, color = AdGuardBlueDns)
                    }
                }
                Column(horizontalAlignment = Alignment.End) {
                    Text(stringResource(R.string.settings_dns_change), fontSize = 12.sp, color = AdGuardBlueDns)
                    if (selected != null) {
                        TextButton(
                            onClick = { onProbe(selected.id) },
                            enabled = !isProbing,
                            contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
                        ) {
                            if (isProbing) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(14.dp),
                                    strokeWidth = 2.dp,
                                    color = AdGuardBlueDns,
                                )
                            } else {
                                Text(
                                    text = stringResource(R.string.settings_dns_test),
                                    fontSize = 11.sp,
                                    color = AdGuardBlueDns,
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    if (showDialog) {
        DnsProviderDialog(
            providers = providers,
            selectedId = selectedId,
            onDismiss = { showDialog = false },
            onSelect = {
                onSelect(it)
                showDialog = false
            },
            onAdd = { name, address, type ->
                onAdd(name, address, type)
                showDialog = false
            },
        )
    }
}

@Composable
private fun DnsProviderDialog(
    providers: List<DnsProvider>,
    selectedId: String,
    onDismiss: () -> Unit,
    onSelect: (String) -> Unit,
    onAdd: (String, String, ProtocolType) -> Unit,
) {
    var name by remember { mutableStateOf("") }
    var address by remember { mutableStateOf("") }
    var protocol by remember { mutableStateOf(ProtocolType.DNS_UDP) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.settings_dns_title), fontSize = 18.sp) },
        text = {
            Column(
                modifier = Modifier
                    .heightIn(max = 430.dp)
                    .verticalScroll(rememberScrollState()),
            ) {
                providers.forEach { provider ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onSelect(provider.id) }
                            .padding(vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(
                            selected = provider.id == selectedId,
                            onClick = { onSelect(provider.id) },
                        )
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = provider.name,
                                fontSize = 15.sp,
                                color = AdGuardTextPrimary,
                            )
                            Text(
                                text = stringResource(
                                    R.string.settings_dns_summary,
                                    protocolLabel(provider.type),
                                    provider.address,
                                ),
                                fontSize = 13.sp,
                                color = AdGuardTextMuted,
                                fontFamily = FontFamily.Monospace,
                            )
                            if (provider.isCustom) {
                                Text(stringResource(R.string.settings_dns_custom), fontSize = 11.sp, color = AdGuardBlueDns)
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = stringResource(R.string.settings_dns_add_title),
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextSecondary,
                )
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = stringResource(R.string.settings_dns_protocol_label),
                    fontSize = 13.sp,
                    color = AdGuardTextMuted,
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    listOf(
                        ProtocolType.DNS_UDP,
                        ProtocolType.DNS_DOT,
                        ProtocolType.DNS_DOH,
                    ).forEach { type ->
                        FilterChip(
                            selected = protocol == type,
                            onClick = { protocol = type },
                            label = { Text(protocolLabel(type), fontSize = 13.sp) },
                            colors = FilterChipDefaults.filterChipColors(
                                selectedContainerColor = AdGuardGreenPrimary,
                                selectedLabelColor = AdGuardOnAccent,
                            ),
                        )
                    }
                }
                Spacer(modifier = Modifier.height(6.dp))
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text(stringResource(R.string.settings_dns_name_label), fontSize = 13.sp) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(modifier = Modifier.height(6.dp))
                OutlinedTextField(
                    value = address,
                    onValueChange = { address = it },
                    label = { Text(stringResource(R.string.settings_dns_address_label), fontSize = 13.sp) },
                    placeholder = {
                        Text(
                            text = stringResource(
                                when (protocol) {
                                    ProtocolType.DNS_DOT -> R.string.settings_dns_address_hint_dot
                                    ProtocolType.DNS_DOH -> R.string.settings_dns_address_hint_doh
                                    else -> R.string.settings_dns_address_hint
                                },
                            ),
                            fontSize = 13.sp,
                        )
                    },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(modifier = Modifier.height(8.dp))
                Button(
                    // The core validates the address; a rejection is shown
                    // in the snackbar by the repository.
                    onClick = { onAdd(name, address, protocol) },
                    enabled = address.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(stringResource(R.string.settings_dns_add), fontSize = 14.sp)
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.common_close)) }
        },
    )
}

@Composable
private fun protocolLabel(type: ProtocolType): String = stringResource(
    when (type) {
        ProtocolType.DNS_DOT -> R.string.dns_protocol_dot
        ProtocolType.DNS_DOH -> R.string.dns_protocol_doh
        else -> R.string.dns_protocol_udp
    },
)

/**
 * DNS rewrites: explicit answers that run before the filter lists.
 *
 * Validation is the core's; the dialog only turns the returned code into
 * localized copy and keeps the sheet open until the row is acceptable.
 */
@Composable
internal fun DnsRewriteSection(
    rewrites: List<DnsRewriteRule>,
    validate: (String, String) -> DnsRewriteValidation,
    onAdd: (String, String) -> Unit,
    onRemove: (String) -> Unit,
) {
    var showDialog by remember { mutableStateOf(false) }

    Column {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = stringResource(R.string.network_rewrites_title),
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextPrimary,
                )
                Text(
                    text = stringResource(R.string.network_rewrites_subtitle),
                    fontSize = 11.sp,
                    color = AdGuardTextMuted,
                )
            }
            TextButton(onClick = { showDialog = true }) {
                Text(stringResource(R.string.network_rewrites_add), fontSize = 12.sp)
            }
        }
        Spacer(modifier = Modifier.height(6.dp))
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        ) {
            Column(modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp)) {
                if (rewrites.isEmpty()) {
                    Text(
                        text = stringResource(R.string.network_rewrites_empty),
                        fontSize = 11.sp,
                        color = AdGuardTextMuted,
                        modifier = Modifier.padding(vertical = 6.dp),
                    )
                } else {
                    rewrites.forEach { rule ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = rule.host,
                                    fontSize = 12.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = AdGuardTextPrimary,
                                )
                                Text(
                                    text = rule.answer,
                                    fontSize = 11.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = AdGuardTextMuted,
                                )
                            }
                            TextButton(onClick = { onRemove(rule.host) }) {
                                Text(
                                    text = stringResource(R.string.network_rewrites_remove),
                                    fontSize = 11.sp,
                                    color = AdGuardRedBlocked,
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    if (showDialog) {
        DnsRewriteDialog(
            validate = validate,
            onAdd = onAdd,
            onDismiss = { showDialog = false },
        )
    }
}

@Composable
private fun DnsRewriteDialog(
    validate: (String, String) -> DnsRewriteValidation,
    onAdd: (String, String) -> Unit,
    onDismiss: () -> Unit,
) {
    var host by remember { mutableStateOf("") }
    var answer by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<UiText?>(null) }

    fun save() {
        val checked = validate(host, answer)
        if (!checked.valid) {
            error = CoreText.dnsRewriteError(checked.error)
            return
        }
        error = null
        onAdd(checked.host, checked.answer)
        onDismiss()
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(stringResource(R.string.network_rewrites_add_title), fontSize = 16.sp)
        },
        text = {
            Column {
                OutlinedTextField(
                    value = host,
                    onValueChange = {
                        host = it
                        error = null
                    },
                    label = {
                        Text(stringResource(R.string.network_rewrites_host_label), fontSize = 11.sp)
                    },
                    placeholder = {
                        Text(stringResource(R.string.network_rewrites_host_hint), fontSize = 11.sp)
                    },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(modifier = Modifier.height(6.dp))
                OutlinedTextField(
                    value = answer,
                    onValueChange = {
                        answer = it
                        error = null
                    },
                    label = {
                        Text(stringResource(R.string.network_rewrites_answer_label), fontSize = 11.sp)
                    },
                    placeholder = {
                        Text(stringResource(R.string.network_rewrites_answer_hint), fontSize = 11.sp)
                    },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                error?.let {
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = it.asString(),
                        fontSize = 11.sp,
                        color = AdGuardRedBlocked,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = { save() },
                enabled = host.isNotBlank() && answer.isNotBlank(),
            ) {
                Text(stringResource(R.string.network_rewrites_save), fontSize = 12.sp)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.common_close))
            }
        },
    )
}

/** Engine build time, i.e. how long compiling the filter lists took. */
@Composable
private fun EngineInfoSection(buildMs: Long) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(
                text = stringResource(R.string.settings_engine_title),
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextSecondary,
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = stringResource(R.string.settings_engine_build, buildMs),
                fontSize = 12.sp,
                color = AdGuardTextPrimary,
            )
        }
    }
}

/** A settings row with an icon and description. */
@Composable
fun SettingsSwitch(
    icon: ImageVector,
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    enabled: Boolean = true,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Row(
                modifier = Modifier.weight(1f),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(AdGuardBlueDns.copy(alpha = 0.12f)),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = icon,
                        contentDescription = null,
                        tint = AdGuardBlueDns,
                        modifier = Modifier.size(18.dp),
                    )
                }
                Spacer(modifier = Modifier.size(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = title,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardTextPrimary,
                    )
                    Text(
                        text = subtitle,
                        fontSize = 11.sp,
                        color = AdGuardTextMuted,
                    )
                }
            }
            Switch(
                checked = checked,
                onCheckedChange = onCheckedChange,
                enabled = enabled,
                colors = SwitchDefaults.colors(
                    checkedThumbColor = Color.White,
                    checkedTrackColor = AdGuardGreenPrimary,
                    uncheckedThumbColor = AdGuardTextMuted,
                    uncheckedTrackColor = AdGuardDarkSurfaceVariant,
                ),
            )
        }
    }
}

@Composable
fun StealthToggleRow(
    title: String,
    subtitle: String,
    isChecked: Boolean,
    enabled: Boolean = true,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold,
                color = if (enabled) AdGuardTextPrimary else AdGuardTextMuted
            )
            Text(
                text = subtitle,
                fontSize = 11.sp,
                color = AdGuardTextSecondary
            )
        }

        Switch(
            checked = isChecked,
            onCheckedChange = onCheckedChange,
            enabled = enabled,
            colors = SwitchDefaults.colors(
                checkedThumbColor = Color.White,
                checkedTrackColor = AdGuardGreenPrimary,
                uncheckedThumbColor = AdGuardTextMuted,
                uncheckedTrackColor = AdGuardDarkSurfaceVariant
            )
        )
    }
}

// ------------------------------------------------------- HTTPS website rules

private enum class HttpsListTarget { SKIP, ONLY }

/**
 * The two website lists behind "Lọc HTTPS".
 *
 * AdGuard calls them the website allowlist and blocklist; here the first is
 * always "leave these alone" and the second only applies when the inverse
 * switch is on, which the copy says instead of relying on a label.
 */
@Composable
private fun HttpsWebsiteSection(
    settings: ProtectionSettings,
    onAddSkip: () -> Unit,
    onRemoveSkip: (String) -> Unit,
    onOnlyModeChange: (Boolean) -> Unit,
    onAddOnly: () -> Unit,
    onRemoveOnly: (String) -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("https_website_rules"),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(
                text = stringResource(R.string.settings_https_sites_title),
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextPrimary,
            )
            Text(
                text = stringResource(R.string.settings_https_sites_body),
                fontSize = 11.sp,
                color = AdGuardTextMuted,
            )

            Spacer(modifier = Modifier.height(10.dp))

            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.settings_https_only_title),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardTextPrimary,
                    )
                    Text(
                        text = stringResource(R.string.settings_https_only_subtitle),
                        fontSize = 11.sp,
                        color = AdGuardTextMuted,
                    )
                }
                Switch(
                    checked = settings.httpsOnlyMode,
                    onCheckedChange = onOnlyModeChange,
                    colors = SwitchDefaults.colors(checkedTrackColor = AdGuardGreenPrimary),
                )
            }

            HttpsHostList(
                label = stringResource(
                    if (settings.httpsOnlyMode) R.string.settings_https_only_list
                    else R.string.settings_https_skip_list
                ),
                hint = stringResource(
                    if (settings.httpsOnlyMode) R.string.settings_https_only_hint
                    else R.string.settings_https_skip_hint
                ),
                hosts = if (settings.httpsOnlyMode) settings.httpsOnlyHosts else settings.httpsSkipHosts,
                onAdd = if (settings.httpsOnlyMode) onAddOnly else onAddSkip,
                onRemove = if (settings.httpsOnlyMode) onRemoveOnly else onRemoveSkip,
            )

            if (settings.httpsOnlyMode) {
                HttpsHostList(
                    label = stringResource(R.string.settings_https_always_skip),
                    hint = stringResource(R.string.settings_https_always_skip_hint),
                    hosts = settings.httpsSkipHosts,
                    onAdd = onAddSkip,
                    onRemove = onRemoveSkip,
                )
            } else if (settings.httpsOnlyHosts.isNotEmpty()) {
                Text(
                    text = stringResource(R.string.settings_https_pending, settings.httpsOnlyHosts.size),
                    fontSize = 11.sp,
                    color = AdGuardTextMuted,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
        }
    }
}

@Composable
private fun HttpsHostList(
    label: String,
    hint: String,
    hosts: List<String>,
    onAdd: () -> Unit,
    onRemove: (String) -> Unit,
) {
    Column(modifier = Modifier.padding(top = 10.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = stringResource(R.string.settings_list_header, label, hosts.size),
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextSecondary,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = onAdd) {
                Text(stringResource(R.string.settings_https_add), fontSize = 11.sp, color = AdGuardGreenLight)
            }
        }
        Text(hint, fontSize = 11.sp, color = AdGuardTextMuted)
        if (hosts.isEmpty()) {
            Text(
                text = stringResource(R.string.settings_https_empty),
                fontSize = 11.sp,
                color = AdGuardTextMuted,
                modifier = Modifier.padding(top = 4.dp),
            )
        } else {
            hosts.forEach { host ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = host,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        color = AdGuardTextPrimary,
                        modifier = Modifier.weight(1f),
                    )
                    IconButton(onClick = { onRemove(host) }, modifier = Modifier.size(28.dp)) {
                        Icon(
                            Icons.Default.Close,
                            contentDescription = stringResource(R.string.settings_https_remove, host),
                            tint = AdGuardTextMuted,
                            modifier = Modifier.size(14.dp),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun HttpsHostDialog(
    title: String,
    onDismiss: () -> Unit,
    onAdd: (String) -> Unit,
) {
    var value by remember { mutableStateOf("") }
    val normalized = normalizeHttpsHost(value)
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title, fontSize = 16.sp, fontWeight = FontWeight.Bold) },
        text = {
            Column {
                Text(
                    text = stringResource(R.string.settings_https_dialog_body),
                    fontSize = 12.sp,
                    color = AdGuardTextSecondary,
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = value,
                    onValueChange = { value = it },
                    singleLine = true,
                    isError = value.isNotBlank() && normalized == null,
                    placeholder = { Text("example.com", fontSize = 12.sp, color = AdGuardTextMuted) },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    colors = androidx.compose.material3.OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = AdGuardGreenPrimary,
                        unfocusedBorderColor = AdGuardDarkOutline,
                        focusedTextColor = AdGuardTextPrimary,
                        unfocusedTextColor = AdGuardTextPrimary,
                    ),
                )
                if (value.isNotBlank() && normalized == null) {
                    Text(
                        text = stringResource(R.string.settings_https_dialog_invalid),
                        fontSize = 11.sp,
                        color = AdGuardOrangeWarning,
                        modifier = Modifier.padding(top = 4.dp),
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    normalized?.let {
                        onAdd(it)
                        onDismiss()
                    }
                },
                enabled = normalized != null,
            ) {
                Text(stringResource(R.string.settings_https_add), color = AdGuardGreenLight)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.common_cancel), color = AdGuardTextSecondary) }
        },
    )
}

/** `dd/MM/yyyy` for the certificate line; the device locale decides digits. */
private fun formatCertDate(ms: Long): String =
    java.text.SimpleDateFormat("dd/MM/yyyy", java.util.Locale.getDefault())
        .format(java.util.Date(ms))
