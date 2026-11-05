package git.shin.adfree.ui.screens

import git.shin.adfree.l10n.L10n
import git.shin.adfree.l10n.Strings
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
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.SettingsBackupRestore
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.RadioButton
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.model.DnsBackup
import git.shin.adfree.model.DnsBackupMode
import git.shin.adfree.model.DnsBlockMode
import git.shin.adfree.model.DnsProvider
import git.shin.adfree.model.ProtocolType
import git.shin.adfree.model.ProxySettings
import git.shin.adfree.model.normalizeProxyHost
import git.shin.adfree.model.probeAddress
import git.shin.adfree.ui.AdGuardIntent
import git.shin.adfree.ui.AdGuardViewModel
import git.shin.adfree.ui.theme.AdGuardBlueDns
import git.shin.adfree.ui.theme.AdGuardDarkBg
import git.shin.adfree.ui.theme.AdGuardDarkOutline
import git.shin.adfree.ui.theme.AdGuardDarkSurface
import git.shin.adfree.ui.theme.AdGuardGreenPrimary
import git.shin.adfree.ui.theme.AdGuardOrangeWarning
import git.shin.adfree.ui.theme.AdGuardRedBlocked
import git.shin.adfree.ui.theme.AdGuardTextMuted
import git.shin.adfree.ui.theme.AdGuardTextPrimary
import git.shin.adfree.ui.theme.AdGuardOnAccent
import git.shin.adfree.ui.theme.AdGuardTextSecondary

/**
 * Full-screen DNS module: which resolver sees the names, how blocked answers
 * look, what may leave the tunnel, and where the flows are routed.
 */
@Composable
fun NetworkScreen(
    viewModel: AdGuardViewModel,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsState()
    val privateDnsOn by viewModel.privateDnsOn.collectAsState()

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(AdGuardDarkBg),
    ) {
        IconButton(onClick = onBack) {
            Icon(
                imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                contentDescription = L10n.get(Strings.hub_back),
                tint = AdGuardTextPrimary,
            )
        }

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp),
        ) {
            ModuleDetailHero(
                icon = Icons.Default.Dns,
                tint = AdGuardBlueDns,
                title = L10n.get(Strings.network_title),
                subtitle = L10n.get(Strings.network_subtitle),
            )

            SettingsSwitch(
                icon = Icons.Default.Dns,
                title = L10n.get(Strings.home_module_dns_title),
                subtitle = L10n.get(Strings.home_module_dns_subtitle),
                checked = state.settings.isDnsProtectionEnabled,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleDns) },
            )

            Spacer(modifier = Modifier.height(18.dp))

            DnsProviderSection(
                providers = state.dnsProviders,
                selectedId = state.settings.selectedDnsProviderId,
                isProbing = state.isDnsProbeRunning,
                onSelect = { viewModel.onIntent(AdGuardIntent.SelectDnsProvider(it)) },
                onAdd = { name, address, type ->
                    viewModel.onIntent(AdGuardIntent.AddCustomDnsProvider(name, address, type))
                },
                onProbe = { viewModel.onIntent(AdGuardIntent.ProbeDnsProvider(it)) },
            )

            Spacer(modifier = Modifier.height(18.dp))

            DnsBackupSection(
                providers = state.dnsProviders,
                backup = state.dnsBackup,
                mode = state.dnsBackupMode,
                onSelect = { mode, id ->
                    viewModel.onIntent(AdGuardIntent.SetBackupDns(mode, id))
                },
            )

            Spacer(modifier = Modifier.height(18.dp))

            Text(
                text = L10n.get(Strings.settings_block_mode_title),
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextSecondary,
                modifier = Modifier.padding(bottom = 6.dp),
            )
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                DnsBlockMode.entries.forEach { mode ->
                    FilterChip(
                        selected = state.settings.blockMode == mode,
                        onClick = { viewModel.onIntent(AdGuardIntent.SetBlockMode(mode)) },
                        label = { Text(blockModeLabel(mode), fontSize = 11.sp) },
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = AdGuardGreenPrimary,
                            selectedLabelColor = AdGuardOnAccent,
                        ),
                    )
                }
            }

            Spacer(modifier = Modifier.height(18.dp))

            SettingsSwitch(
                icon = Icons.Default.Bolt,
                title = L10n.get(Strings.network_quic_title),
                subtitle = L10n.get(Strings.network_quic_subtitle),
                checked = state.settings.blockQuic,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleBlockQuic(it)) },
            )

            Spacer(modifier = Modifier.height(10.dp))

            SettingsSwitch(
                icon = Icons.Default.Lock,
                title = L10n.get(Strings.network_doh_title),
                subtitle = L10n.get(Strings.network_doh_subtitle),
                checked = state.settings.blockDoh,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleBlockDoh(it)) },
            )

            Spacer(modifier = Modifier.height(10.dp))

            SettingsSwitch(
                icon = Icons.Default.Dns,
                title = L10n.get(Strings.network_dot_title),
                subtitle = if (privateDnsOn) {
                    L10n.get(Strings.network_dot_private_dns)
                } else {
                    L10n.get(Strings.network_dot_subtitle)
                },
                checked = state.settings.blockDot,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleBlockDot(it)) },
            )

            Spacer(modifier = Modifier.height(18.dp))

            SettingsSwitch(
                icon = Icons.Default.Search,
                title = L10n.get(Strings.network_safe_search_title),
                subtitle = L10n.get(Strings.network_safe_search_subtitle),
                checked = state.settings.safeSearch,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleSafeSearch(it)) },
            )

            Spacer(modifier = Modifier.height(18.dp))

            DnsRewriteSection(
                rewrites = state.dnsRewrites,
                validate = viewModel::validateDnsRewrite,
                onAdd = { host, answer ->
                    viewModel.onIntent(AdGuardIntent.AddDnsRewrite(host, answer))
                },
                onRemove = { viewModel.onIntent(AdGuardIntent.RemoveDnsRewrite(it)) },
            )

            Spacer(modifier = Modifier.height(18.dp))

            ProxySection(
                viewModel = viewModel,
                saved = state.settings.proxy,
            )

            Spacer(modifier = Modifier.height(64.dp))
        }
    }
}

@Composable
private fun blockModeLabel(mode: DnsBlockMode): String = L10n.get(when (mode) {
        DnsBlockMode.NXDOMAIN -> Strings.settings_block_mode_nxdomain
        DnsBlockMode.ZERO_IP -> Strings.settings_block_mode_zero
        DnsBlockMode.REFUSED -> Strings.settings_block_mode_refused
    }
)

/**
 * AdGuard's fallback servers: one plain UDP query when the selected resolver
 * stays silent. Only UDP entries are offered because a TLS fallback would
 * share the failure it exists to cover.
 */
@Composable
private fun DnsBackupSection(
    providers: List<DnsProvider>,
    backup: DnsBackup?,
    mode: DnsBackupMode,
    onSelect: (DnsBackupMode, String?) -> Unit,
) {
    var showDialog by remember { mutableStateOf(false) }
    val udp = providers.filter { it.type == ProtocolType.DNS_UDP }
    val selected = udp.firstOrNull { backup?.matches(it) == true }

    Column {
        Text(
            text = L10n.get(Strings.network_backup_title),
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextSecondary,
            modifier = Modifier.padding(bottom = 6.dp),
        )
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
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(AdGuardBlueDns.copy(alpha = 0.12f)),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = Icons.Default.SettingsBackupRestore,
                        contentDescription = null,
                        tint = AdGuardBlueDns,
                        modifier = Modifier.size(18.dp),
                    )
                }
                Spacer(modifier = Modifier.size(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = when (mode) {
                            DnsBackupMode.SYSTEM -> L10n.get(Strings.network_backup_system)
                            DnsBackupMode.OFF -> L10n.get(Strings.network_backup_off)
                            DnsBackupMode.FIXED -> selected?.name
                                ?: backup?.let { "${it.address}:${it.port}" }
                                ?: L10n.get(Strings.network_backup_off)
                        },
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardTextPrimary,
                    )
                    Text(
                        text = when (mode) {
                            DnsBackupMode.SYSTEM ->
                                L10n.get(Strings.network_backup_system_subtitle)
                            DnsBackupMode.OFF ->
                                L10n.get(Strings.network_backup_off_subtitle)
                            DnsBackupMode.FIXED -> L10n.format(Strings.network_backup_summary,
                                selected?.address ?: backup?.address.orEmpty(),
                            )
                        },
                        fontSize = 13.sp,
                        color = AdGuardTextMuted,
                    )
                }
                Text(
                    text = L10n.get(Strings.settings_dns_change),
                    fontSize = 12.sp,
                    color = AdGuardBlueDns,
                )
            }
        }
    }

    if (showDialog) {
        AlertDialog(
            onDismissRequest = { showDialog = false },
            title = { Text(L10n.get(Strings.network_backup_title), fontSize = 18.sp) },
            text = {
                Column(
                    modifier = Modifier
                        .heightIn(max = 430.dp)
                        .verticalScroll(rememberScrollState()),
                ) {
                    Text(
                        text = L10n.get(Strings.network_backup_body),
                        fontSize = 13.sp,
                        color = AdGuardTextMuted,
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    BackupOptionRow(
                        selected = mode == DnsBackupMode.SYSTEM,
                        title = L10n.get(Strings.network_backup_system),
                        subtitle = L10n.get(Strings.network_backup_system_subtitle),
                        onSelect = {
                            onSelect(DnsBackupMode.SYSTEM, null)
                            showDialog = false
                        },
                    )
                    BackupOptionRow(
                        selected = mode == DnsBackupMode.OFF,
                        title = L10n.get(Strings.network_backup_off),
                        subtitle = L10n.get(Strings.network_backup_off_subtitle),
                        onSelect = {
                            onSelect(DnsBackupMode.OFF, null)
                            showDialog = false
                        },
                    )
                    udp.forEach { provider ->
                        BackupOptionRow(
                            selected = mode == DnsBackupMode.FIXED &&
                                backup?.matches(provider) == true,
                            title = provider.name,
                            subtitle = provider.probeAddress(),
                            onSelect = {
                                onSelect(DnsBackupMode.FIXED, provider.id)
                                showDialog = false
                            },
                        )
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = L10n.get(Strings.network_backup_udp_only),
                        fontSize = 11.sp,
                        color = AdGuardTextMuted,
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = { showDialog = false }) {
                    Text(L10n.get(Strings.common_close))
                }
            },
        )
    }
}

@Composable
private fun BackupOptionRow(
    selected: Boolean,
    title: String,
    subtitle: String,
    onSelect: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onSelect)
            .padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = onSelect)
        Column(modifier = Modifier.weight(1f)) {
            Text(title, fontSize = 15.sp, color = AdGuardTextPrimary)
            Text(subtitle, fontSize = 13.sp, color = AdGuardTextMuted)
        }
    }
}

/**
 * Routing mode: outbound SOCKS5 for TCP flows.
 *
 * The fields edit a local draft; nothing reaches the core until Save, so a
 * half-typed address never becomes a binding whose failure is only visible in
 * the log. A disabled proxy is saved as-is, which lets the user fill the
 * endpoint first and switch it on later.
 */
@Composable
private fun ProxySection(
    viewModel: AdGuardViewModel,
    saved: ProxySettings,
) {
    var draft by remember(saved) { mutableStateOf(saved) }
    var portText by remember(saved) { mutableStateOf(saved.port.toString()) }
    var error by remember(saved) { mutableStateOf<String?>(null) }

    val host = normalizeProxyHost(draft.host)
    val port = portText.toIntOrNull()

    fun save() {
        if (draft.enabled) {
            if (host == null) {
                error = Strings.network_proxy_host_error
                return
            }
            if (port == null || port !in 1..65535) {
                error = Strings.network_proxy_port_error
                return
            }
        }
        error = null
        viewModel.setProxy(
            draft.copy(
                host = host ?: draft.host.trim(),
                port = port ?: draft.port,
                username = draft.username.trim(),
            ),
        )
    }

    Column {
        Text(
            text = L10n.get(Strings.network_proxy_title),
            fontSize = 14.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextPrimary,
        )
        Text(
            text = L10n.get(Strings.network_proxy_subtitle),
            fontSize = 11.sp,
            color = AdGuardTextMuted,
        )
        Spacer(modifier = Modifier.height(10.dp))

        SettingsSwitch(
            icon = Icons.Default.Public,
            title = L10n.get(Strings.network_socks_title),
            subtitle = L10n.get(Strings.network_socks_subtitle),
            checked = draft.enabled,
            onCheckedChange = { enabled ->
                draft = draft.copy(enabled = enabled)
                error = null
            },
        )

        Spacer(modifier = Modifier.height(10.dp))

        SettingsSwitch(
            icon = Icons.Default.Language,
            title = L10n.get(Strings.network_proxy_auto_title),
            subtitle = L10n.get(Strings.network_proxy_auto_subtitle),
            checked = draft.automatic,
            onCheckedChange = { automatic ->
                draft = draft.copy(automatic = automatic)
                error = null
            },
        )

        Spacer(modifier = Modifier.height(10.dp))

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                OutlinedTextField(
                    value = draft.host,
                    onValueChange = {
                        draft = draft.copy(host = it)
                        error = null
                    },
                    label = { Text(L10n.get(Strings.network_proxy_host_label), fontSize = 11.sp) },
                    placeholder = { Text(L10n.get(Strings.network_proxy_host_hint), fontSize = 11.sp) },
                    singleLine = true,
                    isError = error != null,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    colors = proxyFieldColors(),
                )
                Spacer(modifier = Modifier.height(6.dp))
                OutlinedTextField(
                    value = portText,
                    onValueChange = {
                        portText = it.filter(Char::isDigit).take(5)
                        error = null
                    },
                    label = { Text(L10n.get(Strings.network_proxy_port_label), fontSize = 11.sp) },
                    placeholder = { Text("1080", fontSize = 11.sp) },
                    singleLine = true,
                    isError = error != null,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    colors = proxyFieldColors(),
                )
                Spacer(modifier = Modifier.height(6.dp))
                OutlinedTextField(
                    value = draft.username,
                    onValueChange = {
                        draft = draft.copy(username = it)
                        error = null
                    },
                    label = { Text(L10n.get(Strings.network_proxy_username_label), fontSize = 11.sp) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    colors = proxyFieldColors(),
                )
                Spacer(modifier = Modifier.height(6.dp))
                OutlinedTextField(
                    value = draft.password,
                    onValueChange = {
                        draft = draft.copy(password = it)
                        error = null
                    },
                    label = { Text(L10n.get(Strings.network_proxy_password_label), fontSize = 11.sp) },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    colors = proxyFieldColors(),
                )
                error?.let {
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(L10n.get(it), fontSize = 11.sp, color = AdGuardRedBlocked)
                }
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = L10n.get(Strings.network_proxy_note),
                    fontSize = 11.sp,
                    color = AdGuardTextMuted,
                )
                Spacer(modifier = Modifier.height(10.dp))
                Button(
                    onClick = { save() },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(8.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = AdGuardBlueDns),
                ) {
                    Text(
                        L10n.get(Strings.network_proxy_save),
                        color = AdGuardOnAccent,
                        fontWeight = FontWeight.Bold,
                    )
                }
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = when {
                        !saved.enabled -> L10n.get(Strings.network_proxy_off)
                        saved.isUsable -> L10n.format(Strings.network_proxy_active,
                            saved.host,
                            saved.port,
                        )
                        else -> L10n.get(Strings.network_proxy_invalid)
                    },
                    fontSize = 11.sp,
                    color = when {
                        !saved.enabled -> AdGuardTextMuted
                        saved.isUsable -> AdGuardGreenPrimary
                        else -> AdGuardOrangeWarning
                    },
                )
            }
        }
    }
}

@Composable
private fun proxyFieldColors() = OutlinedTextFieldDefaults.colors(
    focusedBorderColor = AdGuardBlueDns,
    unfocusedBorderColor = AdGuardDarkOutline,
    focusedTextColor = AdGuardTextPrimary,
    unfocusedTextColor = AdGuardTextPrimary,
    focusedLabelColor = AdGuardBlueDns,
    unfocusedLabelColor = AdGuardTextSecondary,
)
