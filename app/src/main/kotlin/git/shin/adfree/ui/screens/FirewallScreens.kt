package git.shin.adfree.ui.screens

import androidx.compose.foundation.Image
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
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.CellTower
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.FlightTakeoff
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material.icons.filled.WifiOff
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
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.R
import git.shin.adfree.model.AppFirewallRule
import git.shin.adfree.model.FirewallAccess
import git.shin.adfree.model.FirewallAppChoice
import git.shin.adfree.model.ProtectionSettings
import git.shin.adfree.ui.AdGuardIntent
import git.shin.adfree.ui.AdGuardViewModel
import git.shin.adfree.ui.rememberAppIcon
import git.shin.adfree.ui.theme.AdGuardDarkBg
import git.shin.adfree.ui.theme.AdGuardDarkOutline
import git.shin.adfree.ui.theme.AdGuardDarkSurface
import git.shin.adfree.ui.theme.AdGuardDarkSurfaceVariant
import git.shin.adfree.ui.theme.AdGuardGreenLight
import git.shin.adfree.ui.theme.AdGuardGreenPrimary
import git.shin.adfree.ui.theme.AdGuardOrangeWarning
import git.shin.adfree.ui.theme.AdGuardRedBlocked
import git.shin.adfree.ui.theme.AdGuardTextMuted
import git.shin.adfree.ui.theme.AdGuardTextPrimary
import git.shin.adfree.ui.theme.AdGuardTextSecondary
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** One of the five per-network answers the firewall tracks for every app. */
private enum class FirewallDimension(
    val titleRes: Int,
    val bodyRes: Int,
    val icon: ImageVector,
    val screenOff: Boolean = false,
) {
    WIFI(R.string.firewall_rule_wifi, R.string.firewall_rule_wifi_body, Icons.Default.Wifi),
    WIFI_SCREEN_OFF(
        R.string.firewall_rule_wifi_screen_off,
        R.string.firewall_rule_screen_off_body,
        Icons.Default.Wifi,
        screenOff = true,
    ),
    CELLULAR(
        R.string.firewall_rule_cellular,
        R.string.firewall_rule_cellular_body,
        Icons.Default.CellTower,
    ),
    CELLULAR_SCREEN_OFF(
        R.string.firewall_rule_cellular_screen_off,
        R.string.firewall_rule_screen_off_body,
        Icons.Default.CellTower,
        screenOff = true,
    ),
    ROAMING(
        R.string.firewall_rule_roaming,
        R.string.firewall_rule_roaming_body,
        Icons.Default.FlightTakeoff,
    ),
}

private fun FirewallDimension.accessIn(rule: AppFirewallRule): FirewallAccess = when (this) {
    FirewallDimension.WIFI -> rule.wifiAccess
    FirewallDimension.WIFI_SCREEN_OFF -> rule.wifiScreenOffAccess
    FirewallDimension.CELLULAR -> rule.cellularAccess
    FirewallDimension.CELLULAR_SCREEN_OFF -> rule.cellularScreenOffAccess
    FirewallDimension.ROAMING -> rule.roamingAccess
}

private fun FirewallDimension.updateIntent(
    packageName: String,
    appName: String?,
    access: FirewallAccess,
): AdGuardIntent = when (this) {
    FirewallDimension.WIFI ->
        AdGuardIntent.UpdateAppFirewall(packageName, appName, wifi = access)
    FirewallDimension.WIFI_SCREEN_OFF ->
        AdGuardIntent.UpdateAppFirewall(packageName, appName, wifiScreenOff = access)
    FirewallDimension.CELLULAR ->
        AdGuardIntent.UpdateAppFirewall(packageName, appName, cellular = access)
    FirewallDimension.CELLULAR_SCREEN_OFF ->
        AdGuardIntent.UpdateAppFirewall(packageName, appName, cellularScreenOff = access)
    FirewallDimension.ROAMING ->
        AdGuardIntent.UpdateAppFirewall(packageName, appName, roaming = access)
}

private fun FirewallDimension.globalAllowed(settings: ProtectionSettings): Boolean = when (this) {
    FirewallDimension.WIFI -> settings.firewallAllowWifi
    FirewallDimension.WIFI_SCREEN_OFF -> settings.firewallAllowWifiScreenOff
    FirewallDimension.CELLULAR -> settings.firewallAllowCellular
    FirewallDimension.CELLULAR_SCREEN_OFF -> settings.firewallAllowCellularScreenOff
    FirewallDimension.ROAMING -> settings.firewallAllowRoaming
}

private fun FirewallDimension.globalIntent(enabled: Boolean): AdGuardIntent =
    when (this) {
        FirewallDimension.WIFI -> AdGuardIntent.UpdateFirewallSettings(allowWifi = enabled)
        FirewallDimension.WIFI_SCREEN_OFF ->
            AdGuardIntent.UpdateFirewallSettings(allowWifiScreenOff = enabled)
        FirewallDimension.CELLULAR ->
            AdGuardIntent.UpdateFirewallSettings(allowCellular = enabled)
        FirewallDimension.CELLULAR_SCREEN_OFF ->
            AdGuardIntent.UpdateFirewallSettings(allowCellularScreenOff = enabled)
        FirewallDimension.ROAMING ->
            AdGuardIntent.UpdateFirewallSettings(allowRoaming = enabled)
    }

/** The effective answer after global defaults and rule-set gates are applied. */
private fun FirewallDimension.isAllowed(
    rule: AppFirewallRule,
    settings: ProtectionSettings,
): Boolean {
    if (!settings.isFirewallEnabled) return true
    if (settings.firewallCustomRules) {
        when (accessIn(rule)) {
            FirewallAccess.ALLOW -> return true
            FirewallAccess.BLOCK -> return false
            FirewallAccess.INHERIT -> Unit
        }
    }
    return !settings.firewallGlobalRules || globalAllowed(settings)
}

// ----------------------------------------------------------- global rules

@Composable
internal fun FirewallGlobalDetail(
    viewModel: AdGuardViewModel,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsState()
    val settings = state.settings

    DetailScaffold(onBack = onBack, modifier = modifier) {
        ModuleDetailHero(
            icon = Icons.Default.Shield,
            tint = AdGuardGreenPrimary,
            title = stringResource(R.string.firewall_global_title),
            subtitle = stringResource(R.string.firewall_global_subtitle),
        )

        SettingsSwitch(
            icon = Icons.Default.Shield,
            title = stringResource(R.string.firewall_global_title),
            subtitle = stringResource(R.string.firewall_global_subtitle),
            checked = settings.firewallGlobalRules,
            onCheckedChange = {
                viewModel.onIntent(AdGuardIntent.UpdateFirewallSettings(globalRules = it))
            },
        )

        Spacer(modifier = Modifier.height(18.dp))

        FirewallDimension.entries.forEachIndexed { index, dimension ->
            if (index > 0) Spacer(modifier = Modifier.height(10.dp))
            SettingsSwitch(
                icon = dimension.icon,
                title = stringResource(dimension.titleRes),
                subtitle = stringResource(dimension.bodyRes),
                checked = dimension.globalAllowed(settings),
                enabled = settings.firewallGlobalRules,
                onCheckedChange = { viewModel.onIntent(dimension.globalIntent(it)) },
            )
        }
    }
}

// ----------------------------------------------------------- custom rules

@Composable
internal fun FirewallCustomDetail(
    viewModel: AdGuardViewModel,
    onBack: () -> Unit,
    onOpenApp: (packageName: String, appName: String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsState()
    val settings = state.settings
    val overrides = state.allAppFirewallRules.filter { it.hasNetworkRules }
    var showPicker by rememberSaveable { mutableStateOf(false) }

    DetailScaffold(onBack = onBack, modifier = modifier) {
        ModuleDetailHero(
            icon = Icons.Default.Apps,
            tint = AdGuardGreenLight,
            title = stringResource(R.string.firewall_custom_title),
            subtitle = stringResource(R.string.firewall_custom_subtitle),
        )

        SettingsSwitch(
            icon = Icons.Default.Apps,
            title = stringResource(R.string.firewall_custom_master),
            subtitle = stringResource(R.string.firewall_custom_subtitle),
            checked = settings.firewallCustomRules,
            onCheckedChange = {
                viewModel.onIntent(AdGuardIntent.UpdateFirewallSettings(customRules = it))
            },
        )

        Spacer(modifier = Modifier.height(18.dp))

        Text(
            text = stringResource(R.string.firewall_custom_apps_header),
            fontSize = 13.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextSecondary,
        )

        Spacer(modifier = Modifier.height(8.dp))

        if (overrides.isEmpty()) {
            Text(
                text = stringResource(R.string.firewall_custom_empty),
                fontSize = 12.sp,
                color = AdGuardTextMuted,
            )
            Spacer(modifier = Modifier.height(10.dp))
        } else {
            overrides.forEach { app ->
                OverrideAppRow(
                    app = app,
                    onClick = { onOpenApp(app.packageName, app.appName) },
                )
                Spacer(modifier = Modifier.height(8.dp))
            }
        }

        NavigationRow(
            icon = Icons.Default.Add,
            accent = AdGuardGreenPrimary,
            title = stringResource(R.string.firewall_add_app),
            subtitle = stringResource(R.string.firewall_picker_body),
            onClick = { showPicker = true },
        )
    }

    if (showPicker) {
        FirewallAppPickerSheet(
            viewModel = viewModel,
            onSelect = { choice ->
                showPicker = false
                viewModel.onIntent(
                    AdGuardIntent.EnsureFirewallApp(choice.packageName, choice.appName),
                )
                onOpenApp(choice.packageName, choice.appName)
            },
            onDismiss = { showPicker = false },
        )
    }
}

@Composable
private fun OverrideAppRow(app: AppFirewallRule, onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        border = CardDefaults.outlinedCardBorder().copy(
            brush = androidx.compose.ui.graphics.SolidColor(AdGuardDarkOutline),
        ),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            AppAvatar(packageName = app.packageName)
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = app.appName,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = AdGuardTextPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = overrideSummary(app),
                    fontSize = 11.sp,
                    color = AdGuardTextSecondary,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}

@Composable
private fun overrideSummary(app: AppFirewallRule): String {
    val parts = buildList {
        FirewallDimension.entries.forEach { dimension ->
            val access = dimension.accessIn(app)
            if (access != FirewallAccess.INHERIT) {
                add("${stringResource(dimension.titleRes)}: ${firewallAccessLabel(access)}")
            }
        }
    }
    return parts.joinToString(" · ")
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FirewallAppPickerSheet(
    viewModel: AdGuardViewModel,
    onSelect: (FirewallAppChoice) -> Unit,
    onDismiss: () -> Unit,
) {
    var query by rememberSaveable { mutableStateOf("") }
    var showSystem by rememberSaveable { mutableStateOf(true) }
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val apps by produceState(initialValue = emptyList<FirewallAppChoice>()) {
        value = withContext(Dispatchers.IO) { viewModel.installedAppsForFirewall() }
    }
    val filtered = remember(apps, query) {
        apps.filter {
            query.isBlank() ||
                it.appName.contains(query, true) ||
                it.packageName.contains(query, true)
        }
    }
    val userApps = filtered.filter { !it.isSystem }
    val systemApps = filtered.filter { it.isSystem }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = AdGuardDarkSurface,
        contentColor = AdGuardTextPrimary,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp)
                .padding(bottom = 24.dp),
        ) {
            Text(
                text = stringResource(R.string.firewall_picker_title),
                fontSize = 19.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextPrimary,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth(),
            )
            Text(
                text = stringResource(R.string.firewall_picker_body),
                fontSize = 12.sp,
                color = AdGuardTextMuted,
                textAlign = TextAlign.Center,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 4.dp),
            )

            Spacer(modifier = Modifier.height(14.dp))

            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                placeholder = {
                    Text(stringResource(R.string.firewall_picker_search), color = AdGuardTextMuted)
                },
                leadingIcon = {
                    Icon(Icons.Default.Search, contentDescription = null, tint = AdGuardTextMuted)
                },
                trailingIcon = {
                    if (query.isNotEmpty()) {
                        IconButton(onClick = { query = "" }) {
                            Icon(
                                Icons.Default.Clear,
                                contentDescription = stringResource(R.string.common_clear_search),
                                tint = AdGuardTextMuted,
                            )
                        }
                    }
                },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedContainerColor = AdGuardDarkSurfaceVariant,
                    unfocusedContainerColor = AdGuardDarkSurfaceVariant,
                    focusedBorderColor = AdGuardGreenPrimary,
                    unfocusedBorderColor = AdGuardDarkOutline,
                    focusedTextColor = AdGuardTextPrimary,
                    unfocusedTextColor = AdGuardTextPrimary,
                ),
            )

            Spacer(modifier = Modifier.height(8.dp))

            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 480.dp),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                items(userApps, key = { it.packageName }) { app ->
                    PickerAppRow(app = app, onClick = { onSelect(app) })
                }
                if (systemApps.isNotEmpty()) {
                    item(key = "system-header") {
                        SystemAppsHeader(
                            expanded = showSystem || query.isNotBlank(),
                            onClick = { showSystem = !showSystem },
                        )
                    }
                    if (showSystem || query.isNotBlank()) {
                        items(systemApps, key = { it.packageName }) { app ->
                            PickerAppRow(app = app, onClick = { onSelect(app) })
                        }
                    }
                }
                if (filtered.isEmpty()) {
                    item(key = "empty") {
                        Text(
                            text = stringResource(R.string.firewall_picker_empty),
                            fontSize = 12.sp,
                            color = AdGuardTextMuted,
                            modifier = Modifier.padding(vertical = 16.dp),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun SystemAppsHeader(expanded: Boolean, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 8.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(Icons.Default.Apps, contentDescription = null, tint = AdGuardTextMuted)
        Spacer(modifier = Modifier.width(12.dp))
        Text(
            text = stringResource(R.string.firewall_picker_system),
            fontSize = 13.sp,
            fontWeight = FontWeight.SemiBold,
            color = AdGuardTextSecondary,
            modifier = Modifier.weight(1f),
        )
        Icon(
            imageVector = if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
            contentDescription = stringResource(
                if (expanded) R.string.firewall_picker_collapse else R.string.firewall_picker_expand,
            ),
            tint = AdGuardTextMuted,
        )
    }
}

@Composable
private fun PickerAppRow(app: FirewallAppChoice, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 8.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        AppAvatar(packageName = app.packageName, size = 34)
        Spacer(modifier = Modifier.width(12.dp))
        Text(
            text = app.appName,
            fontSize = 13.sp,
            color = AdGuardTextPrimary,
            modifier = Modifier.weight(1f),
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        Icon(
            imageVector = Icons.Default.ChevronRight,
            contentDescription = null,
            tint = AdGuardTextMuted,
            modifier = Modifier.size(18.dp),
        )
    }
}

// ----------------------------------------------------------- per-app rule

@Composable
internal fun FirewallAppRuleDetail(
    viewModel: AdGuardViewModel,
    packageName: String,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsState()
    val app = state.allAppFirewallRules.firstOrNull { it.packageName == packageName }

    DetailScaffold(onBack = onBack, modifier = modifier) {
        if (app == null) {
            Text(
                text = stringResource(R.string.firewall_custom_empty),
                fontSize = 12.sp,
                color = AdGuardTextMuted,
            )
            return@DetailScaffold
        }

        AppRuleHeader(app = app)
        Spacer(modifier = Modifier.height(10.dp))
        FirewallNetworkStrip(rule = app, settings = state.settings, centered = true)
        Spacer(modifier = Modifier.height(16.dp))

        SettingsSwitch(
            icon = Icons.Default.Notifications,
            title = stringResource(R.string.firewall_app_notify_title),
            subtitle = stringResource(R.string.firewall_app_notify_body),
            checked = app.notifyBlocked,
            onCheckedChange = {
                viewModel.onIntent(
                    AdGuardIntent.UpdateAppFirewall(
                        packageName = app.packageName,
                        appName = app.appName,
                        notifyBlocked = it,
                    ),
                )
            },
        )

        Spacer(modifier = Modifier.height(18.dp))

        Text(
            text = stringResource(R.string.firewall_app_applied_header),
            fontSize = 13.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextSecondary,
        )
        Spacer(modifier = Modifier.height(8.dp))

        val applied = FirewallDimension.entries.filter {
            it.accessIn(app) != FirewallAccess.INHERIT
        }
        if (applied.isEmpty()) {
            Text(
                text = stringResource(R.string.firewall_app_applied_empty),
                fontSize = 12.sp,
                color = AdGuardTextMuted,
            )
        } else {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    applied.forEachIndexed { index, dimension ->
                        if (index > 0) Spacer(modifier = Modifier.height(14.dp))
                        FirewallAccessRow(
                            title = stringResource(dimension.titleRes),
                            subtitle = stringResource(dimension.bodyRes),
                            access = dimension.accessIn(app),
                            onSelect = {
                                viewModel.onIntent(
                                    dimension.updateIntent(app.packageName, app.appName, it),
                                )
                            },
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(18.dp))

        Text(
            text = stringResource(R.string.firewall_app_available_header),
            fontSize = 13.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextSecondary,
        )
        Spacer(modifier = Modifier.height(8.dp))

        val available = FirewallDimension.entries.filter {
            it.accessIn(app) == FirewallAccess.INHERIT
        }
        if (available.isEmpty()) {
            Text(
                text = stringResource(R.string.firewall_app_applied_empty),
                fontSize = 12.sp,
                color = AdGuardTextMuted,
            )
        } else {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
            ) {
                Column {
                    available.forEach { dimension ->
                        AvailableRuleRow(
                            title = stringResource(dimension.titleRes),
                            onClick = {
                                viewModel.onIntent(
                                    dimension.updateIntent(
                                        app.packageName,
                                        app.appName,
                                        FirewallAccess.BLOCK,
                                    ),
                                )
                            },
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun AvailableRuleRow(title: String, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(Icons.Default.Add, contentDescription = null, tint = AdGuardGreenPrimary)
        Spacer(modifier = Modifier.width(12.dp))
        Text(title, fontSize = 13.sp, color = AdGuardGreenLight)
    }
}

@Composable
private fun AppRuleHeader(app: AppFirewallRule) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        AppAvatar(packageName = app.packageName, size = 56)
        Spacer(modifier = Modifier.height(10.dp))
        Text(
            text = app.appName,
            fontSize = 19.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextPrimary,
            textAlign = TextAlign.Center,
        )
        Text(
            text = app.packageName,
            fontSize = 11.sp,
            fontFamily = FontFamily.Monospace,
            color = AdGuardTextMuted,
        )
        Text(
            text = stringResource(R.string.firewall_app_subtitle),
            fontSize = 12.sp,
            color = AdGuardTextSecondary,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(top = 4.dp),
        )
    }
}

/** The five network glyphs; colour carries allow/block at a glance. */
@Composable
internal fun FirewallNetworkStrip(
    rule: AppFirewallRule,
    settings: ProtectionSettings,
    centered: Boolean = false,
) {
    Row(
        modifier = if (centered) {
            Modifier
                .fillMaxWidth()
                .padding(top = 6.dp)
        } else {
            Modifier.padding(top = 4.dp)
        },
        horizontalArrangement = if (centered) Arrangement.Center else Arrangement.Start,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        FirewallDimension.entries.forEach { dimension ->
            val allowed = dimension.isAllowed(rule, settings)
            NetworkGlyph(
                icon = dimension.icon,
                screenOff = dimension.screenOff,
                tint = if (allowed) AdGuardGreenLight else AdGuardRedBlocked,
                description = stringResource(dimension.titleRes),
            )
            Spacer(modifier = Modifier.width(14.dp))
        }
    }
}

@Composable
private fun NetworkGlyph(
    icon: ImageVector,
    screenOff: Boolean,
    tint: Color,
    description: String,
) {
    Box(modifier = Modifier.size(22.dp), contentAlignment = Alignment.Center) {
        Icon(
            imageVector = icon,
            contentDescription = description,
            tint = tint,
            modifier = Modifier.size(18.dp),
        )
        if (screenOff) {
            Icon(
                imageVector = Icons.Default.DarkMode,
                contentDescription = null,
                tint = tint,
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .size(9.dp),
            )
        }
    }
}

@Composable
private fun AppAvatar(packageName: String, size: Int = 40) {
    Box(
        modifier = Modifier
            .size(size.dp)
            .clip(RoundedCornerShape((size / 4).dp))
            .background(AdGuardDarkSurfaceVariant),
        contentAlignment = Alignment.Center,
    ) {
        val icon = rememberAppIcon(packageName)
        if (icon != null) {
            Image(
                bitmap = icon,
                contentDescription = null,
                modifier = Modifier.size((size - 8).dp),
            )
        } else {
            Icon(
                imageVector = Icons.Default.Apps,
                contentDescription = null,
                tint = AdGuardGreenLight,
                modifier = Modifier.size((size / 2).dp),
            )
        }
    }
}

// ----------------------------------------------------------- quick actions

private data class QuickActionApp(
    val packageName: String,
    val appName: String,
    val lastSeenMs: Long,
)

@Composable
internal fun FirewallQuickActionsDetail(
    viewModel: AdGuardViewModel,
    onBack: () -> Unit,
    onOpenAppRule: (packageName: String, appName: String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsState()
    var query by rememberSaveable { mutableStateOf("") }
    val rules = remember(state.allAppFirewallRules) {
        state.allAppFirewallRules.associateBy { it.packageName }
    }
    val recent = remember(state.logs, state.allAppFirewallRules, state.appNames) {
        val names = state.allAppFirewallRules.associate { it.packageName to it.appName }
        state.logs.asSequence()
            .mapNotNull { log ->
                val pkg = log.appPackage?.takeIf { it.isNotBlank() } ?: return@mapNotNull null
                pkg to log.timestampMs
            }
            .groupBy({ it.first }, { it.second })
            .map { (pkg, times) ->
                QuickActionApp(
                    packageName = pkg,
                    appName = names[pkg] ?: state.appNames[pkg] ?: pkg,
                    lastSeenMs = times.max(),
                )
            }
            .sortedByDescending { it.lastSeenMs }
            .toList()
    }
    val filtered = remember(recent, query) {
        if (query.isBlank()) {
            recent
        } else {
            recent.filter {
                it.appName.contains(query, true) || it.packageName.contains(query, true)
            }
        }
    }

    FirewallListScaffold(onBack = onBack) {
        item(key = "hero") {
            ModuleDetailHero(
                icon = Icons.Default.History,
                tint = AdGuardGreenPrimary,
                title = stringResource(R.string.firewall_quick_title),
                subtitle = stringResource(R.string.firewall_quick_subtitle),
            )
        }
        item(key = "search") {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                placeholder = {
                    Text(stringResource(R.string.firewall_quick_search), color = AdGuardTextMuted)
                },
                leadingIcon = {
                    Icon(Icons.Default.Search, contentDescription = null, tint = AdGuardTextMuted)
                },
                trailingIcon = {
                    if (query.isNotEmpty()) {
                        IconButton(onClick = { query = "" }) {
                            Icon(
                                Icons.Default.Clear,
                                contentDescription = stringResource(R.string.common_clear_search),
                                tint = AdGuardTextMuted,
                            )
                        }
                    }
                },
                singleLine = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 4.dp),
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedContainerColor = AdGuardDarkSurface,
                    unfocusedContainerColor = AdGuardDarkSurface,
                    focusedBorderColor = AdGuardGreenPrimary,
                    unfocusedBorderColor = AdGuardDarkOutline,
                    focusedTextColor = AdGuardTextPrimary,
                    unfocusedTextColor = AdGuardTextPrimary,
                ),
            )
        }
        if (filtered.isEmpty()) {
            item(key = "empty") {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 32.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Text(
                        text = stringResource(R.string.firewall_quick_empty_title),
                        fontSize = 15.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = AdGuardTextPrimary,
                    )
                    Text(
                        text = stringResource(R.string.firewall_quick_empty_body),
                        fontSize = 12.sp,
                        color = AdGuardTextMuted,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(top = 4.dp),
                    )
                }
            }
        } else {
            items(filtered, key = { it.packageName }) { entry ->
                val rule = rules[entry.packageName] ?: AppFirewallRule(
                    packageName = entry.packageName,
                    appName = entry.appName,
                )
                QuickActionCard(
                    entry = entry,
                    rule = rule,
                    settings = state.settings,
                    onBlock = {
                        val blocked = FirewallDimension.entries.all {
                            it.accessIn(rule) == FirewallAccess.BLOCK
                        }
                        val target = if (blocked) {
                            FirewallAccess.INHERIT
                        } else {
                            FirewallAccess.BLOCK
                        }
                        viewModel.onIntent(
                            AdGuardIntent.UpdateAppFirewall(
                                packageName = entry.packageName,
                                appName = entry.appName,
                                wifi = target,
                                wifiScreenOff = target,
                                cellular = target,
                                cellularScreenOff = target,
                                roaming = target,
                            ),
                        )
                    },
                    onOpenRule = {
                        viewModel.onIntent(
                            AdGuardIntent.EnsureFirewallApp(entry.packageName, entry.appName),
                        )
                        onOpenAppRule(entry.packageName, entry.appName)
                    },
                    onOpenManagement = {
                        viewModel.onIntent(
                            AdGuardIntent.EnsureFirewallApp(entry.packageName, entry.appName),
                        )
                        viewModel.onIntent(AdGuardIntent.OpenAppManagement(rule))
                    },
                    onOpenActivity = {
                        viewModel.onIntent(AdGuardIntent.ViewAppLogs(rule))
                    },
                    onToggleMute = {
                        viewModel.onIntent(
                            AdGuardIntent.UpdateAppFirewall(
                                packageName = entry.packageName,
                                appName = entry.appName,
                                notifyBlocked = !rule.notifyBlocked,
                            ),
                        )
                    },
                )
            }
        }
    }
}

@Composable
private fun QuickActionCard(
    entry: QuickActionApp,
    rule: AppFirewallRule,
    settings: ProtectionSettings,
    onBlock: () -> Unit,
    onOpenRule: () -> Unit,
    onOpenManagement: () -> Unit,
    onOpenActivity: () -> Unit,
    onToggleMute: () -> Unit,
) {
    val wifiAllowed = FirewallDimension.WIFI.isAllowed(rule, settings)
    val blocked = FirewallDimension.entries.all { it.accessIn(rule) == FirewallAccess.BLOCK }
    var menuOpen by remember { mutableStateOf(false) }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        border = CardDefaults.outlinedCardBorder().copy(
            brush = androidx.compose.ui.graphics.SolidColor(AdGuardDarkOutline),
        ),
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = relativeAge(entry.lastSeenMs),
                    fontSize = 11.sp,
                    color = AdGuardTextMuted,
                    modifier = Modifier.weight(1f),
                )
                Box {
                    IconButton(
                        onClick = { menuOpen = true },
                        modifier = Modifier.size(28.dp),
                    ) {
                        Icon(
                            Icons.Default.MoreVert,
                            contentDescription = stringResource(
                                R.string.firewall_quick_overflow,
                                entry.appName,
                            ),
                            tint = AdGuardTextMuted,
                        )
                    }
                    DropdownMenu(
                        expanded = menuOpen,
                        onDismissRequest = { menuOpen = false },
                    ) {
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.firewall_quick_recent_activity)) },
                            onClick = {
                                menuOpen = false
                                onOpenActivity()
                            },
                        )
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.firewall_quick_app_rule)) },
                            onClick = {
                                menuOpen = false
                                onOpenRule()
                            },
                        )
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.firewall_quick_manage_app)) },
                            onClick = {
                                menuOpen = false
                                onOpenManagement()
                            },
                        )
                        DropdownMenuItem(
                            text = {
                                Text(
                                    stringResource(
                                        if (rule.notifyBlocked) {
                                            R.string.firewall_quick_mute
                                        } else {
                                            R.string.firewall_quick_unmute
                                        },
                                    ),
                                )
                            },
                            onClick = {
                                menuOpen = false
                                onToggleMute()
                            },
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(4.dp))

            Row(verticalAlignment = Alignment.CenterVertically) {
                AppAvatar(packageName = entry.packageName, size = 36)
                Spacer(modifier = Modifier.width(10.dp))
                Text(
                    text = entry.appName,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = if (wifiAllowed) Icons.Default.Wifi else Icons.Default.WifiOff,
                    contentDescription = null,
                    tint = if (wifiAllowed) AdGuardGreenLight else AdGuardRedBlocked,
                    modifier = Modifier.size(16.dp),
                )
                Spacer(modifier = Modifier.width(8.dp))
                Column {
                    Text(
                        text = stringResource(
                            if (wifiAllowed) {
                                R.string.firewall_quick_has_wifi
                            } else {
                                R.string.firewall_quick_no_wifi
                            },
                        ),
                        fontSize = 12.sp,
                        color = AdGuardTextPrimary,
                    )
                    Text(
                        text = quickRuleReason(rule, settings),
                        fontSize = 11.sp,
                        color = AdGuardTextMuted,
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            Button(
                onClick = onBlock,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(40.dp),
                shape = RoundedCornerShape(8.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = AdGuardOrangeWarning,
                    contentColor = Color.White,
                ),
            ) {
                Text(
                    text = stringResource(
                        if (blocked) R.string.firewall_quick_unblock else R.string.firewall_quick_block,
                    ),
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                )
            }
        }
    }
}

@Composable
private fun quickRuleReason(rule: AppFirewallRule, settings: ProtectionSettings): String = when {
    !settings.isFirewallEnabled -> stringResource(R.string.firewall_quick_firewall_off)
    settings.firewallCustomRules && rule.wifiAccess == FirewallAccess.BLOCK ->
        stringResource(R.string.firewall_quick_rule_blocked)
    else -> stringResource(R.string.firewall_quick_allowed_global)
}

@Composable
private fun relativeAge(timestampMs: Long): String {
    val minutes = ((System.currentTimeMillis() - timestampMs) / 60_000L).coerceAtLeast(0L)
    return when {
        minutes < 1 -> stringResource(R.string.firewall_quick_ago_now)
        minutes < 60 -> stringResource(R.string.firewall_quick_ago_minutes, minutes)
        minutes < 24 * 60 -> stringResource(R.string.firewall_quick_ago_hours, minutes / 60)
        else -> stringResource(R.string.firewall_quick_ago_days, minutes / (24 * 60))
    }
}

// ----------------------------------------------------------- notifications

@Composable
internal fun FirewallNotificationsDetail(
    viewModel: AdGuardViewModel,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsState()
    val settings = state.settings
    // Notifications cover every app the firewall can block, not only the ones
    // with a rule: a row without an override inherits "on".
    val installed by produceState(initialValue = emptyList<FirewallAppChoice>()) {
        value = withContext(Dispatchers.IO) { viewModel.installedAppsForFirewall() }
    }
    val rules = remember(state.allAppFirewallRules) {
        state.allAppFirewallRules.associateBy { it.packageName }
    }
    val apps = remember(installed, rules) {
        installed.map { choice ->
            rules[choice.packageName] ?: AppFirewallRule(
                packageName = choice.packageName,
                appName = choice.appName,
            )
        }
    }

    FirewallListScaffold(onBack = onBack, trailing = null) {
        item(key = "hero") {
            ModuleDetailHero(
                icon = Icons.Default.Notifications,
                tint = AdGuardOrangeWarning,
                title = stringResource(R.string.firewall_notifications_title),
                subtitle = stringResource(R.string.firewall_notifications_body),
            )
        }
        item(key = "master") {
            SettingsSwitch(
                icon = Icons.Default.Notifications,
                title = stringResource(R.string.firewall_notifications_title),
                subtitle = stringResource(R.string.firewall_notifications_body),
                checked = settings.firewallNotifications,
                onCheckedChange = {
                    viewModel.onIntent(AdGuardIntent.UpdateFirewallSettings(notifications = it))
                },
            )
        }
        if (apps.isNotEmpty()) {
            items(apps, key = { it.packageName }) { app ->
                NotificationAppRow(
                    app = app,
                    enabled = settings.firewallNotifications,
                    onToggle = {
                        viewModel.onIntent(
                            AdGuardIntent.UpdateAppFirewall(
                                packageName = app.packageName,
                                appName = app.appName,
                                notifyBlocked = it,
                            ),
                        )
                    },
                )
            }
        }
    }
}

@Composable
private fun NotificationAppRow(
    app: AppFirewallRule,
    enabled: Boolean,
    onToggle: (Boolean) -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            AppAvatar(packageName = app.packageName, size = 34)
            Spacer(modifier = Modifier.width(10.dp))
            Text(
                text = app.appName,
                fontSize = 13.sp,
                color = AdGuardTextPrimary,
                modifier = Modifier.weight(1f),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Switch(
                checked = app.notifyBlocked,
                onCheckedChange = onToggle,
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

// ----------------------------------------------------------- shared list

@Composable
private fun FirewallListScaffold(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    trailing: (@Composable () -> Unit)? = null,
    content: LazyListScope.() -> Unit,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .background(AdGuardDarkBg),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) {
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = stringResource(R.string.hub_back),
                    tint = AdGuardTextPrimary,
                )
            }
            Spacer(modifier = Modifier.weight(1f))
            trailing?.invoke()
        }
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp),
            contentPadding = PaddingValues(bottom = 64.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            content()
        }
    }
}
