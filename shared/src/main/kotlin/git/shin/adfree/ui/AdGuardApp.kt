package git.shin.adfree.ui

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.ListAlt
import androidx.compose.material.icons.automirrored.outlined.ListAlt
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.PieChart
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.outlined.Apps
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.PieChart
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.TextButton
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.NavigationRailItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Snackbar
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.l10n.L10n
import git.shin.adfree.l10n.Strings
import git.shin.adfree.platform.currentFileHost
import git.shin.adfree.platform.currentPlatformHost
import git.shin.adfree.ui.screens.AppsManagementScreen
import git.shin.adfree.ui.screens.FilteringLogScreen
import git.shin.adfree.ui.screens.HomeScreen
import git.shin.adfree.ui.screens.ProtectionScreen
import git.shin.adfree.ui.screens.SecurityLabScreen
import git.shin.adfree.ui.screens.SettingsScreen
import git.shin.adfree.ui.screens.StatisticsScreen
import git.shin.adfree.ui.theme.AdGuardDarkBg
import git.shin.adfree.ui.theme.AdGuardDarkOutline
import git.shin.adfree.ui.theme.AdGuardDarkSurface
import git.shin.adfree.ui.theme.AdGuardGreenPrimary
import git.shin.adfree.ui.theme.AdGuardOnAccent
import git.shin.adfree.ui.theme.AdGuardOrangeWarning
import git.shin.adfree.ui.theme.AdGuardTextMuted
import git.shin.adfree.ui.theme.AdGuardTextPrimary
import git.shin.adfree.ui.theme.AdGuardTextSecondary
import git.shin.adfree.ui.theme.LocalUiLayout
import git.shin.adfree.ui.theme.UiLayout
import git.shin.adfree.ui.theme.UiSize
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.launch

data class NavItem(
    val tab: AdGuardTab,
    val label: UiText,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector,
    val tag: String,
)

/** The bottom bar and the wide-layout side rail show the same destinations. */
@Composable
private fun defaultNavItems(): List<NavItem> {
    val platform = git.shin.adfree.platform.currentPlatformHost()
    return listOf(
        NavItem(AdGuardTab.HOME, UiText.Resource(Strings.nav_home), Icons.Filled.Home, Icons.Outlined.Home, "nav_home"),
        NavItem(AdGuardTab.PROTECTION, UiText.Resource(Strings.nav_protection), Icons.Filled.Shield, Icons.Outlined.Shield, "nav_protection"),
        NavItem(AdGuardTab.APPS, UiText.Resource(Strings.nav_apps), Icons.Filled.Apps, Icons.Outlined.Apps, "nav_apps"),
        NavItem(AdGuardTab.ACTIVITY, UiText.Resource(Strings.nav_activity), Icons.AutoMirrored.Filled.ListAlt, Icons.AutoMirrored.Outlined.ListAlt, "nav_activity"),
        NavItem(AdGuardTab.STATISTICS, UiText.Resource(Strings.nav_statistics), Icons.Filled.PieChart, Icons.Outlined.PieChart, "nav_statistics"),
        NavItem(AdGuardTab.SETTINGS, UiText.Resource(Strings.nav_settings), Icons.Filled.Settings, Icons.Outlined.Settings, "nav_settings"),
    ).filter { it.tab != AdGuardTab.APPS || platform.supportsAppCatalogue() }
}

@Composable
fun AdGuardBottomBar(
    currentTab: AdGuardTab,
    onTabSelected: (AdGuardTab) -> Unit,
) {
    val navItems = defaultNavItems()

    NavigationBar(
        containerColor = AdGuardDarkSurface,
        tonalElevation = 8.dp,
        modifier = Modifier.testTag("adguard_bottom_nav"),
    ) {
        navItems.forEach { item ->
            val isSelected = currentTab == item.tab
            NavigationBarItem(
                selected = isSelected,
                onClick = { onTabSelected(item.tab) },
                icon = {
                    Icon(
                        imageVector = if (isSelected) item.selectedIcon else item.unselectedIcon,
                        contentDescription = item.label.asString(),
                    )
                },
                label = {
                    Text(
                        text = item.label.asString(),
                        fontSize = 10.sp,
                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                    )
                },
                colors = NavigationBarItemDefaults.colors(
                    selectedIconColor = AdGuardOnAccent,
                    selectedTextColor = AdGuardGreenPrimary,
                    indicatorColor = AdGuardGreenPrimary,
                    unselectedIconColor = AdGuardTextSecondary,
                    unselectedTextColor = AdGuardTextMuted,
                ),
                modifier = Modifier.testTag(item.tag),
            )
        }
    }
}

/**
 * Side navigation for wide layouts (tablets, desktop windows, landscape).
 *
 * A desktop window has no app bar of its own: the wordmark sits at the top of
 * the rail and the app-wide menu at its bottom, the way AdGuard for Windows
 * keeps both in the sidebar and leaves the page to the page.
 */
@Composable
fun AdGuardNavigationRail(
    currentTab: AdGuardTab,
    onTabSelected: (AdGuardTab) -> Unit,
    modifier: Modifier = Modifier,
    footer: (@Composable () -> Unit)? = null,
) {
    NavigationRail(
        modifier = modifier,
        containerColor = AdGuardDarkSurface,
        header = {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.padding(top = 10.dp, bottom = 6.dp),
            ) {
                Icon(
                    imageVector = Icons.Default.Shield,
                    contentDescription = null,
                    tint = AdGuardGreenPrimary,
                    modifier = Modifier.size(20.dp),
                )
                Text(
                    text = L10n.get(Strings.app_name),
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextPrimary,
                )
            }
        },
    ) {
        defaultNavItems().forEach { item ->
            val isSelected = currentTab == item.tab
            NavigationRailItem(
                selected = isSelected,
                onClick = { onTabSelected(item.tab) },
                icon = {
                    Icon(
                        imageVector = if (isSelected) item.selectedIcon else item.unselectedIcon,
                        contentDescription = item.label.asString(),
                    )
                },
                label = {
                    Text(
                        text = item.label.asString(),
                        fontSize = 10.sp,
                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                    )
                },
                colors = NavigationRailItemDefaults.colors(
                    selectedIconColor = AdGuardOnAccent,
                    selectedTextColor = AdGuardGreenPrimary,
                    indicatorColor = AdGuardGreenPrimary,
                    unselectedIconColor = AdGuardTextSecondary,
                    unselectedTextColor = AdGuardTextMuted,
                ),
                modifier = Modifier.testTag(item.tag),
            )
        }
        if (footer != null) {
            Spacer(modifier = Modifier.height(10.dp))
            HorizontalDivider(
                modifier = Modifier.width(36.dp),
                color = AdGuardDarkOutline,
            )
            footer()
        }
    }
}

/** Persistent reminder shown whenever HTTPS filtering is disabled. */
@Composable
private fun HttpsOffBar(onEnable: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(AdGuardOrangeWarning.copy(alpha = 0.16f))
            .clickable(onClick = onEnable)
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .testTag("https_off_banner"),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = Icons.Default.Lock,
            contentDescription = null,
            tint = AdGuardOrangeWarning,
            modifier = Modifier.size(16.dp),
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(
            text = L10n.get(Strings.https_off_banner),
            fontSize = 11.sp,
            color = AdGuardTextPrimary,
            modifier = Modifier.weight(1f),
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(
            text = L10n.get(Strings.https_off_banner_action),
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardOrangeWarning,
        )
    }
}

/**
 * The app-wide menu: check for updates and the settings/activity
 * export-import pair. It lives at the bottom of the rail on a desktop window,
 * where AdGuard for Windows keeps the same commands.
 */
@Composable
private fun AppMenuButton(viewModel: AdGuardViewModel) {
    val files = currentFileHost()
    val scope = rememberCoroutineScope()
    var menuOpen by remember { mutableStateOf(false) }
    var pendingRestoreUri by remember { mutableStateOf<String?>(null) }

    IconButton(
        onClick = { menuOpen = true },
        modifier = Modifier.testTag("header_menu"),
    ) {
        Icon(
            imageVector = Icons.Default.MoreVert,
            contentDescription = L10n.get(Strings.app_name),
            tint = AdGuardTextSecondary,
        )
    }
    DropdownMenu(
        expanded = menuOpen,
        onDismissRequest = { menuOpen = false },
        containerColor = AdGuardDarkSurface,
    ) {
        DropdownMenuItem(
            text = {
                Text(L10n.get(Strings.header_check_updates), fontSize = 13.sp, color = AdGuardTextPrimary)
            },
            onClick = {
                menuOpen = false
                viewModel.checkAppUpdateManually()
            },
        )
        HorizontalDivider(color = AdGuardDarkOutline)
        DropdownMenuItem(
            text = {
                Text(L10n.get(Strings.header_export_settings), fontSize = 13.sp, color = AdGuardTextPrimary)
            },
            onClick = {
                menuOpen = false
                scope.launch {
                    files.createDocument("adfree-backup.json", "application/json")?.let {
                        viewModel.onIntent(AdGuardIntent.ExportBackup(it))
                    }
                }
            },
        )
        DropdownMenuItem(
            text = {
                Text(L10n.get(Strings.header_import_settings), fontSize = 13.sp, color = AdGuardTextPrimary)
            },
            onClick = {
                menuOpen = false
                scope.launch {
                    files.openText()?.let { pendingRestoreUri = it }
                }
            },
        )
        DropdownMenuItem(
            text = {
                Text(L10n.get(Strings.log_export_action), fontSize = 13.sp, color = AdGuardTextPrimary)
            },
            onClick = {
                menuOpen = false
                scope.launch {
                    files.createDocument("adfree-activity.csv", "text/csv")?.let {
                        viewModel.onIntent(AdGuardIntent.ExportLogs(it))
                    }
                }
            },
        )
        // The desktop window has no toolbar of its own for the log, so the
        // file the user wants to read is one menu item away.
        DropdownMenuItem(
            text = {
                Text(L10n.get(Strings.log_import_action), fontSize = 13.sp, color = AdGuardTextPrimary)
            },
            onClick = {
                menuOpen = false
                scope.launch {
                    files.openText()?.let { viewModel.onIntent(AdGuardIntent.ImportLogs(it)) }
                }
            },
        )
    }

    pendingRestoreUri?.let { uri ->
        AlertDialog(
            onDismissRequest = { pendingRestoreUri = null },
            title = { Text(L10n.get(Strings.settings_restore_title)) },
            text = { Text(L10n.get(Strings.settings_restore_body), fontSize = 12.sp) },
            confirmButton = {
                TextButton(
                    onClick = {
                        pendingRestoreUri = null
                        viewModel.onIntent(AdGuardIntent.ImportBackup(uri))
                    },
                ) {
                    Text(L10n.get(Strings.settings_restore_confirm), color = AdGuardOrangeWarning)
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingRestoreUri = null }) {
                    Text(L10n.get(Strings.common_cancel))
                }
            },
        )
    }
}

/**
 * The app shell both hosts render: snackbar, HTTPS-off strip, the six-tab
 * rail (wide) or bottom bar (narrow), and the tab transition. Host glue that
 * only Android can do — VPN consent launchers, lifecycle resumes, SAF
 * pickers — stays outside this composable. [toastMessages] lets a host pipe
 * platform toasts into the same snackbar (the desktop has no OS toasts).
 */
@Composable
fun AdGuardApp(
    viewModel: AdGuardViewModel,
    modifier: Modifier = Modifier,
    toastMessages: Flow<String> = emptyFlow(),
) {
    val state by viewModel.uiState.collectAsState()
    val platform = currentPlatformHost()
    val snackbarHostState = remember { SnackbarHostState() }
    // Keep each tab's own navigation (for example the Filters hub
    // sub-screen) alive while the user visits another tab.
    val tabStateHolder = rememberSaveableStateHolder()

    LaunchedEffect(viewModel) {
        viewModel.effect.collect { effect ->
            when (effect) {
                is AdGuardEffect.ShowSnackbar ->
                    snackbarHostState.showSnackbar(effect.message.asString())

                is AdGuardEffect.ShowUndoSnackbar -> {
                    val outcome = snackbarHostState.showSnackbar(
                        effect.message.asString(),
                        effect.actionLabel.asString(),
                    )
                    if (outcome == SnackbarResult.ActionPerformed) {
                        viewModel.onIntent(effect.undo)
                    }
                }
                // The consent dialog itself is host glue; the host watches
                // showVpnPermissionPrompt on the state it already collects.
                is AdGuardEffect.RequestVpnPermission -> Unit
            }
        }
    }
    LaunchedEffect(toastMessages) {
        toastMessages.collect { snackbarHostState.showSnackbar(it) }
    }

    BoxWithConstraints(modifier = modifier.fillMaxSize()) {
        // Material wide-layout rule: below 600dp keep the bottom bar;
        // at or above it switch to a side rail, and cap the content
        // width so tablets never stretch one column edge to edge.
        val isWide = maxWidth >= 600.dp
        // A desktop window is not a phone with room to spare: past 840dp the
        // screens draw their desktop body (flat rows, hairlines, two columns)
        // instead of the stacked phone one, the way AdGuard for Windows does.
        val uiLayout = if (platform.supportsWindowHeader() && maxWidth >= 840.dp) {
            UiLayout.Desktop
        } else {
            UiLayout.Compact
        }
        CompositionLocalProvider(LocalUiLayout provides uiLayout) {
            Scaffold(
            modifier = Modifier.fillMaxSize(),
            containerColor = AdGuardDarkBg,
            topBar = {
                // A desktop window gets its identity and its app-wide menu
                // from the rail instead: a 48dp bar repeating "AdFree · Bảo vệ"
                // above a page titled "Bảo vệ" is a row of chrome that buys
                // nothing but a shorter page.
            },
            snackbarHost = {
                SnackbarHost(snackbarHostState) { data ->
                    Snackbar(
                        snackbarData = data,
                        containerColor = AdGuardDarkSurface,
                        contentColor = AdGuardTextPrimary,
                    )
                }
            },
            bottomBar = {
                Column {
                    // AdGuard pins this strip above the tab bar: with
                    // HTTPS off the engine only filters DNS and plain
                    // HTTP, so the Home screen otherwise overstates
                    // what is actually blocked.
                    if (!state.settings.isHttpsFilteringEnabled) {
                        HttpsOffBar(
                            onEnable = {
                                viewModel.onIntent(
                                    AdGuardIntent.OpenProtectionSection(
                                        ProtectionSection.HTTPS,
                                    ),
                                )
                            },
                        )
                    }
                    if (!isWide) {
                        AdGuardBottomBar(
                            currentTab = state.currentTab,
                            onTabSelected = { viewModel.onIntent(AdGuardIntent.SelectTab(it)) },
                        )
                    }
                }
            },
        ) { innerPadding ->
            Row(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
            ) {
                if (isWide) {
                    // The rail owns the whole column so the app menu can sit
                    // at its foot, the way AdGuard for Windows parks the same
                    // menu under the sidebar.
                    AdGuardNavigationRail(
                        currentTab = state.currentTab,
                        onTabSelected = { viewModel.onIntent(AdGuardIntent.SelectTab(it)) },
                        footer = { AppMenuButton(viewModel) },
                    )
                }
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxSize(),
                    contentAlignment = Alignment.TopCenter,
                ) {
                    AnimatedContent(
                        targetState = state.currentTab,
                        modifier = Modifier
                            .fillMaxSize()
                            .widthIn(
                                max = if (uiLayout == UiLayout.Desktop) {
                                    UiSize.CONTENT_MAX_WIDTH.dp
                                } else {
                                    1000.dp
                                },
                            ),
                        transitionSpec = {
                            val direction =
                                if (targetState.ordinal > initialState.ordinal) 1 else -1
                            (fadeIn(tween(200)) +
                                slideInHorizontally(tween(260)) { direction * it / 10 })
                                .togetherWith(
                                    fadeOut(tween(150)) +
                                        slideOutHorizontally(tween(260)) { -direction * it / 10 },
                                )
                        },
                        label = "tab-transition",
                    ) { tab ->
                        tabStateHolder.SaveableStateProvider(tab) {
                            when (tab) {
                                AdGuardTab.HOME -> HomeScreen(viewModel = viewModel)
                                AdGuardTab.PROTECTION -> ProtectionScreen(viewModel = viewModel)
                                // The tab follows the same split as the rest of
                                // the shell: a desktop window gets the
                                // AdGuard-shaped log, because that is the shape
                                // a mouse and a wide pane are for, while a phone
                                // or a tablet keeps the cards, the search field
                                // and the chips. `supportsWindowHeader()` is what
                                // keeps a tablet on the compact side.
                                AdGuardTab.ACTIVITY -> FilteringLogScreen(
                                    viewModel = viewModel,
                                    adGuardLayout = uiLayout == UiLayout.Desktop,
                                )
                                AdGuardTab.APPS -> AppsManagementScreen(viewModel = viewModel)
                                AdGuardTab.STATISTICS -> StatisticsScreen(viewModel = viewModel)
                                AdGuardTab.SETTINGS -> SettingsScreen(viewModel = viewModel)
                                // Reached from Settings instead of the tab bar: it is
                                // a diagnostic tool, not something used daily.
                                AdGuardTab.AI_LAB -> SecurityLabScreen(viewModel = viewModel)
                            }
                        }
                    }
                }
            }
        }
        }
    }
}
