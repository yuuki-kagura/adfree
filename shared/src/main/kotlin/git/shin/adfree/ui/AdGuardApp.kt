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
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ListAlt
import androidx.compose.material.icons.automirrored.outlined.ListAlt
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PieChart
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.outlined.Apps
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.PieChart
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.Icon
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
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.l10n.L10n
import git.shin.adfree.l10n.Strings
import git.shin.adfree.ui.screens.AppsManagementScreen
import git.shin.adfree.ui.screens.FilteringLogScreen
import git.shin.adfree.ui.screens.HomeScreen
import git.shin.adfree.ui.screens.ProtectionScreen
import git.shin.adfree.ui.screens.SecurityLabScreen
import git.shin.adfree.ui.screens.SettingsScreen
import git.shin.adfree.ui.screens.StatisticsScreen
import git.shin.adfree.ui.theme.AdGuardDarkBg
import git.shin.adfree.ui.theme.AdGuardDarkSurface
import git.shin.adfree.ui.theme.AdGuardGreenPrimary
import git.shin.adfree.ui.theme.AdGuardOnAccent
import git.shin.adfree.ui.theme.AdGuardOrangeWarning
import git.shin.adfree.ui.theme.AdGuardTextMuted
import git.shin.adfree.ui.theme.AdGuardTextPrimary
import git.shin.adfree.ui.theme.AdGuardTextSecondary
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emptyFlow

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

/** Side navigation for wide layouts (tablets, desktop windows, landscape). */
@Composable
fun AdGuardNavigationRail(
    currentTab: AdGuardTab,
    onTabSelected: (AdGuardTab) -> Unit,
) {
    NavigationRail(
        containerColor = AdGuardDarkSurface,
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
    val snackbarHostState = remember { SnackbarHostState() }
    // Keep each tab's own navigation (for example the Filters hub
    // sub-screen) alive while the user visits another tab.
    val tabStateHolder = rememberSaveableStateHolder()

    LaunchedEffect(viewModel) {
        viewModel.effect.collect { effect ->
            when (effect) {
                is AdGuardEffect.ShowSnackbar ->
                    snackbarHostState.showSnackbar(effect.message.asString())
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
        Scaffold(
            modifier = Modifier.fillMaxSize(),
            containerColor = AdGuardDarkBg,
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
                    AdGuardNavigationRail(
                        currentTab = state.currentTab,
                        onTabSelected = { viewModel.onIntent(AdGuardIntent.SelectTab(it)) },
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
                            .widthIn(max = 1000.dp),
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
                                AdGuardTab.ACTIVITY -> FilteringLogScreen(viewModel = viewModel)
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
