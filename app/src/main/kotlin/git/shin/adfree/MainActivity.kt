package git.shin.adfree

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ListAlt
import androidx.compose.material.icons.automirrored.outlined.ListAlt
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Layers
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.outlined.Apps
import androidx.compose.material.icons.outlined.Layers
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import git.shin.adfree.ui.AdGuardEffect
import git.shin.adfree.ui.AdGuardIntent
import git.shin.adfree.ui.AdGuardTab
import git.shin.adfree.ui.AdGuardViewModel
import git.shin.adfree.ui.screens.AppsManagementScreen
import git.shin.adfree.ui.screens.FilteringHubScreen
import git.shin.adfree.ui.screens.FilteringLogScreen
import git.shin.adfree.ui.screens.HomeScreen
import git.shin.adfree.ui.screens.SecurityLabScreen
import git.shin.adfree.ui.screens.SettingsScreen
import git.shin.adfree.ui.theme.AdGuardDarkBg
import git.shin.adfree.ui.theme.AdGuardDarkSurface
import git.shin.adfree.ui.theme.AdGuardGreenPrimary
import git.shin.adfree.ui.theme.AdGuardTextMuted
import git.shin.adfree.ui.theme.AdGuardTextSecondary
import git.shin.adfree.ui.theme.MyApplicationTheme

class MainActivity : ComponentActivity() {

    private val viewModel: AdGuardViewModel by viewModels {
        AdGuardApplication.instance.container.provideViewModelFactory()
    }

    /** Container kept for the Activity's lifetime so MainActivity can read it. */
    private val container get() = AdGuardApplication.instance.container

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // System screens (the certificate installer, consent dialogs) launch
        // from the ViewModel, so it needs a context that can start activities.
        viewModel.attachContext { this }
        enableEdgeToEdge()

        setContent {
            MyApplicationTheme {
                val state by viewModel.uiState.collectAsState()
                val snackbarHostState = remember { SnackbarHostState() }

                // Collect one-off side effects
                LaunchedEffect(Unit) {
                    viewModel.effect.collect { effect ->
                        when (effect) {
                            is AdGuardEffect.ShowSnackbar -> {
                                snackbarHostState.showSnackbar(effect.message)
                            }
                            is AdGuardEffect.RequestVpnPermission -> {
                                // Handled via launcher
                            }
                        }
                    }
                }

                // Foreground-only stale-list check. No worker/alarm: opening
                // the app after a day in Recents is the catch-up point.
                LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
                    container.repository.autoUpdateIfStale()
                }

                // VPN consent: the system shows a confirmation dialog once (and after a revoke).
                val vpnLauncher = rememberLauncherForActivityResult(
                    contract = ActivityResultContracts.StartActivityForResult(),
                ) { result ->
                    viewModel.onIntent(
                        AdGuardIntent.VpnPermissionResolved(result.resultCode == RESULT_OK),
                    )
                }

                LaunchedEffect(state.showVpnPermissionPrompt) {
                    if (!state.showVpnPermissionPrompt) return@LaunchedEffect
                    val prepare = container.vpnController.prepareIfNeeded()
                    if (prepare == null) {
                        viewModel.onIntent(AdGuardIntent.VpnPermissionResolved(true))
                    } else {
                        vpnLauncher.launch(prepare)
                    }
                }

                // BackHandler: Return to Home if on another tab
                if (state.currentTab != AdGuardTab.HOME) {
                    BackHandler {
                        viewModel.onIntent(AdGuardIntent.SelectTab(AdGuardTab.HOME))
                    }
                }

                Scaffold(
                    modifier = Modifier.fillMaxSize(),
                    contentWindowInsets = WindowInsets.safeDrawing,
                    containerColor = AdGuardDarkBg,
                    snackbarHost = { SnackbarHost(snackbarHostState) },
                    bottomBar = {
                        AdGuardBottomBar(
                            currentTab = state.currentTab,
                            onTabSelected = { viewModel.onIntent(AdGuardIntent.SelectTab(it)) }
                        )
                    }
                ) { innerPadding ->
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(innerPadding)
                    ) {
                        when (state.currentTab) {
                            AdGuardTab.HOME -> HomeScreen(viewModel = viewModel)
                            AdGuardTab.ACTIVITY -> FilteringLogScreen(viewModel = viewModel)
                            AdGuardTab.FILTERS -> FilteringHubScreen(viewModel = viewModel)
                            AdGuardTab.APPS -> AppsManagementScreen(viewModel = viewModel)
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

data class NavItem(
    val tab: AdGuardTab,
    val label: String,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector,
    val tag: String
)

@Composable
fun AdGuardBottomBar(
    currentTab: AdGuardTab,
    onTabSelected: (AdGuardTab) -> Unit
) {
    val navItems = listOf(
        NavItem(AdGuardTab.HOME, "Bảo vệ", Icons.Filled.Shield, Icons.Outlined.Shield, "nav_home"),
        NavItem(AdGuardTab.ACTIVITY, "Nhật ký", Icons.AutoMirrored.Filled.ListAlt, Icons.AutoMirrored.Outlined.ListAlt, "nav_activity"),
        NavItem(AdGuardTab.FILTERS, "Bộ lọc", Icons.Filled.Layers, Icons.Outlined.Layers, "nav_filters"),
        NavItem(AdGuardTab.APPS, "Ứng dụng", Icons.Filled.Apps, Icons.Outlined.Apps, "nav_apps"),
        NavItem(AdGuardTab.SETTINGS, "Cài đặt", Icons.Filled.Settings, Icons.Outlined.Settings, "nav_settings")
    )

    NavigationBar(
        containerColor = AdGuardDarkSurface,
        tonalElevation = 8.dp,
        windowInsets = WindowInsets.navigationBars,
        modifier = Modifier.testTag("adguard_bottom_nav")
    ) {
        navItems.forEach { item ->
            val isSelected = currentTab == item.tab
            NavigationBarItem(
                selected = isSelected,
                onClick = { onTabSelected(item.tab) },
                icon = {
                    Icon(
                        imageVector = if (isSelected) item.selectedIcon else item.unselectedIcon,
                        contentDescription = item.label
                    )
                },
                label = {
                    Text(
                        text = item.label,
                        fontSize = 10.sp,
                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal
                    )
                },
                colors = NavigationBarItemDefaults.colors(
                    selectedIconColor = Color.Black,
                    selectedTextColor = AdGuardGreenPrimary,
                    indicatorColor = AdGuardGreenPrimary,
                    unselectedIconColor = AdGuardTextSecondary,
                    unselectedTextColor = AdGuardTextMuted
                ),
                modifier = Modifier.testTag(item.tag)
            )
        }
    }
}
