package git.shin.adfree

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.SystemBarStyle
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ListAlt
import androidx.compose.material.icons.automirrored.outlined.ListAlt
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.outlined.Apps
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import git.shin.adfree.model.ThemeMode
import git.shin.adfree.R
import git.shin.adfree.ui.AdGuardEffect
import git.shin.adfree.ui.AdGuardIntent
import git.shin.adfree.ui.AdGuardTab
import git.shin.adfree.ui.AdGuardViewModel
import git.shin.adfree.ui.Localization
import git.shin.adfree.ui.UiText
import git.shin.adfree.ui.screens.AppsManagementScreen
import git.shin.adfree.ui.screens.FilteringLogScreen
import git.shin.adfree.ui.screens.HomeScreen
import git.shin.adfree.ui.screens.ProtectionScreen
import git.shin.adfree.ui.screens.SecurityLabScreen
import git.shin.adfree.ui.screens.SettingsScreen
import git.shin.adfree.ui.theme.AdGuardDarkBg
import git.shin.adfree.ui.theme.AdGuardDarkSurface
import git.shin.adfree.ui.theme.AdGuardGreenPrimary
import git.shin.adfree.ui.theme.AdGuardOnAccent
import git.shin.adfree.ui.theme.AdGuardTextMuted
import git.shin.adfree.ui.theme.AdGuardTextPrimary
import git.shin.adfree.ui.theme.AdGuardTextSecondary
import git.shin.adfree.ui.theme.MyApplicationTheme

class MainActivity : AppCompatActivity() {

    private val viewModel: AdGuardViewModel by viewModels {
        AdGuardApplication.instance.container.provideViewModelFactory()
    }

    /** Container kept for the Activity's lifetime so MainActivity can read it. */
    private val container get() = AdGuardApplication.instance.container

    /**
     * Android 13+ gates the ongoing protection notification and the result of
     * a background filter refresh behind an explicit grant.
     */
    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { /* The notification is optional; refusal only silences it. */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // System screens (the certificate installer, consent dialogs) launch
        // from the ViewModel, so it needs a context that can start activities.
        viewModel.attachContext { this }
        // A launch intent is consumed once: rotation replays the original
        // intent, and asking for consent again there would look like a bug.
        if (savedInstanceState == null) handleLaunchAction(intent)
        requestNotificationPermissionOnce()

        setContent {
            val state by viewModel.uiState.collectAsState()
            val darkTheme = when (state.settings.themeMode) {
                ThemeMode.SYSTEM -> isSystemInDarkTheme()
                ThemeMode.DARK -> true
                ThemeMode.LIGHT -> false
            }
            LaunchedEffect(darkTheme) {
                // The system bars follow the app theme, not the device theme:
                // a light app on a dark device still needs dark status icons.
                val transparent = android.graphics.Color.TRANSPARENT
                val statusBar = if (darkTheme) {
                    SystemBarStyle.dark(transparent)
                } else {
                    SystemBarStyle.light(transparent, transparent)
                }
                enableEdgeToEdge(statusBarStyle = statusBar, navigationBarStyle = statusBar)
            }
            MyApplicationTheme(darkTheme = darkTheme) {
                val snackbarHostState = remember { SnackbarHostState() }
                val context = LocalContext.current
                // The persisted choice is applied once at startup; this keeps
                // the UI in sync when the user picks another language.
                LaunchedEffect(Unit) {
                    container.repository.settings.collect {
                        Localization.apply(it.appLanguage)
                        // HTTPS, protection and language changes all pass
                        // through here; re-evaluate the certificate reminder.
                        container.repository.syncHttpsReminder()
                    }
                }
                // Keep each tab's own navigation (for example the Filters hub
                // sub-screen) alive while the user visits another tab.
                val tabStateHolder = rememberSaveableStateHolder()

                // Collect one-off side effects
                LaunchedEffect(Unit) {
                    viewModel.effect.collect { effect ->
                        when (effect) {
                            is AdGuardEffect.ShowSnackbar -> {
                                snackbarHostState.showSnackbar(effect.message.resolve(context))
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
                    // The certificate installer is another activity: coming
                    // back is the moment trust can have changed.
                    container.repository.syncHttpsReminder()
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
                        AdGuardBottomBar(
                            currentTab = state.currentTab,
                            onTabSelected = { viewModel.onIntent(AdGuardIntent.SelectTab(it)) }
                        )
                    }
                ) { innerPadding ->
                    AnimatedContent(
                        targetState = state.currentTab,
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(innerPadding),
                        transitionSpec = {
                            val direction =
                                if (targetState.ordinal > initialState.ordinal) 1 else -1
                            (fadeIn(tween(200)) +
                                slideInHorizontally(tween(260)) { direction * it / 10 })
                                .togetherWith(
                                    fadeOut(tween(150)) +
                                        slideOutHorizontally(tween(260)) { -direction * it / 10 }
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

    /** Tile and update-notification deep links arrive here while we are alive. */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleLaunchAction(intent)
    }

    private fun handleLaunchAction(intent: Intent?) {
        when (intent?.action) {
            ACTION_ENABLE_PROTECTION -> viewModel.enableProtectionFromShortcut()
            ACTION_OPEN_FILTERS -> viewModel.openFilters()
            ACTION_OPEN_PROTECTION -> viewModel.onIntent(AdGuardIntent.SelectTab(AdGuardTab.PROTECTION))
        }
    }

    private fun requestNotificationPermissionOnce() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        val prefs = getSharedPreferences(NOTIFICATION_PREFS, MODE_PRIVATE)
        if (prefs.getBoolean(KEY_NOTIFICATION_ASKED, false)) return
        // Record the attempt before launching: a refusal is the user's answer,
        // not a reason to ask on every launch.
        prefs.edit { putBoolean(KEY_NOTIFICATION_ASKED, true) }
        notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
    }

    companion object {
        /** Tile tapped without VPN consent: open the app and raise the dialog. */
        const val ACTION_ENABLE_PROTECTION = "git.shin.adfree.action.ENABLE_PROTECTION"

        /** Update notification tapped: land on the Protection tab. */
        const val ACTION_OPEN_FILTERS = "git.shin.adfree.action.OPEN_FILTERS"

        /** Certificate reminder tapped: land on the Protection tab. */
        const val ACTION_OPEN_PROTECTION = "git.shin.adfree.action.OPEN_PROTECTION"

        private const val NOTIFICATION_PREFS = "notification_permission"
        private const val KEY_NOTIFICATION_ASKED = "asked"
    }
}

data class NavItem(
    val tab: AdGuardTab,
    val label: UiText,
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
        NavItem(AdGuardTab.HOME, UiText.Resource(R.string.nav_home), Icons.Filled.Home, Icons.Outlined.Home, "nav_home"),
        NavItem(AdGuardTab.PROTECTION, UiText.Resource(R.string.nav_protection), Icons.Filled.Shield, Icons.Outlined.Shield, "nav_protection"),
        NavItem(AdGuardTab.APPS, UiText.Resource(R.string.nav_apps), Icons.Filled.Apps, Icons.Outlined.Apps, "nav_apps"),
        NavItem(AdGuardTab.ACTIVITY, UiText.Resource(R.string.nav_activity), Icons.AutoMirrored.Filled.ListAlt, Icons.AutoMirrored.Outlined.ListAlt, "nav_activity"),
        NavItem(AdGuardTab.SETTINGS, UiText.Resource(R.string.nav_settings), Icons.Filled.Settings, Icons.Outlined.Settings, "nav_settings")
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
                        contentDescription = item.label.asString()
                    )
                },
                label = {
                    Text(
                        text = item.label.asString(),
                        fontSize = 10.sp,
                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal
                    )
                },
                colors = NavigationBarItemDefaults.colors(
                    selectedIconColor = AdGuardOnAccent,
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
