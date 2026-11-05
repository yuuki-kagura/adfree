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
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
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
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import git.shin.adfree.model.ThemeMode
import git.shin.adfree.platform.AndroidFileHost
import git.shin.adfree.platform.AppInventory
import git.shin.adfree.platform.BackRegistry
import git.shin.adfree.platform.FileHost
import git.shin.adfree.platform.LocalAppInventory
import git.shin.adfree.platform.LocalBackRegistry
import git.shin.adfree.platform.LocalFileHost
import git.shin.adfree.platform.LocalPlatformHost
import git.shin.adfree.platform.LocalResumeTick
import git.shin.adfree.platform.PlatformHost
import git.shin.adfree.ui.AdGuardApp
import git.shin.adfree.ui.AdGuardIntent
import git.shin.adfree.ui.AdGuardTab
import git.shin.adfree.ui.AdGuardViewModel
import git.shin.adfree.ui.Localization
import git.shin.adfree.ui.theme.MyApplicationTheme
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.suspendCancellableCoroutine

class MainActivity : AppCompatActivity() {

    /** The one state holder for the whole process, owned by the container. */
    private val viewModel: AdGuardViewModel get() = container.viewModel

    /** Container kept for the Activity's lifetime so MainActivity can read it. */
    private val container get() = AdGuardApplication.instance.container

    /** Bumped on every foreground resume; shared screens refresh from this. */
    private val resumeTick = MutableStateFlow(0L)

    /** The back stack the moved screens register their dialogs/sub-routes on. */
    private val backRegistry = BackRegistry()

    /**
     * Android 13+ gates the ongoing protection notification and the result of
     * a background filter refresh behind an explicit grant.
     */
    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        // The service posted its notification before this grant; Android
        // dropped it then, so ask for a redraw now.
        if (granted) {
            container.vpnController.refreshStatusNotification()
        } else if (userInitiatedNotificationAsk) {
            // Android stops showing the dialog after two refusals and returns
            // "denied" silently; the settings page is the only way back.
            container.platformHost.openNotificationSettings()
        }
        userInitiatedNotificationAsk = false
    }

    /** True while the Home chip's permission dialog is the pending one. */
    private var userInitiatedNotificationAsk = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // A launch intent is consumed once: rotation replays the original
        // intent, and asking for consent again there would look like a bug.
        if (savedInstanceState == null) handleLaunchAction(intent)
        requestNotificationPermissionOnce()
        // The moved HomeScreen asks for the permission through the platform
        // seam; the launcher itself can only live here, in the Activity.
        container.platformHost.onNotificationPermission = {
            userInitiatedNotificationAsk = true
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

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
            AdFreeHosts(
                platform = container.platformHost,
                files = container.fileHost,
                inventory = container.appInventory,
                resumeTick = resumeTick,
                backRegistry = backRegistry,
            ) {
                FilePickerWiring(fileHost = container.fileHost)
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

                // Foreground-only stale-list check. No worker/alarm: opening
                // the app after a day in Recents is the catch-up point.
                LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
                    resumeTick.value += 1
                    container.repository.autoUpdateIfStale()
                    // The app release check rides the same pass, with its own
                    // day gate and its own silence.
                    container.appUpdate.autoCheck()
                    // The certificate installer is another activity: coming
                    // back is the moment trust can have changed.
                    container.repository.syncHttpsReminder()
                    // Permission may have been granted from system settings
                    // while the tunnel kept running without a visible status.
                    container.vpnController.refreshStatusNotification()
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

                // Back goes to the screens' own stack first (open dialogs,
                // sub-routes); only when nothing claims it does a tab hop
                // back to Home, and Home lets the task go background.
                BackHandler {
                    when {
                        backRegistry.onBack() -> Unit
                        state.currentTab != AdGuardTab.HOME ->
                            viewModel.onIntent(AdGuardIntent.SelectTab(AdGuardTab.HOME))
                        else -> moveTaskToBack(true)
                    }
                }

                AdGuardApp(viewModel)
            }
            }
        }
    }

    /**
     * The stats poller only runs while a screen is on top. Without this the
     * repository would keep ticking every 500ms in the background — waking
     * the process and its threads for a UI nobody can see.
     */
    override fun onStart() {
        super.onStart()
        container.repository.setUiVisible(true)
    }

    override fun onStop() {
        container.repository.setUiVisible(false)
        super.onStop()
    }

    /** The container outlives the Activity; drop the back-reference to it. */
    override fun onDestroy() {
        container.platformHost.onNotificationPermission = null
        super.onDestroy()
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
            ACTION_OPEN_ACTIVITY -> {
                val app = intent.getStringExtra(EXTRA_LOG_APP)
                val domain = intent.getStringExtra(EXTRA_LOG_DOMAIN)
                when {
                    app != null -> viewModel.openLogForApp(app)
                    domain != null -> viewModel.openLogForDomain(domain)
                    else -> viewModel.openRecentActivity()
                }
            }
            ACTION_OPEN_APPS -> viewModel.onIntent(AdGuardIntent.SelectTab(AdGuardTab.APPS))
            ACTION_OPEN_UPDATE -> viewModel.onIntent(AdGuardIntent.SelectTab(AdGuardTab.SETTINGS))
            ACTION_OPEN_APP_DETAILS -> {
                intent.getStringExtra(EXTRA_APP_PACKAGE)?.let { packageName ->
                    viewModel.openAppDetails(
                        packageName,
                        intent.getStringExtra(EXTRA_APP_NAME),
                    )
                }
            }
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

        /** Assistant row tapped: land on the Activity tab, optionally filtered. */
        const val ACTION_OPEN_ACTIVITY = "git.shin.adfree.action.OPEN_ACTIVITY"
        const val EXTRA_LOG_APP = "git.shin.adfree.extra.LOG_APP"
        const val EXTRA_LOG_DOMAIN = "git.shin.adfree.extra.LOG_DOMAIN"

        /** Assistant shortcut: land on the Apps tab. */
        const val ACTION_OPEN_APPS = "git.shin.adfree.action.OPEN_APPS"

        /** App-update notice tapped: land on Settings, where the row installs. */
        const val ACTION_OPEN_UPDATE = "git.shin.adfree.action.OPEN_UPDATE"

        /** Assistant per-app panel: open that app's management sheet. */
        const val ACTION_OPEN_APP_DETAILS = "git.shin.adfree.action.OPEN_APP_DETAILS"
        const val EXTRA_APP_PACKAGE = "git.shin.adfree.extra.APP_PACKAGE"
        const val EXTRA_APP_NAME = "git.shin.adfree.extra.APP_NAME"

        private const val NOTIFICATION_PREFS = "notification_permission"
        private const val KEY_NOTIFICATION_ASKED = "asked"
    }
}

/** Gives the moved screens their platform seams through composition locals. */
@Composable
private fun AdFreeHosts(
    platform: PlatformHost,
    files: FileHost,
    inventory: AppInventory,
    resumeTick: StateFlow<Long>,
    backRegistry: BackRegistry,
    content: @Composable () -> Unit,
) {
    CompositionLocalProvider(
        LocalPlatformHost provides platform,
        LocalFileHost provides files,
        LocalAppInventory provides inventory,
        LocalResumeTick provides resumeTick,
        LocalBackRegistry provides backRegistry,
    ) { content() }
}

/**
 * Registers the two SAF launchers once and hands them to the file host the
 * moved screens pick from: openText()/createDocument() suspend on these
 * callbacks instead of every screen owning its own launcher.
 */
@Composable
private fun FilePickerWiring(fileHost: AndroidFileHost) {
    val pendingOpen = remember { AtomicReference<CancellableContinuation<String?>?>(null) }
    val pendingCreate = remember { AtomicReference<CancellableContinuation<String?>?>(null) }
    val openLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        val cont = pendingOpen.getAndSet(null) ?: return@rememberLauncherForActivityResult
        if (uri != null) {
            fileHost.persistRead(uri.toString())
            cont.resume(uri.toString(), onCancellation = null)
        } else {
            cont.resume(null, onCancellation = null)
        }
    }
    val createLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain"),
    ) { uri ->
        val cont = pendingCreate.getAndSet(null) ?: return@rememberLauncherForActivityResult
        cont.resume(uri?.toString(), onCancellation = null)
    }
    DisposableEffect(fileHost) {
        fileHost.openPicker = {
            suspendCancellableCoroutine { cont ->
                pendingOpen.set(cont)
                openLauncher.launch(arrayOf("*/*"))
            }
        }
        fileHost.createPicker = { name ->
            suspendCancellableCoroutine { cont ->
                pendingCreate.set(cont)
                createLauncher.launch(name)
            }
        }
        onDispose {
            fileHost.openPicker = null
            fileHost.createPicker = null
        }
    }
}
