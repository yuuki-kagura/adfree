package git.shin.adfree.desktop

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Canvas
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.Paint
import androidx.compose.ui.graphics.painter.BitmapPainter
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEvent
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.type
import androidx.compose.ui.window.Notification
import androidx.compose.ui.window.Tray
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberTrayState
import androidx.compose.ui.window.rememberWindowState
import git.shin.adfree.l10n.L10n
import git.shin.adfree.l10n.Strings
import git.shin.adfree.model.ThemeMode
import git.shin.adfree.platform.BackRegistry
import git.shin.adfree.platform.LocalAppInventory
import git.shin.adfree.platform.LocalBackRegistry
import git.shin.adfree.platform.LocalFileHost
import git.shin.adfree.platform.LocalPlatformHost
import git.shin.adfree.platform.LocalResumeTick
import git.shin.adfree.ui.AdGuardApp
import git.shin.adfree.ui.AdGuardIntent
import git.shin.adfree.ui.AdGuardTab
import git.shin.adfree.ui.theme.MyApplicationTheme
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

/**
 * The full AdFree UI on Linux: the shared screens, scaffold and ViewModel
 * exactly as the Android app runs them, with the desktop seams underneath.
 * Escape walks the shared back stack (dialogs, then tab-to-Home) before the
 * window closes.
 *
 * The window and a tray icon are the app: closing the window leaves the
 * listeners and the redirect rules filtering, the way AdGuard for Windows
 * keeps filtering with its window shut.
 */
fun main() {
    val container = DesktopContainer()
    val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    container.start(appScope)
    val resumeTick = MutableStateFlow(0L)
    val backRegistry = BackRegistry()
    // Hiding is only a detour when there is a status field to come back
    // through. Many Linux sessions have no tray owner at all, and a hidden
    // window there is an app the user cannot reach: close quits instead.
    val hasTray = java.awt.SystemTray.isSupported()
    // Whatever ends the process — the tray, a signal, a crash of the UI thread
    // — the listeners go down with it. Left up, native threads keep the JVM
    // from finishing and the ports stay taken.
    Runtime.getRuntime().addShutdownHook(Thread { container.coreEngine.stopProxy() })

    application {
        val windowState = rememberWindowState(width = 1200.dp, height = 800.dp)
        val trayState = rememberTrayState()
        var visible by remember { mutableStateOf(true) }
        var paused by remember { mutableStateOf(false) }
        var pauseJob by remember { mutableStateOf<Job?>(null) }

        val showWindow: () -> Unit = {
            visible = true
            container.repository.setUiVisible(true)
            // Same tick the Activity's ON_RESUME maps to: coming back from the
            // tray re-reads what only a foreground pass can see.
            resumeTick.value += 1
        }
        val hideWindow: () -> Unit = {
            visible = false
            container.repository.setUiVisible(false)
            trayState.sendNotification(
                Notification("AdFree", L10n.get(Strings.tray_hidden), Notification.Type.None),
            )
        }
        val quit: () -> Unit = {
            pauseJob?.cancel()
            container.repository.setUiVisible(false)
            // The listeners are native threads: left up, they keep the JVM
            // from finishing, and quitting would leave ports bound behind a
            // process with no window and no way back to it.
            container.coreEngine.stopProxy()
            appScope.cancel()
            exitApplication()
        }
        // The privileged instance binds the same ports, so this one has to be
        // the one that leaves.
        DisposableEffect(quit) {
            container.onEngineTakeover = quit
            onDispose { container.onEngineTakeover = {} }
        }

        val resumeFiltering: () -> Unit = {
            pauseJob?.cancel()
            pauseJob = null
            container.coreEngine.setProtectionPaused(false)
            paused = false
        }
        val pauseFiltering: (Long) -> Unit = { millis ->
            pauseJob?.cancel()
            container.coreEngine.setProtectionPaused(true)
            paused = true
            pauseJob = appScope.launch {
                delay(millis)
                container.coreEngine.setProtectionPaused(false)
                paused = false
                pauseJob = null
            }
        }

        if (hasTray) {
            Tray(
                icon = rememberTrayIcon(),
                state = trayState,
                tooltip = "AdFree",
                onAction = { if (visible) Unit else showWindow() },
                menu = {
                    Item(L10n.get(Strings.tray_open), onClick = { showWindow() })
                    Separator()
                    Item(L10n.get(Strings.tray_pause_30s), onClick = { pauseFiltering(30_000) })
                    Item(L10n.get(Strings.tray_pause_1h), onClick = { pauseFiltering(3_600_000) })
                    Item(
                        text = L10n.get(Strings.tray_resume),
                        enabled = paused,
                        onClick = { resumeFiltering() },
                    )
                    Separator()
                    Item(L10n.get(Strings.tray_exit), onClick = { quit() })
                },
            )
        }

        Window(
            onCloseRequest = { if (hasTray) hideWindow() else quit() },
            visible = visible,
            title = "AdFree",
            state = windowState,
            onPreviewKeyEvent = { event: KeyEvent ->
                if (event.key == Key.Escape && event.type == KeyEventType.KeyDown) {
                    when {
                        backRegistry.onBack() -> true
                        container.viewModel.uiState.value.currentTab != AdGuardTab.HOME -> {
                            container.viewModel.onIntent(AdGuardIntent.SelectTab(AdGuardTab.HOME))
                            true
                        }
                        else -> {
                            // Escape and the window button mean the same thing.
                            if (hasTray) hideWindow() else quit()
                            true
                        }
                    }
                } else {
                    false
                }
            },
        ) {
            if (!container.engineAvailable) {
                MissingCoreScreen(container.dataRoot.absolutePath)
            } else {
                DesktopHosts(container, resumeTick, backRegistry)
            }
        }
    }
}

/** The status-field glyph size: every tray Linux offers is 24px or smaller. */
private const val TRAY_ICON_PX = 24

/** The app's dark/green palette, in the two colours a 24px glyph can carry. */
private val TrayGreen = Color(0xFF00D06C)
private val TrayBg = Color(0xFF0A0E13)

/** The app's own green mark, painted once: a tray needs an icon, not a photo. */
@Composable
private fun rememberTrayIcon(): Painter {
    val bitmap = remember {
        ImageBitmap(TRAY_ICON_PX, TRAY_ICON_PX).also { surface ->
            val edge = TRAY_ICON_PX.toFloat()
            val green = Paint().apply { color = TrayGreen }
            val dark = Paint().apply { color = TrayBg }
            Canvas(surface).apply {
                drawRoundRect(0f, 0f, edge, edge, 6f, 6f, green)
                drawRoundRect(4f, 3f, edge - 4f, edge - 3f, 5f, 5f, dark)
                drawCircle(Offset(edge / 2f, edge / 2f), 4f, green)
            }
        }
    }
    return BitmapPainter(bitmap)
}

@Composable
private fun DesktopHosts(
    container: DesktopContainer,
    resumeTick: MutableStateFlow<Long>,
    backRegistry: BackRegistry,
) {
    val settings by container.repository.settings.collectAsState()
    LaunchedEffect(container) {
        // The stats poller follows the window, like it follows the Activity.
        container.repository.setUiVisible(true)
        // One resume tick at startup: screens that refresh on foreground
        // (Private DNS re-read) run their first pass like on Android.
        resumeTick.value += 1
    }
    DisposableEffect(container) {
        onDispose { container.repository.setUiVisible(false) }
    }
    MyApplicationTheme(
        darkTheme = when (settings.themeMode) {
            // No system dark mode on a desktop session: DARK is the default
            // and LIGHT follows the light palette.
            ThemeMode.SYSTEM, ThemeMode.DARK -> true
            ThemeMode.LIGHT -> false
        },
    ) {
        CompositionLocalProvider(
            LocalPlatformHost provides container.platformHost,
            LocalFileHost provides container.fileHost,
            LocalAppInventory provides container.inventory,
            LocalResumeTick provides resumeTick,
            LocalBackRegistry provides backRegistry,
        ) {
            AdGuardApp(
                viewModel = container.viewModel,
                toastMessages = container.platformHost.toasts,
            )
        }
    }
}

@Composable
private fun MissingCoreScreen(dataRoot: String) {
    Scaffold(containerColor = MaterialTheme.colorScheme.background) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).padding(32.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text("libadfree_core.so not found", color = MaterialTheme.colorScheme.error)
            Text(
                "Run `cargo build --release` in the rust/ directory or set " +
                    "ADFREE_CORE_LIB to the built library. Data root: $dataRoot",
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}
