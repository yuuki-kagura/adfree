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
import androidx.compose.runtime.rememberUpdatedState
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
import androidx.compose.ui.res.loadImageBitmap
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
import git.shin.adfree.ui.screens.FilteringLogScreen
import git.shin.adfree.ui.AdGuardTab
import git.shin.adfree.ui.theme.MyApplicationTheme
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import androidx.compose.runtime.produceState

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
/**
 * The single-instance lock, or null when another window already holds it.
 *
 * Held for the life of the process through the returned channel: closing it
 * releases the lock, which is exactly what a window that goes away should do.
 */
private fun acquireInstanceLock(dataRoot: java.io.File): java.nio.channels.FileChannel? {
    return try {
        dataRoot.mkdirs()
        val channel = java.io.RandomAccessFile(java.io.File(dataRoot, "adfree.lock"), "rw").channel
        val deadline = System.currentTimeMillis() + 10_000
        while (System.currentTimeMillis() < deadline) {
            val lock = try {
                channel.tryLock()
            } catch (_: java.nio.channels.OverlappingFileLockException) {
                null
            }
            if (lock != null) return channel
            Thread.sleep(250)
        }
        channel.close()
        null
    } catch (e: Exception) {
        // A directory that cannot hold a lock file is not a reason to lose the
        // window; it is the same window that would have said so.
        System.err.println("[desktop] no instance lock: ${e.message}")
        null
    }
}

fun main() {
    val container = DesktopContainer()
    // One engine, one set of listeners, one set of redirect rules. A second
    // window is what takes the machine down rather than filtering it: the
    // instance that holds the ports answers every redirected query, and if it
    // is the one without `CAP_NET_ADMIN` its own upstream dials come straight
    // back into it — DNS stops answering and nothing loads. The escalation to
    // a privileged unit re-launches this same main, so the wait covers the
    // hand-over: the instance being replaced has to let go before the new one
    // reads the lock.
    val lock = acquireInstanceLock(container.dataRoot)
    if (lock == null) {
        System.err.println(
            "[desktop] AdFree is already running; this window will not start a second engine",
        )
        return
    }
    val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    container.start(appScope)
    // The system bundle is not the only trust store: NSS applications read
    // their own database, and one a browser creates after this point would
    // never see the certificate. Writing them every start is idempotent and
    // costs a `certutil` per database, so it runs off the UI thread instead of
    // hiding behind the once-per-install flag the HTTPS default uses.
    appScope.launch(Dispatchers.IO) { container.platformHost.refreshUserTrustStores() }
    // The window is not up yet and does not need to be: the ask runs on its own
    // thread, so the certificate dialog the system raises never blocks it.
    container.applyHttpsDefault(appScope)
    val resumeTick = MutableStateFlow(0L)
    val backRegistry = BackRegistry()
    // A Wayland session draws AWT's XEmbed icon through KDE's
    // `xembedsniproxy`, which paints it and then delivers no clicks back: the
    // menu there can never open. StatusNotifierItem is the protocol the shell
    // does answer, so it is tried first, and AWT stays the fallback for
    // sessions with no StatusNotifier host at all.
    // `main` is not a composable, so the icon's lifetime is the process's:
    // it is closed by `quit` below.
    val sni = TraySni.start()
    // Hiding is only a detour when there is a status field to come back
    // through. Many Linux sessions have no tray owner at all, and a hidden
    // window there is an app the user cannot reach: close quits instead.
    val hasTray = sni != null || java.awt.SystemTray.isSupported()
    // Whatever ends the process — the tray, a signal, a crash of the UI thread
    // — the listeners go down with it. Left up, native threads keep the JVM
    // from finishing and the ports stay taken. The redirect goes first: rules
    // aimed at closed ports are a machine with no DNS and no web, and a signal
    // never runs the UI's stop path.
    Runtime.getRuntime().addShutdownHook(Thread {
        if (container.privileges.canSetFirewallMark()) container.privileges.removeRules()
        container.coreEngine.stopProxy()
    })

    application {
        val windowState = rememberWindowState(width = 1200.dp, height = 800.dp)
        val trayState = rememberTrayState()
        var visible by remember { mutableStateOf(true) }
        var paused by remember { mutableStateOf(false) }
        var pauseJob by remember { mutableStateOf<Job?>(null) }
        var showFilteringLog by remember { mutableStateOf(false) }
        val filteringLogWindowState = rememberWindowState(width = 900.dp, height = 700.dp)

        // Whether filtering is on, as the shield reads it. The tray icon is the
        // same answer in a place the user can see while the window is hidden:
        // a tray that stays green after protection is switched off in the app
        // is a tray that lies. `produceState` so only a change of this boolean
        // rebuilds anything.
        val filteringOn by produceState(initialValue = true) {
            container.repository.settings.map { it.isProtectionActive }.collect { value = it }
        }
        // Read through `rememberUpdatedState`: the D-Bus pump below is started
        // once and lives in its own coroutine, so a lambda that closed over this
        // value would keep answering with the state it was started in — a menu
        // that offered "pause" over an app that had already stopped filtering.
        val notFilteringState = rememberUpdatedState(trayIconPaused(paused, filteringOn))

        // Bumped by every "show me" request, because a window that is already
        // visible (only minimised or covered) does not change `visible` and so
        // would never be raised again.
        var raiseTick by remember { mutableStateOf(0) }
        val showWindow: () -> Unit = {
            visible = true
            raiseTick += 1
            container.repository.setUiVisible(true)
            // Same tick the Activity's ON_RESUME maps to: coming back from the
            // tray re-reads what only a foreground pass can see.
            resumeTick.value += 1
        }
        val hideWindow: () -> Unit = {
            closeTrayMenu()
            visible = false
            container.repository.setUiVisible(false)
            if (sni != null) {
                sni.notify("AdFree", L10n.get(Strings.tray_hidden))
            } else {
                trayState.sendNotification(
                    Notification("AdFree", L10n.get(Strings.tray_hidden), Notification.Type.None),
                )
            }
        }
        val quit: () -> Unit = {
            closeTrayMenu()
            pauseJob?.cancel()
            container.repository.setUiVisible(false)
            // The listeners are native threads: left up, they keep the JVM
            // from finishing, and quitting would leave ports bound behind a
            // process with no window and no way back to it. The redirect goes
            // first for the same reason it goes first in the shutdown hook.
            if (container.privileges.canSetFirewallMark()) container.privileges.removeRules()
            container.coreEngine.stopProxy()
            sni?.close()
            appScope.cancel()
            exitApplication()
        }
        // The privileged instance binds the same ports, so this one has to be
        // the one that leaves.
        DisposableEffect(quit) {
            container.onEngineTakeover = quit
            onDispose { container.onEngineTakeover = {} }
        }

        // Pausing stops the filtering but not the listeners, and the flag the
        // window reads is the persisted protection record: without writing it
        // the Home card kept saying "filtering" while the tray said otherwise.
        val resumeFiltering: () -> Unit = {
            pauseJob?.cancel()
            pauseJob = null
            container.coreEngine.setProtectionPaused(false)
            paused = false
            // Through the ViewModel, because starting filtering is where this
            // platform asks the system for the privilege the redirect needs.
            // Writing the record here and leaving the listeners alone made the
            // tray's resume a second, poorer start path.
            container.viewModel.resumeProtection()
        }
        val pauseFiltering: (Long) -> Unit = { millis ->
            pauseJob?.cancel()
            container.coreEngine.setProtectionPaused(true)
            container.repository.toggleProtection(false)
            paused = true
            pauseJob = appScope.launch {
                delay(millis)
                container.coreEngine.setProtectionPaused(false)
                container.repository.toggleProtection(true)
                paused = false
                pauseJob = null
            }
        }

        // One place decides what a menu row does, so the D-Bus menu and the
        // AWT one cannot drift apart.
        val handleCommand: (TrayCommand) -> Unit = { command ->
            when (command) {
                TrayCommand.OPEN -> showWindow()
                TrayCommand.LOG -> showFilteringLog = true
                TrayCommand.PAUSE_30S -> pauseFiltering(30_000)
                TrayCommand.PAUSE_1H -> pauseFiltering(3_600_000)
                TrayCommand.RESUME -> resumeFiltering()
                TrayCommand.EXIT -> quit()
            }
        }

        // The icon's clicks land on D-Bus threads; this drains them where the
        // window's own state lives, so a menu item does exactly what the same
        // action does from inside the app.
        if (sni != null) {
            LaunchedEffect(sni) {
                for (request in sni.requests) {
                    when (request) {
                        is TrayRequest.Command -> handleCommand(request.command)
                        is TrayRequest.Menu -> showTrayMenu(
                            request.x,
                            request.y,
                            notFilteringState.value,
                        ) { chosen ->
                            sni.requests.trySend(TrayRequest.Command(chosen))
                        }
                    }
                }
            }
            // The icon says whether filtering is running; the menu greys out
            // whichever of the pause/resume entries cannot be used.
            LaunchedEffect(notFilteringState.value) { sni.setPaused(notFilteringState.value) }
            DisposableEffect(sni) { onDispose { sni.close() } }
        }

        if (hasTray && sni == null) {
            Tray(
                icon = rememberTrayIcon(),
                state = trayState,
                tooltip = "AdFree",
                onAction = { if (visible) Unit else showWindow() },
                menu = {
                    for (entry in trayMenuEntries(notFilteringState.value)) {
                        val command = entry.command
                        if (command == null) {
                            Separator()
                        } else {
                            Item(entry.label, enabled = entry.enabled, onClick = { handleCommand(command) })
                        }
                    }
                },
            )
        }

        Window(
            onCloseRequest = { if (hasTray) hideWindow() else quit() },
            visible = visible,
            title = "AdFree",
            // Without this the window (and the taskbar entry behind it) carries
            // the JVM's own icon: a `java -cp …` launch has no application name
            // for the shell to match, so the mark has to travel with the window.
            icon = rememberAppIconPainter(),
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
            // A hidden-to-tray window comes back where it was left, which on
            // this desktop means behind whatever the user was working in and
            // without the keyboard: raising it is what makes "open AdFree"
            // from the tray look like it did something.
            LaunchedEffect(visible, raiseTick) {
                if (visible) {
                    // Minimised is not hidden: the window is mapped the whole
                    // time, so it has to be restored before it can be raised.
                    window.extendedState = java.awt.Frame.NORMAL
                    window.toFront()
                    window.requestFocus()
                }
            }
            if (!container.engineAvailable) {
                MissingCoreScreen(container.dataRoot.absolutePath)
            } else {
                DesktopHosts(container, resumeTick, backRegistry)
            }
        }

        if (showFilteringLog) {
            Window(
                onCloseRequest = { showFilteringLog = false },
                title = "Filtering log",
                icon = rememberAppIconPainter(),
                state = filteringLogWindowState,
            ) {
                val settings by container.repository.settings.collectAsState()
                MyApplicationTheme(
                    darkTheme = when (settings.themeMode) {
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
                        FilteringLogScreen(
                            viewModel = container.viewModel,
                            // This window is the AdGuard-for-Windows log: the
                            // request-type tabs and the column table. The
                            // Activity tab keeps the app's own card list.
                            adGuardLayout = true,
                        )
                    }
                }
            }
        }
    }
}

/** The status-field glyph size: every tray Linux offers is 24px or smaller. */
private const val TRAY_ICON_PX = 24

/** The app's own mark, 192px, the same art the APK ships. */
private const val APP_ICON_RESOURCE = "/icon/adfree.png"

/**
 * The app icon, read from the packaged resource.
 *
 * A tray entry and a window both want it, and a gradient-and-canvas guess is
 * not the app: a status field that shows a different mark than the APK (or a
 * blank square, when the surface is created before the toolkit is ready) is the
 * icon the desktop cannot match to the app.
 */
private fun loadAppIcon(): ImageBitmap? = runCatching {
    DesktopAppIconResource::class.java.getResourceAsStream(APP_ICON_RESOURCE)
        ?.use { loadImageBitmap(it) }
}.getOrNull()

private object DesktopAppIconResource

/** The dark/green palette, for the painted fallback below. */
private val TrayGreen = Color(0xFF00D06C)
private val TrayBg = Color(0xFF0A0E13)

/**
 * The tray glyph: the app icon when it is on the classpath, and the old painted
 * mark when it is not, so a run without resources still has a visible icon.
 */
@Composable
private fun rememberTrayIcon(): Painter {
    val bitmap = remember { loadAppIcon() ?: paintedTrayGlyph() }
    return BitmapPainter(bitmap)
}

@Composable
private fun rememberAppIconPainter(): Painter? {
    val bitmap = remember { loadAppIcon() } ?: return null
    return BitmapPainter(bitmap)
}

/** The fallback mark, painted once: a tray needs an icon, not a photo. */
private fun paintedTrayGlyph(): ImageBitmap =
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
