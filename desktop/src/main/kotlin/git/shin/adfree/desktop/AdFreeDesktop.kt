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
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEvent
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.type
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
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
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow

/**
 * The full AdFree UI on Linux: the shared screens, scaffold and ViewModel
 * exactly as the Android app runs them, with the desktop seams underneath.
 * Escape walks the shared back stack (dialogs, then tab-to-Home) before the
 * window closes.
 */
fun main() {
    val container = DesktopContainer()
    val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    container.start(appScope)
    val resumeTick = MutableStateFlow(0L)
    val backRegistry = BackRegistry()

    application {
        val windowState = rememberWindowState(width = 1200.dp, height = 800.dp)
        Window(
            onCloseRequest = {
                container.repository.setUiVisible(false)
                appScope.cancel()
                exitApplication()
            },
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
                            exitApplication()
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
