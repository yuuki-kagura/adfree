package git.shin.adfree.desktop

import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.graphics.toAwtImage
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.runComposeUiTest
import androidx.compose.ui.test.waitUntilAtLeastOneExists
import git.shin.adfree.l10n.L10n
import git.shin.adfree.l10n.Strings
import git.shin.adfree.platform.BackRegistry
import git.shin.adfree.platform.LocalAppInventory
import git.shin.adfree.platform.LocalBackRegistry
import git.shin.adfree.platform.LocalFileHost
import git.shin.adfree.platform.LocalPlatformHost
import git.shin.adfree.platform.LocalResumeTick
import git.shin.adfree.ui.AdGuardApp
import git.shin.adfree.ui.theme.MyApplicationTheme
import java.io.File
import javax.imageio.ImageIO
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import org.junit.Test

/**
 * Drives the *whole* app headlessly on Linux: the shared scaffold, the real
 * shared screens, the shared ViewModel and repository, and the actual
 * libadfree_core.so behind the desktop seams. The labels asserted below are
 * produced by L10n from the shared string tables, not hardcoded here.
 */
@OptIn(ExperimentalTestApi::class)
class FullAppUiTest {

    @Test
    fun sharedAppRunsOnDesktopSeams() {
        val dataRoot = File(System.getProperty("java.io.tmpdir"), "adfree-full-${System.nanoTime()}")
        val container = DesktopContainer(dataRoot = dataRoot)
        check(container.engineAvailable) { "libadfree_core.so required: cargo build --release in rust/" }
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        container.start(scope)

        runComposeUiTest {
            val backRegistry = BackRegistry()
            val resumeTick = MutableStateFlow(0L)
            setContent {
                CompositionLocalProvider(
                    LocalPlatformHost provides container.platformHost,
                    LocalFileHost provides container.fileHost,
                    LocalAppInventory provides container.inventory,
                    LocalResumeTick provides resumeTick,
                    LocalBackRegistry provides backRegistry,
                ) {
                    MyApplicationTheme {
                        AdGuardApp(viewModel = container.viewModel)
                    }
                }
            }

            // The rail carries the six L10n destinations and Home renders first.
            onNodeWithText(L10n.get(Strings.nav_home)).assertExists()
            onNodeWithText(L10n.get(Strings.nav_protection)).assertExists()
            onNodeWithText(L10n.get(Strings.nav_settings)).assertExists()
            waitUntilAtLeastOneExists(hasText(L10n.get(Strings.app_name)), 30_000)

            // Tab switch through the shared intent pipeline.
            onNodeWithText(L10n.get(Strings.nav_settings)).performClick()
            waitUntilAtLeastOneExists(
                hasText(L10n.get(Strings.settings_subtitle)),
                30_000,
            )
            onNodeWithText(L10n.get(Strings.settings_group_general)).assertExists()

            val image = onRoot().captureToImage().toAwtImage()
            ImageIO.write(image, "png", File("/tmp/adfree_full_app.png"))
        }
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }
}
