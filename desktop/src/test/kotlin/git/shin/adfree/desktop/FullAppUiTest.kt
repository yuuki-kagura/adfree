package git.shin.adfree.desktop

import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.graphics.toAwtImage
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.runComposeUiTest
import androidx.compose.ui.test.waitUntilAtLeastOneExists
import git.shin.adfree.core.CoreEngine
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

            // The rail carries the L10n destinations and Home renders first.
            // The Apps destination is Android-only: no app catalogue here.
            onNodeWithText(L10n.get(Strings.nav_home)).assertExists()
            onNodeWithText(L10n.get(Strings.nav_protection)).assertExists()
            onNodeWithText(L10n.get(Strings.nav_settings)).assertExists()
            onNodeWithText(L10n.get(Strings.nav_apps)).assertDoesNotExist()
            waitUntilAtLeastOneExists(hasText(L10n.get(Strings.app_name)), 30_000)
            // No notification/battery health chips on a desktop OS.
            onNodeWithText(L10n.get(Strings.home_health_notifications)).assertDoesNotExist()
            onNodeWithText(L10n.get(Strings.home_health_battery)).assertDoesNotExist()
            // What a desktop does have: the local proxy the traffic is
            // redirected onto, in place of the Android tunnel status.
            onNodeWithText(L10n.get(Strings.home_proxy_title)).assertExists()
            onNodeWithText("127.0.0.1:${CoreEngine.PROXY_TCP_PORT}").assertExists()
            // The redirect that captures the machine's own traffic needs a
            // privilege a phone gets from VPN consent, so the card carries the
            // request rather than a command line to type out.
            onNodeWithTag("home_ask_privileges").assertExists()

            // Tab switch through the shared intent pipeline.
            onNodeWithText(L10n.get(Strings.nav_settings)).performClick()
            waitUntilAtLeastOneExists(
                hasText(L10n.get(Strings.settings_subtitle)),
                30_000,
            )
            onNodeWithText(L10n.get(Strings.settings_group_general)).assertExists()
            // The routing row and the notification link hide with their capabilities.
            onNodeWithText(L10n.get(Strings.settings_routing_mode_title)).assertDoesNotExist()
            onNodeWithText(L10n.get(Strings.settings_notifications_title)).assertDoesNotExist()
            // The desktop's own listener ports are the row a phone never sees:
            // there the ports are not the user's to move, so nothing binds one.
            onNodeWithText(L10n.get(Strings.settings_local_proxy_title)).assertExists()
            onNodeWithText(L10n.get(Strings.settings_local_proxy_tcp_label)).assertExists()
            onNodeWithText(L10n.get(Strings.settings_local_proxy_dns_label)).assertExists()
            // …and with them the loopback switch that decides whether this
            // machine's own conversations reach the filter at all.
            onNodeWithText(L10n.get(Strings.settings_local_proxy_filter_localhost_title)).assertExists()

            // The desktop shell draws its own window header: the OS title bar
            // says nothing about where in the app you are, and there is no
            // system menu for settings export/import either.
            onNodeWithTag("header_menu").assertExists()
            onNodeWithTag("header_menu").performClick()
            waitUntilAtLeastOneExists(hasText(L10n.get(Strings.header_export_settings)), 30_000)
            onNodeWithText(L10n.get(Strings.header_import_settings)).assertExists()
            // Back stays hidden: no dialog or sub-route is open at the top level.
            onNodeWithTag("header_back").assertDoesNotExist()
            // Choosing the update row runs the desktop update seam (which
            // reports the package-manager answer) and closes the menu again.
            onNodeWithText(L10n.get(Strings.header_check_updates)).performClick()

            // Statistics carries the counter reset AdGuard keeps in its menu.
            // Only the row is driven here: the confirmation it opens is an
            // AlertDialog, and on a desktop that is a separate OS window the
            // test composition cannot see.
            onNodeWithText(L10n.get(Strings.nav_statistics)).performClick()
            waitUntilAtLeastOneExists(hasText(L10n.get(Strings.stats_clear_action)), 30_000)
            onNodeWithTag("stats_clear").assertExists()

            val image = onRoot().captureToImage().toAwtImage()
            ImageIO.write(image, "png", File("/tmp/adfree_full_app.png"))
        }
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }
}
