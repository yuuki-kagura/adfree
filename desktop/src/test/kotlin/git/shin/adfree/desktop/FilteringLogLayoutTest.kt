package git.shin.adfree.desktop

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.width
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.runComposeUiTest
import androidx.compose.ui.unit.dp
import git.shin.adfree.platform.BackRegistry
import git.shin.adfree.platform.LocalAppInventory
import git.shin.adfree.platform.LocalBackRegistry
import git.shin.adfree.platform.LocalFileHost
import git.shin.adfree.platform.LocalPlatformHost
import git.shin.adfree.platform.LocalResumeTick
import git.shin.adfree.ui.screens.FilteringLogScreen
import git.shin.adfree.ui.theme.MyApplicationTheme
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import org.junit.Test

/**
 * The two surfaces the log has, and the difference between them.
 *
 * The Activity tab is the app's own screen and keeps the card list it has
 * always had. The desktop's separate Filtering log window is the
 * AdGuard-for-Windows log — request-type tabs and a column table — and it is a
 * popup beside the tabbed UI, not a replacement for that tab. This test pins
 * the switch that keeps the two apart, because the failure mode is silent: the
 * window looks right while the tab has quietly become the same thing.
 */
@OptIn(ExperimentalTestApi::class)
class FilteringLogLayoutTest {

    private fun container(): DesktopContainer {
        val dataRoot = File(System.getProperty("java.io.tmpdir"), "adfree-log-${System.nanoTime()}")
        val container = DesktopContainer(dataRoot = dataRoot)
        check(container.engineAvailable) { "libadfree_core.so required: cargo build --release in rust/" }
        container.start(CoroutineScope(SupervisorJob() + Dispatchers.Default))
        return container
    }

    /**
     * The tab's shape: no request-type strip, no table header. A window wide
     * enough for the table still gets cards, because the tab is not the
     * AdGuard-shaped surface.
     */
    @Test
    fun theActivityTabKeepsItsCardList() {
        val container = container()
        runComposeUiTest {
            setContent {
                CompositionLocalProvider(
                    LocalPlatformHost provides container.platformHost,
                    LocalFileHost provides container.fileHost,
                    LocalAppInventory provides container.inventory,
                    LocalResumeTick provides MutableStateFlow(0L),
                    LocalBackRegistry provides BackRegistry(),
                ) {
                    MyApplicationTheme {
                        // Wider than TABLE_MIN_WIDTH on purpose: a table here
                        // would be the regression this guards.
                        Box(modifier = Modifier.width(1200.dp)) {
                            FilteringLogScreen(viewModel = container.viewModel)
                        }
                    }
                }
            }
            onNodeWithTag("log_type_tabs").assertDoesNotExist()
            onNodeWithTag("log_table_header").assertDoesNotExist()
        }
    }

    /**
     * The popup's shape: the request-type strip is there, because that window
     * exists to be AdGuard's log.
     */
    @Test
    fun theFilteringLogWindowIsTheAdGuardShapedOne() {
        val container = container()
        runComposeUiTest {
            setContent {
                CompositionLocalProvider(
                    LocalPlatformHost provides container.platformHost,
                    LocalFileHost provides container.fileHost,
                    LocalAppInventory provides container.inventory,
                    LocalResumeTick provides MutableStateFlow(0L),
                    LocalBackRegistry provides BackRegistry(),
                ) {
                    MyApplicationTheme {
                        Box(modifier = Modifier.width(1200.dp)) {
                            FilteringLogScreen(
                                viewModel = container.viewModel,
                                adGuardLayout = true,
                            )
                        }
                    }
                }
            }
            onNodeWithTag("log_type_tabs").assertExists()
        }
    }
}
