package git.shin.adfree.desktop

import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.graphics.toAwtImage
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.runComposeUiTest
import androidx.compose.ui.test.waitUntilAtLeastOneExists
import git.shin.adfree.data.AdGuardRepository
import git.shin.adfree.data.writeLogCsv
import git.shin.adfree.l10n.L10n
import git.shin.adfree.l10n.Strings
import git.shin.adfree.model.FilterStatus
import git.shin.adfree.model.NetworkRequestLog
import git.shin.adfree.model.ProtocolType
import git.shin.adfree.model.RequestCategory
import git.shin.adfree.platform.BackRegistry
import git.shin.adfree.platform.FileHost
import git.shin.adfree.platform.LocalAppInventory
import git.shin.adfree.platform.LocalBackRegistry
import git.shin.adfree.platform.LocalFileHost
import git.shin.adfree.platform.LocalPlatformHost
import git.shin.adfree.platform.LocalResumeTick
import git.shin.adfree.ui.AdGuardApp
import git.shin.adfree.ui.theme.MyApplicationTheme
import java.io.File
import java.io.StringWriter
import java.io.Writer
import javax.imageio.ImageIO
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import org.junit.Test

/**
 * The imported file is a whole viewing mode, so it is driven as one: the CSV is
 * written by the app's own exporter, picked by the log screen, and the screen
 * has to show the file's rows and nothing else until it is closed again.
 *
 * Only the picker is faked — reading the file, counting it and holding it
 * apart from the store all run through the real repository on the real core.
 */
@OptIn(ExperimentalTestApi::class)
class LogImportUiTest {

    @Test
    fun anExportedFileReadsIntoTheLogScreenAndBackOut() {
        val dataRoot = File(System.getProperty("java.io.tmpdir"), "adfree-import-${System.nanoTime()}")
        dataRoot.mkdirs()
        val picked = File(dataRoot, "adfree-activity.csv")
        val out = StringWriter()
        writeLogCsv(
            sequenceOf(
                rowAt(1, "imported.example.com", FilterStatus.BLOCKED),
                rowAt(2, "kept.example.com", FilterStatus.ALLOWED),
            ),
            out,
        )
        picked.writeText(out.toString())

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
                    LocalFileHost provides Picker(picked.absolutePath),
                    LocalAppInventory provides container.inventory,
                    LocalResumeTick provides resumeTick,
                    LocalBackRegistry provides backRegistry,
                ) {
                    MyApplicationTheme {
                        AdGuardApp(viewModel = container.viewModel)
                    }
                }
            }

            onNodeWithText(L10n.get(Strings.nav_activity)).performClick()
            waitUntilAtLeastOneExists(hasText(L10n.get(Strings.log_subtitle)), 30_000)
            onNodeWithTag("import_logs_button").assertIsDisplayed()
            onNodeWithTag("export_logs_button").assertIsDisplayed()
            onNodeWithTag("clear_logs_button").assertIsDisplayed()
            onNodeWithTag("log_retention_note").assertIsDisplayed()

            onNodeWithTag("import_logs_button").performClick()

            val banner = L10n.format(Strings.log_imported_viewing, 2L, picked.name)
            waitUntilAtLeastOneExists(hasText(banner), 30_000)
            onNodeWithTag("log_imported_banner").assertIsDisplayed()
            waitUntilAtLeastOneExists(hasText("imported.example.com", substring = true), 30_000)
            // What the file says replaces what the store says, everywhere at
            // once: the note about retention is this machine's history, and so
            // are the actions that would write or wipe it.
            onNodeWithTag("log_retention_note").assertDoesNotExist()
            onNodeWithTag("export_logs_button").assertDoesNotExist()
            onNodeWithTag("clear_logs_button").assertDoesNotExist()
            onNodeWithTag("close_imported_logs_button").assertIsDisplayed()
            ImageIO.write(onRoot().captureToImage().toAwtImage(), "png", File("/tmp/adfree_log_import.png"))

            onNodeWithTag("close_imported_logs_button").performClick()

            onNodeWithTag("log_imported_banner").assertDoesNotExist()
            waitUntilAtLeastOneExists(
                hasText(
                    L10n.format(
                        Strings.log_retention_note,
                        AdGuardRepository.LOG_DB_MAX_ROWS,
                        AdGuardRepository.LOG_DB_KEEP_DAYS,
                    ),
                ),
                30_000,
            )
            onNodeWithTag("import_logs_button").assertIsDisplayed()
            onNodeWithTag("export_logs_button").assertIsDisplayed()
        }
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }

    /** A picker that has already decided: the file the test wrote. */
    private class Picker(private val path: String) : FileHost {
        override suspend fun openText(): String? = path
        override suspend fun createDocument(suggestedName: String, mime: String): String? = null
        override fun readText(uriText: String): String? =
            runCatching { File(uriText).readText() }.getOrNull()

        override fun writeText(uriText: String, text: String): Boolean = false
        override fun openWrite(uriText: String): Writer? = null
        override fun displayName(uriText: String): String = File(uriText).name
        override fun persistRead(uriText: String) = Unit
    }

    private fun rowAt(id: Long, domain: String, status: FilterStatus) = NetworkRequestLog(
        id = id,
        timestampMs = 1_730_000_000_000L,
        domain = domain,
        ipAddress = "10.0.0.$id",
        protocol = ProtocolType.DNS_UDP,
        status = status,
        category = RequestCategory.AD,
        matchedRule = "||$domain^",
        filterListName = "EasyList",
        appPackage = "com.example.app",
        latencyMicros = 120,
        dataSavedBytes = 4_096,
        requestType = "dns",
    )
}
