package git.shin.adfree.desktop

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.NavigationRailItemDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import git.shin.adfree.core.FilterListBinding
import git.shin.adfree.core.HostVerdictBinding
import git.shin.adfree.core.coreCheckHost
import git.shin.adfree.core.coreFilterBuildErrors
import git.shin.adfree.core.coreFilterSave
import git.shin.adfree.core.coreSetDataRoot
import git.shin.adfree.core.coreSetLists
import git.shin.adfree.core.coreStats
import git.shin.adfree.core.coreVersion
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Colors mirroring the app's dark AdFree palette (same hex values). */
private val EngineGreen = Color(0xFF00D06C)
private val EngineBg = Color(0xFF0A0E13)
private val EngineSurface = Color(0xFF131920)
private val EngineSurfaceVariant = Color(0xFF1B242E)
private val EngineOutline = Color(0xFF283645)
private val EngineRed = Color(0xFFFF435A)
private val EngineTextPrimary = Color(0xFFF3F6F9)
private val EngineTextSecondary = Color(0xFF8B9DAF)
private val EngineTextMuted = Color(0xFF5A6C7D)

/**
 * The Rust core behind a small synchronous façade: one-time load of the
 * native library, a data root in a temp dir, and a saved probe list so host
 * verdicts mean something.
 */
object DesktopEngine {
    private val probeRules = """
        ||doubleclick.net^
        ||google-analytics.com^
        @@ok.doubleclick.net^
    """.trimIndent()

    @Volatile
    private var started = false

    /** Loads the library and compiles the probe lists; false when unusable. */
    @Synchronized
    fun start(): Boolean {
        if (started) return true
        val lib = findCoreLibrary() ?: return false
        System.setProperty("uniffi.component.adfree.libraryOverride", lib.absolutePath)
        val dataRoot = File(System.getProperty("java.io.tmpdir"), "adfree-desktop-ui")
        dataRoot.mkdirs()
        if (!coreSetDataRoot(dataRoot.absolutePath)) return false
        val asset = coreFilterSave("desktop-ui", probeRules) ?: return false
        val binding = FilterListBinding(
            id = 1,
            name = "desktop-ui",
            url = "",
            enabled = true,
            path = asset.path,
            format = 0,
            category = 0,
            trusted = true,
            ruleCount = asset.lineCount,
            lastError = "",
            dnsOnly = false,
        )
        started = coreSetLists(listOf(binding), listOf("||example-ads.com^"))
        return started
    }

    fun version(): String = coreVersion()

    fun activeRules(): Long = coreStats().activeRules

    fun buildErrors(): List<String> = coreFilterBuildErrors().map { it.message }

    fun check(host: String): HostVerdictBinding = coreCheckHost(host)

    val probeHosts = listOf("doubleclick.net", "ok.doubleclick.net", "example-ads.com", "example.com")
}

fun main() {
    application {
        val windowState = rememberWindowState(width = 1100.dp, height = 760.dp)
        Window(
            onCloseRequest = ::exitApplication,
            title = "AdFree desktop",
            state = windowState,
        ) {
            DesktopApp()
        }
    }
}

@Composable
internal fun DesktopApp() {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = EngineGreen,
            onPrimary = Color.Black,
            background = EngineBg,
            onBackground = EngineTextPrimary,
            surface = EngineSurface,
            onSurface = EngineTextPrimary,
            surfaceVariant = EngineSurfaceVariant,
            onSurfaceVariant = EngineTextSecondary,
            outline = EngineOutline,
        )
    ) {
        var tab by remember { mutableStateOf(0) }
        Scaffold(
            containerColor = EngineBg,
            contentColor = EngineTextPrimary,
        ) { innerPadding ->
            Row(Modifier.fillMaxSize().padding(innerPadding)) {
                NavigationRail(
                    containerColor = EngineSurface,
                    header = {
                        Column(Modifier.padding(vertical = 12.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                            Text("AdFree", color = EngineGreen, fontWeight = FontWeight.Bold)
                        }
                    },
                ) {
                    NavigationRailItem(
                        selected = tab == 0,
                        onClick = { tab = 0 },
                        icon = { Icon(Icons.Default.Shield, contentDescription = "Engine") },
                        label = { Text("Engine") },
                        colors = NavigationRailItemDefaults.colors(
                            selectedIconColor = EngineGreen,
                            selectedTextColor = EngineGreen,
                            indicatorColor = EngineSurfaceVariant,
                            unselectedIconColor = EngineTextSecondary,
                            unselectedTextColor = EngineTextMuted,
                        ),
                    )
                    NavigationRailItem(
                        selected = tab == 1,
                        onClick = { tab = 1 },
                        icon = { Icon(Icons.Default.Search, contentDescription = "Host check") },
                        label = { Text("Check") },
                        colors = NavigationRailItemDefaults.colors(
                            selectedIconColor = EngineGreen,
                            selectedTextColor = EngineGreen,
                            indicatorColor = EngineSurfaceVariant,
                            unselectedIconColor = EngineTextSecondary,
                            unselectedTextColor = EngineTextMuted,
                        ),
                    )
                }
                Box(Modifier.weight(1f).fillMaxSize(), contentAlignment = Alignment.TopCenter) {
                    Column(
                        Modifier.fillMaxSize().widthIn(max = 760.dp)
                            .padding(horizontal = 24.dp, vertical = 20.dp)
                            .verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(16.dp),
                    ) {
                        when (tab) {
                            0 -> EngineStatusScreen()
                            else -> HostCheckScreen()
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun EngineStatusScreen() {
    var report by remember { mutableStateOf<EngineReport?>(null) }
    var failed by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        val built = withContext(Dispatchers.IO) { buildEngineReport() }
        if (built == null) failed = true else report = built
    }

    Text("Engine status", style = MaterialTheme.typography.headlineSmall, color = EngineTextPrimary)
    if (failed) {
        Text(
            "${coreLibraryName} not found — run `cargo build --release` in rust/ or set ADFREE_CORE_LIB.",
            color = EngineRed,
        )
        return
    }
    if (report == null) {
        CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp, color = EngineGreen)
        return
    }
    val snapshot = report ?: return

    EngineCard("Core") {
        DetailLine("Version", snapshot.version)
        DetailLine("Data root", snapshot.dataRoot)
        DetailLine("Active rules", snapshot.activeRules.toString())
        DetailLine("Filter build", if (snapshot.buildErrors.isEmpty()) "clean" else snapshot.buildErrors.joinToString())
    }

    EngineCard("Probe verdicts") {
        snapshot.checks.forEach { check ->
            Row(Modifier.fillMaxWidth().padding(vertical = 3.dp), verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier.size(8.dp).background(
                        if (check.blocked) EngineRed else EngineGreen,
                        RoundedCornerShape(4.dp),
                    )
                )
                Spacer(Modifier.width(10.dp))
                Text(check.host, Modifier.weight(1f), color = EngineTextPrimary)
                Text(
                    if (check.blocked) "blocked by ${check.rule} (${check.listName})" else "allowed",
                    color = if (check.blocked) EngineRed else EngineTextSecondary,
                )
            }
        }
    }
}

private data class EngineCheckRow(val host: String, val blocked: Boolean, val rule: String, val listName: String)

private data class EngineReport(
    val version: String,
    val dataRoot: String,
    val activeRules: Long,
    val buildErrors: List<String>,
    val checks: List<EngineCheckRow>,
)

private fun buildEngineReport(): EngineReport? {
    if (!DesktopEngine.start()) return null
    val root = File(System.getProperty("java.io.tmpdir"), "adfree-desktop-ui").absolutePath
    return EngineReport(
        version = DesktopEngine.version(),
        dataRoot = root,
        activeRules = DesktopEngine.activeRules(),
        buildErrors = DesktopEngine.buildErrors(),
        checks = DesktopEngine.probeHosts.map {
            val verdict = DesktopEngine.check(it)
            EngineCheckRow(it, verdict.blocked, verdict.rule, verdict.listName)
        },
    )
}

@Composable
private fun HostCheckScreen() {
    var host by remember { mutableStateOf("doubleclick.net") }
    var verdict by remember { mutableStateOf<HostVerdictBinding?>(null) }
    val scope = rememberCoroutineScope()

    Text("Host check", style = MaterialTheme.typography.headlineSmall, color = EngineTextPrimary)
    OutlinedTextField(
        value = host,
        onValueChange = { host = it },
        label = { Text("Hostname") },
        singleLine = true,
    )
    Button(
        onClick = {
            scope.launch(Dispatchers.IO) {
                if (DesktopEngine.start()) verdict = DesktopEngine.check(host.trim())
            }
        },
        colors = ButtonDefaults.buttonColors(
            containerColor = EngineGreen,
            contentColor = Color.Black,
        ),
    ) { Text("Check") }
    verdict?.let { v ->
        EngineCard("Result for $host") {
            DetailLine("Blocked", v.blocked.toString())
            DetailLine("Rule", v.rule)
            DetailLine("List", v.listName)
        }
    }
}

@Composable
private fun EngineCard(title: String, content: @Composable ColumnScope.() -> Unit) {
    Card(colors = CardDefaults.cardColors(containerColor = EngineSurface)) {
        Column(Modifier.fillMaxWidth().padding(16.dp)) {
            Text(title, color = EngineTextMuted, style = MaterialTheme.typography.labelLarge)
            Spacer(Modifier.size(8.dp))
            content()
        }
    }
}

@Composable
private fun DetailLine(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text(label, Modifier.width(120.dp), color = EngineTextSecondary)
        Text(value, Modifier.weight(1f), color = EngineTextPrimary)
    }
}
