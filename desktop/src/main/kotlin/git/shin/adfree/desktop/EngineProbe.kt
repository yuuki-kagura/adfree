package git.shin.adfree.desktop

import git.shin.adfree.core.FilterListBinding
import git.shin.adfree.core.coreCheckHost
import git.shin.adfree.core.coreDrainEvents
import git.shin.adfree.core.coreFilterBuildErrors
import git.shin.adfree.core.coreFilterSave
import git.shin.adfree.core.coreSetDataRoot
import git.shin.adfree.core.coreSetLists
import git.shin.adfree.core.coreStats
import git.shin.adfree.core.coreVersion
import java.io.File

/**
 * Runs the real Rust engine on the host JVM through the shared uniffi
 * bindings: data root, a saved filter list, a compiled build, host verdicts
 * and the stats snapshot — no Android in sight.
 *
 * The native library is located via ADFREE_CORE_LIB, then the usual
 * `rust/target/release/<core library>` next to the repo root.
 */
fun runEngineProbe(): Boolean {
    val lib = findCoreLibrary()
    if (lib == null) {
        System.err.println("engine probe: ${coreLibraryName} not found — run `cargo build --release` in rust/")
        return false
    }
    System.setProperty("uniffi.component.adfree.libraryOverride", lib.absolutePath)

    println("engine probe: loading ${lib.absolutePath}")
    println("coreVersion() = ${coreVersion()}")

    val dataRoot = File(System.getProperty("java.io.tmpdir"), "adfree-desktop-probe-${ProcessHandle.current().pid()}")
    dataRoot.mkdirs()
    if (!coreSetDataRoot(dataRoot.absolutePath)) {
        System.err.println("engine probe: coreSetDataRoot failed for $dataRoot")
        return false
    }
    println("coreSetDataRoot(${dataRoot.absolutePath}) = true")

    val rules = """
        ||doubleclick.net^
        ||google-analytics.com^
        @@ok.doubleclick.net^
    """.trimIndent()
    val asset = coreFilterSave("desktop-probe", rules)
    if (asset == null) {
        System.err.println("engine probe: coreFilterSave failed")
        return false
    }
    println("coreFilterSave -> path=${asset.path} lineCount=${asset.lineCount}")

    val binding = FilterListBinding(
        id = 1,
        name = "desktop-probe",
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
    if (!coreSetLists(listOf(binding), listOf("||example-ads.com^"))) {
        System.err.println("engine probe: coreSetLists failed")
        return false
    }
    val buildErrors = coreFilterBuildErrors()
    println("coreSetLists = true, buildErrors=${buildErrors.map { it.message }}")

    var ok = buildErrors.isEmpty()
    val expectations = mapOf(
        "doubleclick.net" to true,
        "ads.doubleclick.net" to true,
        "ok.doubleclick.net" to false,
        "example-ads.com" to true,
        "example.com" to false,
    )
    for ((host, expectBlocked) in expectations) {
        val verdict = coreCheckHost(host)
        val asExpected = verdict.blocked == expectBlocked
        if (!asExpected) ok = false
        println("coreCheckHost($host) -> blocked=${verdict.blocked} rule=${verdict.rule} list=${verdict.listName} expected=$expectBlocked")
    }

    val stats = coreStats()
    println("coreStats -> activeRules=${stats.activeRules} dnsBlocked=${stats.dnsBlocked} dnsAllowed=${stats.dnsAllowed}")
    println("coreDrainEvents(16) -> ${coreDrainEvents(16).size} events")

    dataRoot.deleteRecursively()
    println("engine probe: ${if (ok) "OK" else "BUILD ERRORS"}")
    return ok
}
