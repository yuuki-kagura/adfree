package git.shin.adfree.desktop

import git.shin.adfree.core.CoreEngine
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The ruleset the app installs and the one documented for a terminal are two
 * spellings of the same thing; if they drift, the manual instructions stop
 * describing what the app does.
 */
class DesktopPrivilegesTest {

    @Test
    fun theGeneratedRulesetMatchesTheHandWrittenOne() {
        val generated = significantLines(
            DesktopPrivileges().ruleset(CoreEngine.PROXY_TCP_PORT, CoreEngine.PROXY_DNS_PORT)
        )
        val documented = significantLines(repositoryRules().readText())
        assertEquals(documented, generated)
    }

    @Test
    fun theRulesetFollowsThePortsItIsGiven() {
        val rules = DesktopPrivileges().ruleset(3130, 5301)
        assertTrue("the tcp port must move", "redirect to :3130" in rules)
        assertTrue("the dns port must move", "redirect to :5301" in rules)
        assertTrue("the mark must be the core's", "meta mark 0xad45 accept" in rules)
    }

    /**
     * systemd-run rejects `-p=Key=Value` as an assignment with an empty key,
     * and it does so before polkit is asked — so a mistyped flag looks exactly
     * like a machine that refuses to grant anything.
     */
    @Test
    fun theEngineUnitCommandUsesFlagsSystemdAccepts() {
        val argv = DesktopPrivileges().engineUnitArgv(
            command = "/usr/lib/jvm/java/bin/java",
            arguments = listOf("-cp", "/tmp/lib/*", "git.shin.adfree.desktop.AdFreeDesktopKt"),
            environment = mapOf("DISPLAY" to ":0", "ADFREE_CORE_LIB" to "/tmp/libadfree_core.so"),
        )
        assertEquals("systemd-run", argv.first())
        assertTrue(argv.contains("--property=AmbientCapabilities=CAP_NET_ADMIN"))
        assertTrue(argv.contains("--property=CapabilityBoundingSet=CAP_NET_ADMIN"))
        assertTrue(argv.contains("--property=Environment=DISPLAY=:0"))
        assertTrue("no short -p= form", argv.none { it.startsWith("-p=") })
        assertTrue("the unit keeps this user's uid", argv.any { it.startsWith("--uid=") })
        assertEquals(
            listOf("/usr/lib/jvm/java/bin/java", "-cp", "/tmp/lib/*", "git.shin.adfree.desktop.AdFreeDesktopKt"),
            argv.takeLast(4),
        )
    }

    /** Comment and blank lines carry no meaning to nft, so they are not compared. */
    private fun significantLines(text: String): List<String> = text.lines()
        .map { it.trim() }
        .filter { it.isNotEmpty() && !it.startsWith("#") }

    private fun repositoryRules(): File {
        var dir = File(".").absoluteFile
        repeat(5) {
            val candidate = File(dir, "tools/adfree-linux.nft")
            if (candidate.isFile) return candidate
            dir = dir.parentFile
        }
        error("tools/adfree-linux.nft not found from ${File(".").absolutePath}")
    }
}
