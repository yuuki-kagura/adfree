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
     * "Filter localhost" off has to reach every chain that would otherwise
     * take a loopback packet: the two redirects (web and DNS) and the QUIC
     * refusal each need the accept ahead of their own rule, and the switch
     * on must leave the documented ruleset exactly as it was.
     */
    @Test
    fun theLoopbackSwitchDecidesWhetherLoopbackIsLeftAlone() {
        val privileges = DesktopPrivileges()

        // On — the shipped default: no loopback accept anywhere (test above
        // pins the default spelling to the hand-written ruleset).
        val filtered = privileges.ruleset(CoreEngine.PROXY_TCP_PORT, CoreEngine.PROXY_DNS_PORT)
        assertTrue("the shipped default still filters localhost", "ip daddr 127.0.0.1 accept" !in filtered)

        val bypassed = privileges.ruleset(3130, 5301, filterLocalhost = false)
        // Three chains, three chances for a loopback packet to slip through
        // without the accept: http redirect, dns redirect, quic refusal.
        assertEquals(
            "every chain needs the loopback accept: $bypassed",
            3,
            Regex("ip daddr 127\\.0\\.0\\.1 accept").findAll(bypassed).count(),
        )
        // Four, not three: the DNS chain excludes its local resolver whether
        // the switch is on or off (see the loop test below), so it always
        // carries one accept of its own on top of the three switch-driven ones.
        assertEquals(
            "IPv6 loopback is localhost too: $bypassed",
            3,
            Regex("ip6 daddr ::1 accept").findAll(bypassed).count(),
        )
        assertTrue("the redirect still follows", "redirect to :3130" in bypassed)
        assertTrue("the QUIC refusal still follows", "udp dport 443 reject" in bypassed)
        assertTrue("the mark still comes first", "meta mark 0xad45 accept" in bypassed)
    }

    /**
     * The DNS chain captures every account, unlike the web and QUIC chains:
     * DNS filtering only works if the machine's stub is intercepted too, and
     * the loop that looks possible is ruled out in the core, which forwards a
     * query to the real server instead of back into the stub. A second account
     * on this machine keeps its own web and QUIC paths but still gets filtered
     * DNS, which is the half that does not need a certificate.
     */
    @Test
    fun theDnsChainCapturesEveryAccount() {
        val rules = DesktopPrivileges().ruleset(CoreEngine.PROXY_TCP_PORT, CoreEngine.PROXY_DNS_PORT)
        val dnsChain = rules.substringAfter("chain dns {").substringBefore("chain quic {")
        assertTrue(
            "the DNS chain must not be narrowed to one account: $dnsChain",
            "skuid" !in dnsChain,
        )
        assertTrue("it still redirects: $dnsChain", "udp dport 53 redirect" in dnsChain)
        assertTrue(
            "and never TCP/53, where nothing listens: $dnsChain",
            "tcp dport 53" !in dnsChain,
        )
        val httpChain = rules.substringAfter("chain http {").substringBefore("chain dns {")
        assertTrue(
            "the web chain stays scoped to this account: $httpChain",
            "meta skuid" in httpChain,
        )
    }

    /**
     * The table has to die with the unit — including when the unit dies the
     * way no shutdown hook can answer. A hard kill leaves redirect rules aimed
     * at a listener nobody holds, which takes the machine's DNS down with it,
     * and only a root-owned sweep can put that right afterwards. `ExecStopPost`
     * is systemd's own answer: it runs on every way the unit can end.
     */
    @Test
    fun theElevatedUnitSweepsItsRedirectRulesWhenItEnds() {
        val argv = DesktopPrivileges(nftBinary = "/usr/bin/nft").engineUnitArgv(
            command = "/usr/lib/jvm/java/bin/java",
            arguments = listOf("git.shin.adfree.desktop.AdFreeDesktopKt"),
            environment = emptyMap(),
        )
        val sweep = argv.filter { it.startsWith("--property=ExecStopPost=") }
        assertEquals("exactly one sweep", 1, sweep.size)
        assertEquals(
            "the sweep runs nft by absolute path, and its failure is not the unit's",
            "--property=ExecStopPost=-/usr/bin/nft delete table inet adfree",
            sweep.single(),
        )
    }

    /**
     * `Exec*=` verbs are not resolved through the unit's `PATH`, so a bare
     * `nft` would be a command systemd cannot find — silently, since the sweep
     * is prefixed to ignore failure. The path this process would have used has
     * to be handed over as an absolute one.
     */
    @Test
    fun theSweepResolvesNftToAnAbsolutePath() {
        val resolved = DesktopPrivileges(nftBinary = "nft").nftForUnitCommand()
        assertTrue(
            "a bare nft must be resolved on PATH, got $resolved",
            resolved.startsWith("/") && File(resolved).isFile,
        )
    }

    private fun home(vararg relative: String): java.io.File {
        val root = java.io.File.createTempFile("adfree-priv", "").let { it.delete(); it.mkdirs(); it }
        relative.forEach { path ->
            val file = java.io.File(root, path)
            if (path.endsWith("/")) file.mkdirs() else {
                file.parentFile.mkdirs()
                file.writeText("")
            }
        }
        return root
    }

    /**
     * Removal travels through the same `pkexec` helper as the install, with a
     * mode word where the install carries a path: an anchor directory is
     * root-owned, so a removal that only cleared the user's own stores would
     * leave the certificate trusted by every OpenSSL program on the machine.
     */
    @Test
    fun removingTheSystemCaUsesTheSameHelperInRemovalMode() {
        val argv = DesktopPrivileges().caRemoveArgv(
            command = "/usr/lib/jvm/java/bin/java",
            classpath = "/tmp/desktop/lib/adfree-desktop.jar:/tmp/desktop/lib/core.jar",
            coreLibPath = "/tmp/libadfree_core.so",
        )
        assertEquals("pkexec", argv.first())
        assertEquals(
            listOf(
                "git.shin.adfree.desktop.CaInstallKt",
                CA_REMOVE_MODE,
                "/tmp/libadfree_core.so",
            ),
            argv.takeLast(3),
        )
        assertTrue("no certificate path travels for a removal", argv.none { it.endsWith(".pem") })
    }

    /**
     * Taking the certificate out of the NSS databases is a `certutil -D` per
     * database, and the nickname must match the one the install wrote or the
     * removal silently does nothing.
     */
    @Test
    fun removingClearsEveryNssDatabaseByNickname() {
        val commands = mutableListOf<List<String>>()
        val stores = DesktopTrustStores(
            home = home(".pki/nssdb/", ".mozilla/firefox/p1/cert9.db"),
            runner = { argv -> commands += argv; 0 to "" },
        )
        val results = stores.remove()
        assertEquals(2, results.size)
        assertTrue(results.all { it.ok })
        assertEquals(2, commands.size)
        commands.forEach { argv ->
            assertEquals("-D", argv[1])
            assertEquals(DesktopTrustStores.NICKNAME, argv[argv.indexOf("-n") + 1])
            assertTrue(argv.last().startsWith("sql:"))
        }
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

    /**
     * The certificate ask is the same authority with the opposite shape: root,
     * for one write, and an answer the caller actually hears. It goes through
     * `pkexec` rather than the systemd unit the engine uses, because a
     * transient unit is started by a D-Bus call that gives up while a person is
     * still reading the dialog. Both paths travel as arguments because the
     * elevated process is handed a sanitized environment — a helper that read
     * `ADFREE_CORE_LIB` would find nothing and say it had no core.
     */
    @Test
    fun theCertificateAskWaitsForTheAnswerAndCarriesItsOwnPaths() {
        val argv = DesktopPrivileges().caInstallArgv(
            command = "/usr/lib/jvm/java/bin/java",
            classpath = "/tmp/desktop/lib/adfree-desktop.jar:/tmp/desktop/lib/core.jar",
            pemPath = "/home/shin/.local/share/adfree/adfree-ca.pem",
            coreLibPath = "/home/shin/adfree/rust/target/release/libadfree_core.so",
        )
        assertEquals("pkexec", argv.first())
        assertTrue("no systemd properties", argv.none { it.startsWith("--property") })
        assertEquals(
            listOf(
                "/usr/lib/jvm/java/bin/java",
                "--enable-native-access=ALL-UNNAMED",
                "-cp",
                "/tmp/desktop/lib/adfree-desktop.jar:/tmp/desktop/lib/core.jar",
                "git.shin.adfree.desktop.CaInstallKt",
                "/home/shin/.local/share/adfree/adfree-ca.pem",
                "/home/shin/adfree/rust/target/release/libadfree_core.so",
            ),
            argv.takeLast(7),
        )
    }

    /**
     * The argv the elevated unit is built from must not come from
     * `ProcessHandle.Info.arguments()`: that returns an empty Optional once the
     * kernel cmdline passes about one page, and a Gradle-run classpath is
     * several. An empty list here starts `java` with no main class, which
     * prints the usage text and exits — the exact shape of the crash this
     * guards. `/proc/self/cmdline` has no such ceiling, so the reader is
     * checked against a live process instead of a mock.
     */
    @Test
    fun theProcessArgvIsReadPastThePageSizedLimit() {
        val raw = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get("/proc/self/cmdline"))
        val argv = DesktopPrivileges().selfArgv()
        assertTrue("this process must be readable from /proc", argv != null)
        // Same bytes, same split: the reader is a faithful view of the kernel's
        // own record, so it cannot silently drop the tail of a long cmdline.
        assertEquals(
            String(raw, Charsets.UTF_8).split('\u0000').dropLastWhile { it.isEmpty() },
            argv,
        )
        // And when the cmdline is long enough to defeat ProcessHandle, the two
        // readers disagree — which is the whole reason this one exists.
        if (raw.size > 4096) {
            assertTrue(
                "ProcessHandle is expected to give up past a page",
                ProcessHandle.current().info().arguments().isEmpty,
            )
        }
    }

    /**
     * `systemd-run` returns zero when the unit is *started*, not when it stays
     * up, so a successful ask has to be confirmed against the unit itself.
     */
    @Test
    fun aStartedUnitIsNotMistakenForARunningOne() {
        val argv = DesktopPrivileges().engineUnitArgv(
            command = "/usr/lib/jvm/java/bin/java",
            arguments = listOf("-cp", "/tmp/lib/*", "git.shin.adfree.desktop.AdFreeDesktopKt"),
            environment = emptyMap(),
        )
        assertTrue("the unit is named so it can be polled", argv.contains("--unit=adfree-desktop"))
    }

    /**
     * A transient unit starts in `/`, so the working directory has to travel
     * with the ask. `findCoreLibrary` resolves the core relative to it, and an
     * elevated instance that inherits `/` reports `libadfree_core.so not
     * found` while the window that asked had just found it.
     */
    @Test
    fun theUnitCarriesTheWorkingDirectoryTheCoreIsFoundFrom() {
        val argv = DesktopPrivileges().engineUnitArgv(
            command = "/usr/lib/jvm/java/bin/java",
            arguments = listOf("-cp", "/tmp/lib/*", "git.shin.adfree.desktop.AdFreeDesktopKt"),
            environment = emptyMap(),
            workingDirectory = "/home/shin/adfree",
        )
        assertTrue(
            "the unit must not start in /: $argv",
            argv.contains("--property=WorkingDirectory=/home/shin/adfree"),
        )
    }

    /**
     * An unknown working directory is left out rather than sent as an empty
     * property, which systemd rejects before polkit is ever asked.
     */
    @Test
    fun anUnknownWorkingDirectoryIsOmittedRatherThanSentEmpty() {
        val argv = DesktopPrivileges().engineUnitArgv(
            command = "/usr/lib/jvm/java/bin/java",
            arguments = listOf("git.shin.adfree.desktop.AdFreeDesktopKt"),
            environment = emptyMap(),
            workingDirectory = "  ",
        )
        assertTrue("no blank property", argv.none { it.startsWith("--property=WorkingDirectory=") })
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
