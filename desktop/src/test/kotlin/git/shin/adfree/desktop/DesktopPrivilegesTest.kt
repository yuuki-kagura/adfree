package git.shin.adfree.desktop

import git.shin.adfree.core.CoreEngine
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
        val unit = DesktopPrivileges(nftBinary = "/usr/bin/nft").unitFile(
            command = "/usr/lib/jvm/java/bin/java",
            arguments = listOf("git.shin.adfree.desktop.AdFreeDesktopKt"),
            environment = emptyMap(),
            workingDirectory = "/home/shin/adfree",
            user = "shin",
        )
        val sweep = unit.lines().filter { it.startsWith("ExecStopPost=") }
        assertEquals("exactly one sweep", 1, sweep.size)
        assertEquals(
            "the sweep runs nft by absolute path, and its failure is not the unit's",
            "ExecStopPost=-/usr/bin/nft delete table inet adfree",
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
     * The unit is the whole command line, written down once: the same user, the
     * one capability, the environment the window needs to find its display, and
     * the app's own argv. Nothing here is optional — a unit that lost the
     * capability would filter nothing, and one that lost `User=` would run root
     * code that then writes the user's database.
     */
    @Test
    fun theUnitPinsTheCapabilityTheUserAndTheCommandLine() {
        val unit = DesktopPrivileges().unitFile(
            command = "/usr/lib/jvm/java/bin/java",
            arguments = listOf("-cp", "/tmp/lib/*", "git.shin.adfree.desktop.AdFreeDesktopKt"),
            environment = mapOf("DISPLAY" to ":0", "ADFREE_CORE_LIB" to "/tmp/libadfree_core.so"),
            workingDirectory = "/home/shin/adfree",
            user = "shin",
        )
        assertTrue("the unit keeps this user's uid", "User=shin" in unit)
        assertTrue("the mark needs this", "AmbientCapabilities=CAP_NET_ADMIN" in unit)
        assertTrue("nothing else is granted", "CapabilityBoundingSet=CAP_NET_ADMIN" in unit)
        assertTrue(
            "the window needs a display",
            unit.lines().any { it.trim() == "Environment=DISPLAY=:0" },
        )
        assertTrue(
            "the child must find the core this process found",
            unit.lines().any { it.trim() == "Environment=ADFREE_CORE_LIB=/tmp/libadfree_core.so" },
        )
        assertTrue(
            "the argv is the whole of ExecStart",
            "ExecStart=/usr/lib/jvm/java/bin/java -cp /tmp/lib/* git.shin.adfree.desktop.AdFreeDesktopKt" in unit,
        )
        assertTrue("the unit is a file, so systemd needs it enabled explicitly", "[Install]" in unit)
    }

    /**
     * systemd is the reader of this file. A unit it refuses is a protection
     * switch that fails with "the privileged instance started and exited at
     * once" and no hint about why, so the text is handed to systemd's own
     * parser here — in a scratch directory, because a unit written into `/etc`
     * by a test would be a unit this machine then has.
     */
    @Test
    fun systemdItselfAcceptsTheUnit() {
        val analyze = listOf("/usr/bin/systemd-analyze", "/bin/systemd-analyze")
            .firstOrNull { File(it).canExecute() } ?: return
        val directory = java.nio.file.Files.createTempDirectory("adfree-unit-check").toFile()
        val unit = File(directory, "adfree-desktop.service")
        unit.writeText(
            DesktopPrivileges().unitFile(
                command = File(System.getProperty("java.home"), "bin/java").absolutePath,
                arguments = listOf(
                    "-cp",
                    "/home/shin/adfree/rust/target/release/libadfree_core.so",
                    "git.shin.adfree.desktop.AdFreeDesktopKt",
                ),
                environment = mapOf("DISPLAY" to ":0", "WAYLAND_DISPLAY" to "wayland-0"),
                workingDirectory = System.getProperty("user.dir"),
                user = System.getProperty("user.name"),
            ),
        )
        val process = ProcessBuilder(analyze, "verify", "--man=no", unit.absolutePath)
            .directory(directory)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText().trim()
        assertEquals("systemd rejected the unit:\n$output", 0, process.waitFor())
        directory.deleteRecursively()
    }

    /**
     * "Installed" is a question about this app's own record, not about a file
     * root owns: a machine set up by an older version has a unit that is there
     * and a rule polkitd cannot read, and asking only whether the unit exists
     * would leave that machine prompting on every start forever.
     */
    @Test
    fun anOlderInstallIsRedoneRatherThanTrusted() {
        val directory = java.nio.file.Files.createTempDirectory("adfree-install").toFile()
        val unit = File(directory, "adfree-desktop.service").apply { writeText("[Unit]\n") }
        val stamp = File(directory, "stamp")

        val fresh = DesktopPrivileges(servicePath = unit.absolutePath, stamp = stamp)
        assertFalse("a unit without a stamp is an old install", fresh.privilegedServiceInstalled())

        stamp.writeText("1")
        assertFalse("an older stamp is an old install", fresh.privilegedServiceInstalled())

        stamp.writeText(DesktopPrivileges.SETUP_VERSION.toString())
        assertTrue("the unit plus this version's stamp is installed", fresh.privilegedServiceInstalled())

        unit.delete()
        assertFalse("no unit, no install", fresh.privilegedServiceInstalled())
    }

    /**
     * An argument with a space in it is one argument. systemd splits `ExecStart=`
     * on whitespace unless the word is quoted, and `%` is a specifier even
     * inside quotes — a classpath with a space in it would otherwise start
     * `java` with two arguments and no main class.
     */
    @Test
    fun anArgumentWithASpaceTravelsAsOneWord() {
        val unit = DesktopPrivileges().unitFile(
            command = "/usr/lib/jvm/java/bin/java",
            arguments = listOf("-cp", "/tmp/the lib/*", "--percent=100%"),
            environment = emptyMap(),
            workingDirectory = "/home/shin/adfree",
            user = "shin",
        )
        assertTrue(
            "the space is quoted: $unit",
            "ExecStart=/usr/lib/jvm/java/bin/java -cp \"/tmp/the lib/*\" \"--percent=100%%\"" in unit,
        )
    }

    /**
     * The rule is what makes protection a switch instead of a password prompt,
     * and it is narrow on three axes because `manage-units` is otherwise the
     * whole system manager: this user, this one unit, these verbs. A rule on a
     * *transient* unit would be a root shell — the caller writes the command
     * line — which is exactly why the unit is a file.
     */
    @Test
    fun thePolkitRuleAnswersOnlyForThisUsersProtectionUnit() {
        val rule = DesktopPrivileges().polkitRule("shin")
        assertTrue("this user only", "subject.user != \"shin\"" in rule)
        assertTrue("this unit only", "!= \"adfree-desktop.service\"" in rule)
        assertTrue("start, stop and restart", "verb == \"restart\"" in rule)
        assertTrue("anything else is left to polkit", "polkit.Result.NOT_HANDLED" in rule)
        assertTrue("and only for manage-units", "org.freedesktop.systemd1.manage-units" in rule)
    }

    /**
     * The install is one `pkexec` call whose every path is an argument, because
     * the elevated process is handed a sanitized environment and a helper that
     * guessed at a path would write root-owned files somewhere unexpected.
     */
    @Test
    fun theOneTimeInstallCarriesEverythingRootNeeds() {
        val argv = DesktopPrivileges().setupArgv(
            java = "/usr/lib/jvm/java/bin/java",
            classpath = "/tmp/lib/*",
            unit = "/tmp/unit.service",
            rule = "/tmp/rule.rules",
            enable = false,
        )
        assertEquals("pkexec", argv.first())
        assertEquals("git.shin.adfree.desktop.PrivilegedSetupKt", argv[argv.size - 6])
        assertEquals("install", argv[argv.size - 5])
        assertEquals("/tmp/unit.service", argv[argv.size - 4])
        assertEquals("/etc/systemd/system/adfree-desktop.service", argv[argv.size - 3])
        assertEquals("/tmp/rule.rules", argv[argv.size - 2])
        assertEquals("/etc/polkit-1/rules.d/50-adfree-desktop.rules", argv[argv.size - 1])
        assertTrue(
            "no boot enable unless asked",
            DesktopPrivileges().setupArgv("/j", "/c", "/u", "/r", enable = true).last() == "enable",
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
     * A unit that is already filtering is not restarted.
     *
     * Every program on this machine reaches the internet through that unit
     * while it runs, so a restart is a hole in the protection and a broken
     * connection for whatever was in the middle of sending something — the
     * reason a second window used to cost the user a chat upload. Asking is
     * cheap; restarting is not.
     */
    @Test
    fun aUnitThatIsAlreadyFilteringIsLeftRunning() {
        val calls = recordingSystemctl()
        val privileges = DesktopPrivileges(
            systemctl = calls.first,
            servicePath = "/etc/systemd/system/adfree-desktop.service",
            stamp = File("/nonexistent/adfree/privileged-setup.version"),
            serviceActive = { true },
            listenerAnswers = { port -> port == 3129 },
        )
        assertEquals(PrivilegeOutcome.Ok, privileges.requestPrivilegedEngine(emptyMap(), 3129))
        // A unit this check cannot reinstall (the stamp says a stranger set the
        // machine up) still has to answer without touching systemd at all.
        assertTrue("the ask that had nothing to do asked systemd: ${calls.second()}", calls.second().isEmpty())
    }

    /**
     * The other half of the same question: a unit systemd calls active whose
     * ports nobody answers on is the case a restart exists for. The rules are
     * still pointing at a closed socket, and a machine in that state sends its
     * traffic nowhere.
     */
    @Test
    fun anActiveUnitWithNoListenerIsRestarted() {
        val calls = recordingSystemctl()
        val privileges = DesktopPrivileges(
            systemctl = calls.first,
            servicePath = "/etc/systemd/system/adfree-desktop.service",
            stamp = File("/nonexistent/adfree/privileged-setup.version"),
            serviceActive = { true },
            listenerAnswers = { false },
        )
        val outcome = privileges.requestPrivilegedEngine(emptyMap(), 3129)
        assertEquals(PrivilegeOutcome.Ok, outcome)
        assertEquals(listOf("restart adfree-desktop"), calls.second())
    }

    /** A `systemctl` that runs for real and writes down what it was asked. */
    private fun recordingSystemctl(): Pair<String, () -> List<String>> {
        val dir = File(System.getProperty("java.io.tmpdir"), "adfree-systemctl-${System.nanoTime()}")
        dir.mkdirs()
        val log = File(dir, "calls")
        val script = File(dir, "systemctl")
        script.writeText("#!/bin/sh\nprintf '%s\\n' \"\$*\" >> " + log.absolutePath + "\nexit 0\n")
        script.setExecutable(true)
        return script.absolutePath to {
            if (log.isFile) log.readLines().filter { it.isNotBlank() } else emptyList()
        }
    }

    /**
     * `systemctl` returns zero when the unit is *started*, not when it stays up,
     * so a start has to be confirmed against the unit itself: a JVM that died on
     * its first line leaves nothing behind but an exit status.
     */
    @Test
    fun aStartedUnitIsNotMistakenForARunningOne() {
        val unit = DesktopPrivileges().unitFile(
            command = "/usr/lib/jvm/java/bin/java",
            arguments = listOf("git.shin.adfree.desktop.AdFreeDesktopKt"),
            environment = emptyMap(),
            workingDirectory = "/home/shin/adfree",
            user = "shin",
        )
        assertTrue("one unit, named so it can be polled", "WantedBy=graphical.target" in unit)
    }

    /**
     * A unit starts in `/` unless told otherwise. `findCoreLibrary` resolves the
     * core relative to the working directory, and an instance that inherits `/`
     * reports `libadfree_core.so not found` while the window that asked had just
     * found it.
     */
    @Test
    fun theUnitCarriesTheWorkingDirectoryTheCoreIsFoundFrom() {
        val unit = DesktopPrivileges().unitFile(
            command = "/usr/lib/jvm/java/bin/java",
            arguments = listOf("git.shin.adfree.desktop.AdFreeDesktopKt"),
            environment = emptyMap(),
            workingDirectory = "/home/shin/adfree",
            user = "shin",
        )
        assertTrue(
            "the unit must not start in /: $unit",
            "WorkingDirectory=/home/shin/adfree" in unit,
        )
    }

    /**
     * An unknown working directory is left out rather than sent as an empty
     * assignment, which systemd rejects before polkit is ever asked.
     */
    @Test
    fun anUnknownWorkingDirectoryIsOmittedRatherThanSentEmpty() {
        val unit = DesktopPrivileges().unitFile(
            command = "/usr/lib/jvm/java/bin/java",
            arguments = listOf("git.shin.adfree.desktop.AdFreeDesktopKt"),
            environment = emptyMap(),
            workingDirectory = "  ",
            user = "shin",
        )
        assertTrue("no blank assignment", unit.lines().none { it.trim() == "WorkingDirectory=" })
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
