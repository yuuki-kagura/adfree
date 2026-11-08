package git.shin.adfree.desktop

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.ptr.IntByReference
import java.io.File
import java.nio.file.Files
import java.nio.file.Paths

/**
 * The first argument [CaInstall] reads as "take the certificate out" instead of
 * a PEM path. One spelling shared by the argv builder and the helper, because a
 * helper that compared a different word would sit in the install branch and
 * report a missing certificate file.
 */
internal const val CA_REMOVE_MODE = "remove"

/**
 * What the desktop needs from the system, and how it asks for it.
 *
 * Filtering on Linux is a kernel conversation: `nft` redirect rules move the
 * machine's traffic onto the local listeners, and the listeners' own upstream
 * sockets have to carry `SO_MARK` or the redirect feeds the proxy back into
 * itself. Both need `CAP_NET_ADMIN`. A process without it is not broken — it
 * just filters only what is pointed at it — so the app says which of the two
 * it is and offers the one command that changes it, rather than telling the
 * user to open a terminal. Trusting the certificate is the same conversation
 * with a different capability, answered by the system's own dialog because a
 * desktop has no `su` and no OS screen that could import a PEM. The protection
 * itself is a root-owned unit that the app installs once — a unit file plus one
 * polkit rule that answers for this exact command line — so later starts ask
 * the system for nothing; a one-shot helper only needs root for as long as it
 * writes, so it asks through `pkexec`, which waits for the answer rather than
 * for twenty-five seconds.
 */
class DesktopPrivileges(
    private val nftBinary: String = "nft",
    private val pkexec: String = "pkexec",
    private val systemctl: String = "systemctl",
    private val log: (String) -> Unit = { System.err.println("[desktop] $it") },
    /** Where the one-time install left the unit; a fixed path on a real machine. */
    private val servicePath: String = SERVICE_PATH,
    /**
     * The app's own record of the install. The rule's own directory belongs to
     * root and polkitd, so "is it there" cannot be asked — but "did this version
     * of the app write it" can, and that is the question that matters after an
     * install format changes.
     */
    private val stamp: java.io.File = File(
        System.getenv("XDG_DATA_HOME") ?: File(System.getProperty("user.home"), ".local/share").absolutePath,
        "adfree/privileged-setup.version",
    ),
    /**
     * Whether the protection unit is running, and whether something answers on
     * the local proxy port. Both are read-only questions; the tests replace
     * them so a machine's own systemd and sockets are not the test's business.
     */
    private val serviceActive: () -> Boolean = {
        runCatching {
            ProcessBuilder(systemctl, "is-active", UNIT_NAME)
                .redirectErrorStream(true)
                .start()
                .let { process ->
                    val text = process.inputStream.bufferedReader().readText().trim()
                    process.waitFor() == 0 && text == "active"
                }
        }.getOrDefault(false)
    },
    private val listenerAnswers: (Int) -> Boolean = ::probeProxyListener,
) {

    /** True when this process may mark its own sockets, i.e. holds `CAP_NET_ADMIN`. */
    fun canSetFirewallMark(): Boolean {
        val fd = CLib.INSTANCE.socket(AF_INET, SOCK_DGRAM, 0)
        if (fd < 0) return false
        return try {
            CLib.INSTANCE.setsockopt(fd, SOL_SOCKET, SO_MARK, IntByReference(FIREWALL_MARK), 4) == 0
        } finally {
            CLib.INSTANCE.close(fd)
        }
    }

    /**
     * The uid of this process, or 1000 when `/proc` cannot say: the rules only
     * capture the account that runs the app.
     */
    private fun currentUid(): Int =
        runCatching {
            (java.nio.file.Files.getAttribute(
                java.nio.file.Path.of("/proc/self"),
                "unix:uid",
            ) as Number).toInt()
        }.getOrElse { 1000 }

    /**
     * Whether the one-time install has happened on this machine.
     *
     * The unit is root-owned but world-readable, so asking is a plain read: a
     * question about whether a file exists must not cost a password.
     */
    fun privilegedServiceInstalled(): Boolean =
        File(servicePath).isFile && installStamp() == SETUP_VERSION

    /** What the last successful install wrote, or 0 when nothing did. */
    private fun installStamp(): Int =
        runCatching { stamp.readText().trim().toInt() }.getOrDefault(0)

    /**
     * Bumped when the install's format changes — a rule that polkitd could not
     * read is the reason this exists. An older stamp is not "installed": the
     * next ask rewrites both files instead of leaving a machine that prompts on
     * every start.
     */
    private fun writeInstallStamp() {
        runCatching {
            stamp.parentFile?.mkdirs()
            stamp.writeText(SETUP_VERSION.toString())
        }.onFailure { log("could not record the install: ${it.message}") }
    }

    /**
     * The protection unit, as a file the system starts rather than a transient
     * unit the app asks for.
     *
     * The command line is fixed here on purpose: a polkit rule that lets the
     * user start a *transient* unit is a rule that lets them start any command
     * as root, because a transient unit carries its own `ExecStart`. A unit
     * file is root-owned, so the same rule grants exactly one command line —
     * this app, with the capability it needs.
     */
    internal fun unitFile(
        command: String,
        arguments: List<String>,
        environment: Map<String, String>,
        workingDirectory: String?,
        user: String,
    ): String {
        val exec = (listOf(command) + arguments).joinToString(" ") { systemdQuote(it) }
        return buildString {
            appendLine("[Unit]")
            appendLine("Description=AdFree filtering with CAP_NET_ADMIN")
            appendLine("Documentation=https://adfree.local")
            appendLine()
            appendLine("[Service]")
            appendLine("Type=simple")
            appendLine("User=$user")
            appendLine("AmbientCapabilities=CAP_NET_ADMIN")
            appendLine("CapabilityBoundingSet=CAP_NET_ADMIN")
            workingDirectory?.takeIf { it.isNotBlank() }?.let { appendLine("WorkingDirectory=${systemdQuote(it)}") }
            environment.forEach { (key, value) ->
                appendLine("Environment=${systemdQuote("$key=$value")}")
            }
            appendLine("ExecStart=$exec")
            // The same sweep the transient unit carried: a stop that outlives
            // TimeoutStopSec, an OOM kill or a crash leaves `table inet adfree`
            // behind, and rules aimed at a listener nobody holds are a machine
            // with no DNS and no web.
            appendLine("ExecStopPost=-${systemdQuote(nftForUnitCommand())} delete table inet adfree")
            appendLine()
            appendLine("[Install]")
            appendLine("WantedBy=graphical.target")
        }
    }

    /**
     * The rule that lets this user start that one unit — and nothing else.
     *
     * `manage-units` covers the whole system manager, so the rule narrows it on
     * three axes: this user, this unit, these verbs. A unit name is enough to
     * be safe precisely because [unitFile] pins the command line; were the unit
     * transient, this rule would be a root shell.
     */
    internal fun polkitRule(user: String): String = """
        // Written by AdFree's one-time setup. It removes the authentication
        // dialog from starting the app's own protection unit — the unit file
        // is root-owned and pins one command line, so this grants that command
        // line, not arbitrary root. Delete this file to ask for a password
        // again on every start.
        polkit.addRule(function(action, subject) {
            if (action.id != "org.freedesktop.systemd1.manage-units") {
                return polkit.Result.NOT_HANDLED;
            }
            if (subject.user != "$user") {
                return polkit.Result.NOT_HANDLED;
            }
            if ((action.lookup("unit") || "") != "$UNIT_NAME.service") {
                return polkit.Result.NOT_HANDLED;
            }
            var verb = action.lookup("verb") || "";
            if (verb == "start" || verb == "stop" || verb == "restart") {
                return polkit.Result.YES;
            }
            return polkit.Result.NOT_HANDLED;
        });
    """.trimIndent()

    /**
     * The one-time install: write the unit and the polkit rule, reload systemd,
     * optionally enable the unit at boot. One dialog, once per machine; every
     * start afterwards goes through [startInstalledService] and asks nothing.
     *
     * It is deliberately blind to what the app is doing right now. The caller
     * releases its listeners before starting the unit, as it already does for
     * the transient path.
     */
    fun installPrivilegedService(
        environment: Map<String, String>,
        startAtBoot: Boolean = false,
    ): PrivilegeOutcome {
        val self = selfArgv()
            ?: return PrivilegeOutcome.Failed("cannot read this process's own command line")
        // A unit pins one command line forever, so it must be a line that can
        // start on its own. Gradle's worker cannot: it talks to the run that
        // spawned it over stdin, and systemd gives it an empty one. Writing
        // such a unit would leave the machine with protection that comes up
        // green and dies on every boot, which is worse than not offering it.
        unstartableCommand(self)?.let { return PrivilegeOutcome.Failed(it) }
        val user = System.getProperty("user.name")
            ?: return PrivilegeOutcome.Failed("cannot tell which user this is")
        val staging = runCatching {
            val unit = File.createTempFile("adfree-unit-", ".service")
            unit.writeText(
                unitFile(self.first(), self.drop(1), environment, System.getProperty("user.dir"), user),
            )
            val rule = File.createTempFile("adfree-polkit-", ".rules")
            rule.writeText(polkitRule(user))
            unit to rule
        }.getOrElse { return PrivilegeOutcome.Failed(it.message ?: "cannot stage the unit") }
        val argv = setupArgv(
            java = self.first(),
            classpath = System.getProperty("java.class.path"),
            unit = staging.first.absolutePath,
            rule = staging.second.absolutePath,
            enable = startAtBoot,
        )
        val outcome = try {
            run(*argv.toTypedArray(), deniedExit = PKEXEC_DENIED)
        } finally {
            staging.first.delete()
            staging.second.delete()
        }
        if (outcome is PrivilegeOutcome.Ok) writeInstallStamp()
        return outcome
    }

    /** Takes the unit and the rule back out. Also one dialog, once. */
    fun removePrivilegedService(): PrivilegeOutcome {
        val command = selfArgv()?.first()
            ?: return PrivilegeOutcome.Failed("cannot read this process's own command line")
        val argv = removeSetupArgv(command, System.getProperty("java.class.path"))
        return run(*argv.toTypedArray(), deniedExit = PKEXEC_DENIED)
    }

    /**
     * Starts the installed unit — no dialog, because the rule written at
     * install time answers for this user on this unit.
     *
     * `restart` rather than `start`: a unit left active by an instance that
     * has since lost its window would make `start` a no-op, and the caller has
     * already given up its listeners by the time this runs, so "nothing to do"
     * here would hand the machine to an instance nobody is watching. systemd
     * starts an inactive unit for `restart` exactly as for `start`.
     */
    fun startInstalledService(): PrivilegeOutcome {
        val outcome = run(systemctl, "restart", UNIT_NAME)
        if (outcome !is PrivilegeOutcome.Ok) return outcome
        return awaitUnitRunning()
    }

    /** The `pkexec` call for the setup helper, as data rather than a shell line. */
    internal fun setupArgv(
        java: String,
        classpath: String,
        unit: String,
        rule: String,
        enable: Boolean,
    ): List<String> = buildList {
        add(pkexec)
        add(java)
        add("--enable-native-access=ALL-UNNAMED")
        add("-cp")
        add(classpath)
        add(SETUP_MAIN)
        add("install")
        add(unit)
        add(servicePath)
        add(rule)
        add(POLKIT_PATH)
        if (enable) add("enable")
    }

    internal fun removeSetupArgv(java: String, classpath: String): List<String> = listOf(
        pkexec,
        java,
        "--enable-native-access=ALL-UNNAMED",
        "-cp",
        classpath,
        SETUP_MAIN,
        "remove",
        servicePath,
        POLKIT_PATH,
    )

    /**
     * The redirect ruleset for these ports. The mark is what keeps the proxy's
     * own traffic out of the loop, so the rules only make sense alongside it —
     * [installRules] refuses without it rather than taking the machine's DNS
     * and web traffic into a loop.
     *
     * `filterLocalhost` is AdGuard for Windows' "Filter localhost": off, the
     * loopback accepts come before every redirect and before the QUIC
     * refusal, so this machine's conversations with itself — a local dev
     * server, the stub resolver, an HTTP/3 service next door — keep their own
     * answers instead of reaching the filter. Only loopback: a neighbour on
     * the LAN is still the filter's business, and the mark stays first so the
     * proxy's own dials never loop either way.
     */
    fun ruleset(
        tcpPort: Int,
        dnsPort: Int,
        filterLocalhost: Boolean = true,
        uid: Int = currentUid(),
    ): String {
        val mark = FIREWALL_MARK.toString(16)
        // Only this user's own traffic is captured. Every daemon on the machine
        // — `systemd-resolved` above all, whose upstream queries would otherwise
        // be handed back to the listener that asks it — keeps its own path, and
        // so does a second user's session: a proxy owned by one account must not
        // be able to take the others offline.
        val mine = "\n                    meta skuid != $uid accept"

        val bypass = if (filterLocalhost) {
            ""
        } else {
            "\n                    ip daddr 127.0.0.1 accept" +
                "\n                    ip6 daddr ::1 accept"
        }
        return """
            table inet adfree {
                chain http {
                    type nat hook output priority -100; policy accept;
                    meta mark 0x$mark accept$mine$bypass
                    meta l4proto tcp tcp dport { 80, 443 } redirect to :$tcpPort
                }
                chain dns {
                    type nat hook output priority -100; policy accept;
                    meta mark 0x$mark accept$bypass
                    # Every account and every resolver is captured here, because
                    # this is where DNS filtering happens: an app asks the
                    # machine's stub, the stub asks upstream, and both halves
                    # have to reach the listener or the answer arrives unfiltered.
                    # The loop that looks possible — listener forwards, stub asks
                    # upstream, redirect catches it again — does not happen:
                    # `proxy::dns::resolver_addr` forwards a query to the real
                    # server, never into the stub it came from.
                    #
                    # UDP only: the listener answers on a datagram socket, so a
                    # redirected TCP/53 would land on a port nothing speaks TCP
                    # on — a black hole for every query that fell back to TCP
                    # after a truncated answer.
                    meta l4proto udp udp dport 53 redirect to :$dnsPort
                }
                chain quic {
                    type filter hook output priority 0; policy accept;
                    meta mark 0x$mark accept$mine$bypass
                    udp dport 443 reject with icmpx type admin-prohibited
                }
            }
        """.trimIndent()
    }

    /**
     * Installs the ruleset. Fails without the mark: see [ruleset]. The table is
     * dropped first because `nft -f` appends — applying the same file twice
     * would leave two redirects on every port.
     */
    fun installRules(tcpPort: Int, dnsPort: Int, filterLocalhost: Boolean = true): PrivilegeOutcome {
        if (!canSetFirewallMark()) {
            return PrivilegeOutcome.Denied(
                "this process cannot mark its own sockets, so the redirect would loop its traffic",
            )
        }
        removeRules()
        val file = File.createTempFile("adfree-", ".nft")
        return try {
            file.writeText(ruleset(tcpPort, dnsPort, filterLocalhost))
            run(nftBinary, "-f", file.absolutePath)
        } finally {
            file.delete()
        }
    }

    fun removeRules(): PrivilegeOutcome = run(nftBinary, "delete", "table", "inet", "adfree")

    /** Whether the rules are live right now — read-only, so it needs no privilege. */
    fun rulesInstalled(): Boolean =
        runCatching {
            ProcessBuilder(nftBinary, "list", "table", "inet", "adfree")
                .redirectErrorStream(true)
                .start()
                .waitFor() == 0
        }.getOrDefault(false)

    /**
     * Protection with the capability it needs: install the fixed unit once,
     * then start it.
     *
     * The transient `systemd-run --system` this replaces asked polkit on every
     * start — that is what made the protection switch a password prompt. A unit
     * file plus one rule answers for this user and this unit forever, so the
     * switch is a switch again. The first call still asks, because writing into
     * `/etc/systemd/system` is a write; every later call does not.
     *
     * The caller must have released the listeners first: the unit it starts
     * binds the same ports.
     */
    fun requestPrivilegedEngine(
        environment: Map<String, String>,
        proxyPort: Int = DEFAULT_PROXY_PORT,
    ): PrivilegeOutcome {
        if (!privilegedServiceInstalled()) {
            val installed = installPrivilegedService(environment)
            if (installed !is PrivilegeOutcome.Ok) return installed
        }
        // A unit that is already filtering is left alone. Restarting it would
        // drop every connection the machine has open through the proxy — a
        // message being sent in another window, a call in progress — and buy
        // nothing: the instance this ask wanted is the one already running.
        // The listener has to answer, though: systemd calls a unit active for
        // as long as its process lives, and a process that lost its ports is
        // exactly the case a restart is for.
        if (unitActive() && listenerAnswers(proxyPort)) {
            log("the privileged instance is already filtering; leaving it running")
            return PrivilegeOutcome.Ok
        }
        return startInstalledService()
    }

    /**
     * This process's own argv, read from `/proc` rather than from
     * `ProcessHandle`.
     *
     * `ProcessHandle.Info.arguments()` returns an empty Optional once the
     * kernel's cmdline passes roughly one page (4096 bytes), and a Gradle-run
     * classpath is several pages of jar paths — 7 KB on this machine. An empty
     * argument list here is not a cosmetic loss: the elevated unit would start
     * `java` with no main class, print the usage text and exit, which reads
     * exactly like a machine that refused the privilege. `/proc/self/cmdline`
     * carries the same bytes with no such ceiling.
     */
    internal fun selfArgv(): List<String>? = runCatching {
        val raw = Files.readAllBytes(Paths.get("/proc/self/cmdline"))
        String(raw, Charsets.UTF_8)
            .split('\u0000')
            .dropLastWhile { it.isEmpty() }
            .takeIf { it.isNotEmpty() }
    }.getOrNull()

    /**
     * Whether the unit this app just asked for is actually up. Polled rather
     * than read once: a unit that is going to fail does so a moment after
     * `systemd-run` returns, and a single immediate read can catch it in the
     * window where it still looks alive.
     */
    private fun awaitUnitRunning(): PrivilegeOutcome {
        repeat(UNIT_START_CHECKS) {
            if (unitActive()) return PrivilegeOutcome.Ok
            Thread.sleep(UNIT_START_POLL_MS)
        }
        return PrivilegeOutcome.Failed(
            "the privileged instance started and exited at once; see `journalctl -u $UNIT_NAME`",
        )
    }

    /** Read-only, so it needs no privilege of its own. */
    private fun unitActive(): Boolean = serviceActive()

    /**
     * Why this command line cannot be a unit's `ExecStart`, or null when it can.
     *
     * The desktop app itself is an ordinary `java -cp … MainKt` line. A Gradle
     * worker — what the test task and an IDE-launched session look like — is a
     * bootstrap that waits for a handshake on stdin, so a unit built from it
     * starts, reads end-of-file and exits.
     */
    internal fun unstartableCommand(argv: List<String>): String? {
        val joined = argv.joinToString(" ")
        if (joined.contains("GradleWorkerMain") || joined.contains("worker.org.gradle")) {
            return "this window was started by Gradle, whose worker cannot start again on its own; " +
                "install the protection unit from the packaged app"
        }
        return null
    }

    /**
     * The `nft` path as the unit's `ExecStopPost` needs it: absolute.
     *
     * systemd resolves `Exec*=` verbs by their own absolute path, not through
     * the unit's `PATH`, so a bare `nft` would be a command not found — and the
     * one time the sweep matters is the time nobody is watching. A configured
     * absolute path is kept as is; a bare name is searched for on this
     * process's `PATH`.
     */
    internal fun nftForUnitCommand(): String {
        if (nftBinary.startsWith("/")) return nftBinary
        val found = System.getenv("PATH").orEmpty()
            .split(File.pathSeparator)
            .filter { it.isNotBlank() }
            .map { File(it, nftBinary) }
            .firstOrNull { it.isFile && it.canExecute() }
        return found?.absolutePath ?: nftBinary
    }

    /**
     * Puts the CA in the system trust store through a short-lived root process,
     * which is the desktop answer to Android's `su` consent dialog. `pkexec` is
     * asked rather than `systemd-run`, even though the redirect rules use the
     * latter: a transient unit is started by a D-Bus call that gives up on the
     * dialog after about twenty-five seconds, so an answer given while someone
     * is still reading the question arrives too late to be seen. `pkexec` waits
     * for the human as long as they take and hands back the helper's own exit
     * status, which is the only report that matters here.
     *
     * The helper is [CaInstallKt] — two paths in, one anchor file out. It is not
     * this app with a different uid: a root instance would open the user's
     * database and leave rows the signed-in app cannot write.
     */
    fun requestRootCaInstall(pemPath: String, coreLibPath: String): PrivilegeOutcome {
        val command = selfArgv()?.first()
            ?: return PrivilegeOutcome.Failed("cannot read this process's own command line")
        val argv = caInstallArgv(command, System.getProperty("java.class.path"), pemPath, coreLibPath)
        return run(*argv.toTypedArray(), deniedExit = PKEXEC_DENIED)
    }

    /**
     * The same `pkexec` helper, in the opposite direction.
     *
     * Removing an anchor is a write in a root-owned directory, exactly as
     * adding one is, so it asks through the same dialog instead of hoping a
     * passwordless `sudo` exists — which on a desktop session it usually does
     * not.
     */
    fun requestRootCaRemove(coreLibPath: String): PrivilegeOutcome {
        val command = selfArgv()?.first()
            ?: return PrivilegeOutcome.Failed("cannot read this process's own command line")
        val argv = caRemoveArgv(command, System.getProperty("java.class.path"), coreLibPath)
        return run(*argv.toTypedArray(), deniedExit = PKEXEC_DENIED)
    }

    /**
     * The removal `pkexec` call. The helper reads its first argument as a mode
     * rather than a path, so no certificate has to travel: `coreRemoveRootCa`
     * finds the anchor by the CA the core already holds.
     */
    internal fun caRemoveArgv(
        command: String,
        classpath: String,
        coreLibPath: String,
    ): List<String> = listOf(
        pkexec,
        command,
        "--enable-native-access=ALL-UNNAMED",
        "-cp",
        classpath,
        CA_INSTALL_MAIN,
        CA_REMOVE_MODE,
        coreLibPath,
    )

    /**
     * The `pkexec` call for that helper, as data rather than as a shell line.
     * `pkexec` hands the child a sanitized environment, so nothing the helper
     * needs travels in a variable: the certificate and the core it links
     * against are both named on its command line.
     */
    internal fun caInstallArgv(
        command: String,
        classpath: String,
        pemPath: String,
        coreLibPath: String,
    ): List<String> = listOf(
        pkexec,
        command,
        "--enable-native-access=ALL-UNNAMED",
        "-cp",
        classpath,
        CA_INSTALL_MAIN,
        pemPath,
        coreLibPath,
    )

    /**
     * `deniedExit` is the code that means "the person said no" rather than
     * "this machine cannot ask" — `pkexec` uses 126 for a dismissed dialog, and
     * only systemd-shaped helpers report a refusal in words.
     */
    private fun run(vararg argv: String, deniedExit: Int = -1): PrivilegeOutcome = runCatching {
        val process = ProcessBuilder(*argv).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().readText().trim()
        val code = process.waitFor()
        when {
            code == 0 -> PrivilegeOutcome.Ok
            // systemd gives up on its own D-Bus call after about twenty-five
            // seconds, and the dialog is still sitting unanswered on the screen
            // when it does: nothing was refused and nothing is broken, so the
            // ask reads as retriable rather than as a machine that cannot grant.
            // The phrase is systemd's own — matching "timed out" alone would
            // catch a helper that printed a network error.
            output.startsWith("Failed to start transient service unit") &&
                output.contains("Connection timed out") -> PrivilegeOutcome.Denied(
                "the authentication dialog was not answered in time; ask again while you are at the screen",
            )
            // polkit reports a cancelled dialog as an authentication failure:
            // the user said no, which is an answer, not a broken setup.
            code == deniedExit || output.contains("authorized") ||
                output.contains("Auth") || output.contains("authentication") ->
                PrivilegeOutcome.Denied(output.ifBlank { "the privilege dialog was dismissed" })
            else -> PrivilegeOutcome.Failed(output.ifBlank { "exit code $code" })
        }
    }.getOrElse { failure ->
        // No nft, no systemd-run, no pkexec, no systemd: the layout simply is not
        // available here, and explicit-proxy mode stays the honest answer.
        log("privilege helper unavailable: ${failure.message}")
        PrivilegeOutcome.Failed(failure.message ?: failure.javaClass.simpleName)
    }

    internal companion object {
        // Linux numbers, and the mark `rust/src/proxy` puts on its sockets.
        const val AF_INET = 2
        const val SOCK_DGRAM = 2
        const val SOL_SOCKET = 1
        const val SO_MARK = 36
        const val FIREWALL_MARK = 0xad45
        const val UNIT_NAME = "adfree-desktop"
        // Fixed destinations: the elevated helper takes paths as arguments only
        // because they are staged in a temp directory, never because the caller
        // chooses where root writes.
        const val SERVICE_PATH = "/etc/systemd/system/adfree-desktop.service"
        const val POLKIT_PATH = "/etc/polkit-1/rules.d/50-adfree-desktop.rules"
        const val SETUP_MAIN = "git.shin.adfree.desktop.PrivilegedSetupKt"
        /** Written into [stamp]; an older stamp means the install is redone. */
        const val SETUP_VERSION = 3
        const val PKEXEC_DENIED = 126
        // A unit that fails does it within a few hundred milliseconds; ten
        // reads at 100 ms is long enough to see it and short enough that a
        // healthy start is not held up.
        const val UNIT_START_CHECKS = 10
        const val UNIT_START_POLL_MS = 100L
        /** The port the desktop proxy listens on when the settings say nothing. */
        const val DEFAULT_PROXY_PORT = 3129
        /** How long a probe waits for the local proxy to accept a connection. */
        const val LISTENER_PROBE_MS = 400
        const val CA_INSTALL_MAIN = "git.shin.adfree.desktop.CaInstallKt"
    }
}

/**
 * True when a connection to `port` on loopback is accepted.
 *
 * A unit systemd calls active is not enough on its own: an instance that died
 * between installing the redirect and taking its ports leaves the rules
 * pointing at a closed socket, which is a machine whose traffic disappears
 * rather than a machine that is protected.
 */
private fun probeProxyListener(port: Int): Boolean = runCatching {
    java.net.Socket().use { socket ->
        socket.connect(
            java.net.InetSocketAddress(java.net.InetAddress.getByName("127.0.0.1"), port),
            DesktopPrivileges.LISTENER_PROBE_MS,
        )
    }
    true
}.getOrDefault(false)

/**
 * One argument as systemd reads it. Left bare when nothing in it is syntax — an
 * ExecStart full of quotes is unreadable in a bug report — and quoted when it
 * has a space, with the three characters systemd still reads inside quotes
 * escaped: `%` is a specifier even there, and a backslash or quote would end
 * the word early.
 */
internal fun systemdQuote(value: String): String {
    if (value.isNotEmpty() && value.none { it.isWhitespace() || it == '"' || it == '\\' || it == '%' }) {
        return value
    }
    return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"").replace("%", "%%") + "\""
}

/** The three answers a privilege request can give. */
sealed interface PrivilegeOutcome {
    data object Ok : PrivilegeOutcome
    /** Refused or cancelled — the user's call, nothing to fix. */
    data class Denied(val reason: String) : PrivilegeOutcome
    /** The mechanism itself is missing or broken on this machine. */
    data class Failed(val reason: String) : PrivilegeOutcome
}

/** The four libc calls the desktop host makes for itself; the core does the rest. */
private interface CLib : Library {
    fun socket(domain: Int, type: Int, protocol: Int): Int
    fun setsockopt(fd: Int, level: Int, optname: Int, optval: IntByReference, optlen: Int): Int
    fun close(fd: Int): Int

    companion object {
        val INSTANCE: CLib = Native.load("c", CLib::class.java)
    }
}
