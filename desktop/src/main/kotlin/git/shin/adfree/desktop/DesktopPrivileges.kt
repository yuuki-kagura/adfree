package git.shin.adfree.desktop

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.ptr.IntByReference
import java.io.File

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
 * desktop has no `su` and no OS screen that could import a PEM. A long-lived
 * privileged process needs systemd to hand out `CAP_NET_ADMIN`; a one-shot
 * helper only needs root for as long as it writes, so it asks through `pkexec`,
 * which waits for the answer rather than for twenty-five seconds.
 */
class DesktopPrivileges(
    private val nftBinary: String = "nft",
    private val systemdRun: String = "systemd-run",
    private val pkexec: String = "pkexec",
    private val log: (String) -> Unit = { System.err.println("[desktop] $it") },
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
     * The redirect ruleset for these ports. The mark is what keeps the proxy's
     * own traffic out of the loop, so the rules only make sense alongside it —
     * [installRules] refuses without it rather than taking the machine's DNS
     * and web traffic into a loop.
     */
    fun ruleset(tcpPort: Int, dnsPort: Int): String {
        val mark = FIREWALL_MARK.toString(16)
        return """
            table inet adfree {
                chain http {
                    type nat hook output priority -100; policy accept;
                    meta mark 0x$mark accept
                    meta l4proto tcp tcp dport { 80, 443 } redirect to :$tcpPort
                }
                chain dns {
                    type nat hook output priority -100; policy accept;
                    meta mark 0x$mark accept
                    meta l4proto udp udp dport 53 redirect to :$dnsPort
                    meta l4proto tcp tcp dport 53 redirect to :$dnsPort
                }
                chain quic {
                    type filter hook output priority 0; policy accept;
                    meta mark 0x$mark accept
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
    fun installRules(tcpPort: Int, dnsPort: Int): PrivilegeOutcome {
        if (!canSetFirewallMark()) {
            return PrivilegeOutcome.Denied(
                "this process cannot mark its own sockets, so the redirect would loop its traffic",
            )
        }
        removeRules()
        val file = File.createTempFile("adfree-", ".nft")
        return try {
            file.writeText(ruleset(tcpPort, dnsPort))
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
     * Starts the same app as a transient systemd unit that keeps the user's uid
     * — so the data files stay theirs — and holds `CAP_NET_ADMIN`, which is what
     * makes the mark and the rules possible. `systemd-run` asks polkit, so the
     * user sees the desktop's own authentication dialog instead of a terminal.
     *
     * The caller must have released the listeners first: the unit it starts
     * binds the same ports.
     */
    fun requestPrivilegedEngine(environment: Map<String, String>): PrivilegeOutcome {
        val self = ProcessHandle.current().info()
        val command = self.command().orElse(null)
            ?: return PrivilegeOutcome.Failed("cannot read this process's own command line")
        val argv = engineUnitArgv(command, self.arguments().orElse(emptyArray()).toList(), environment)
        return run(*argv.toTypedArray())
    }

    /**
     * The `systemd-run` call that starts this same command as a transient unit.
     * Split out because a mistyped property flag fails before polkit is ever
     * asked, which looks exactly like a machine that has no privilege to give.
     */
    internal fun engineUnitArgv(
        command: String,
        arguments: List<String>,
        environment: Map<String, String>,
    ): List<String> {
        val argv = mutableListOf(
            systemdRun,
            "--system",
            "--unit=$UNIT_NAME",
            "--service-type=simple",
            "--collect",
            "--uid=${System.getProperty("user.name")}",
            // `-p=Key=Value` is read as an assignment with an empty key and
            // fails outright, so each property is its own long option.
            "--property=AmbientCapabilities=CAP_NET_ADMIN",
            "--property=CapabilityBoundingSet=CAP_NET_ADMIN",
        )
        environment.forEach { (key, value) -> argv += "--property=Environment=$key=$value" }
        argv += command
        argv += arguments
        return argv
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
        val command = ProcessHandle.current().info().command().orElse(null)
            ?: return PrivilegeOutcome.Failed("cannot read this process's own command line")
        val argv = caInstallArgv(command, System.getProperty("java.class.path"), pemPath, coreLibPath)
        return run(*argv.toTypedArray(), deniedExit = PKEXEC_DENIED)
    }

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

    private companion object {
        // Linux numbers, and the mark `rust/src/proxy` puts on its sockets.
        const val AF_INET = 2
        const val SOCK_DGRAM = 2
        const val SOL_SOCKET = 1
        const val SO_MARK = 36
        const val FIREWALL_MARK = 0xad45
        const val UNIT_NAME = "adfree-desktop"
        const val PKEXEC_DENIED = 126
        const val CA_INSTALL_MAIN = "git.shin.adfree.desktop.CaInstallKt"
    }
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
