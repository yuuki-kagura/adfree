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
 * user to open a terminal.
 */
class DesktopPrivileges(
    private val nftBinary: String = "nft",
    private val systemdRun: String = "systemd-run",
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
        val args = self.arguments().orElse(emptyArray()).toList()
        val argv = mutableListOf(
            systemdRun,
            "--system",
            "--unit=$UNIT_NAME",
            "--service-type=simple",
            "--collect",
            "--uid=${System.getProperty("user.name")}",
            "-p=AmbientCapabilities=CAP_NET_ADMIN",
            "-p=CapabilityBoundingSet=CAP_NET_ADMIN",
        )
        environment.forEach { (key, value) -> argv += "-p=Environment=$key=$value" }
        argv += command
        argv += args
        return run(*argv.toTypedArray())
    }

    private fun run(vararg argv: String): PrivilegeOutcome = runCatching {
        val process = ProcessBuilder(*argv).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().readText().trim()
        val code = process.waitFor()
        when {
            code == 0 -> PrivilegeOutcome.Ok
            // polkit reports a cancelled dialog as an authentication failure:
            // the user said no, which is an answer, not a broken setup.
            output.contains("Auth") || output.contains("authentication") ->
                PrivilegeOutcome.Denied(output.ifBlank { "the privilege dialog was dismissed" })
            else -> PrivilegeOutcome.Failed(output.ifBlank { "exit code $code" })
        }
    }.getOrElse { failure ->
        // No nft, no systemd-run, no systemd: the layout simply is not available
        // here, and explicit-proxy mode stays the honest answer.
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
