package git.shin.adfree.desktop

import git.shin.adfree.core.CoreEngine
import git.shin.adfree.model.LocalProxySettings
import java.net.DatagramSocket
import java.net.ServerSocket
import kotlinx.coroutines.flow.MutableStateFlow
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The ports in Settings are the ports the listeners take.
 *
 * The redirect rules are written from what the core actually bound, so the
 * pair the user applied has to reach both halves of the desktop start path —
 * and a port somebody else holds has to come back as a refusal with its
 * reason, not as a protection switch that reads "on" over a filter that is a
 * plain relay.
 */
class DesktopTunnelControlTest {

    init {
        // The bindings load the core by name; point them at this repo's build
        // the same way [DesktopContainer] does, or whatever `adfree_core` sits
        // on the library path answers instead — an older core that has no
        // status record at all, which reads as "never started".
        findCoreLibrary()?.let {
            System.setProperty("uniffi.component.adfree.libraryOverride", it.absolutePath)
        }
    }

    private val core = CoreEngine()

    @After
    fun listenersGoDown() {
        core.stopProxy()
    }

    @Test
    fun `the listeners come up on the ports the settings name`() {
        val tcp = freeTcpPort()
        val dns = freeDnsPort()
        val control = controlOn(LocalProxySettings(tcpPort = tcp, dnsPort = dns))

        control.startVpnService()

        val status = core.proxyStatus()
        assertTrue("listeners must come up on free ports: $status", status.running)
        assertEquals(tcp, status.tcpPort.toInt())
        assertEquals(dns, status.dnsPort.toInt())
    }

    @Test
    fun `a port somebody else holds is refused and keeps the reason`() {
        val squatter = ServerSocket(0)
        try {
            val control = controlOn(
                LocalProxySettings(tcpPort = squatter.localPort, dnsPort = freeDnsPort()),
            )

            control.startVpnService()

            val status = core.proxyStatus()
            assertFalse("a taken port must not claim to run: $status", status.running)
            assertTrue("the refusal owes a reason: $status", status.tcpError.isNotBlank())
            assertFalse(core.isProxyRunning())
        } finally {
            squatter.close()
        }
    }

    private fun controlOn(ports: LocalProxySettings) = DesktopTunnelControl(
        coreEngine = core,
        protectionWanted = MutableStateFlow(true),
        // No privilege to ask for in a test: the listeners are the half under
        // test, and the rules can only be written by a process holding the mark.
        privileges = null,
        localProxy = { ports },
    )

    /** A port the OS just proved is free, released before it is used. */
    private fun freeTcpPort(): Int = ServerSocket(0).use { it.localPort }

    private fun freeDnsPort(): Int = DatagramSocket(0).use { it.localPort }
}
