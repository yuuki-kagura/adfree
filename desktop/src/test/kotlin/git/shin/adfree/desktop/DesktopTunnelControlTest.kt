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

    /**
     * Turning protection on is where the privilege is asked for. An instance
     * without the mark has to hand the window over *before* it binds the ports
     * the privileged instance is about to take, so nothing may be listening when
     * the ask goes out.
     */
    @Test
    fun `the shield is where the privilege is asked for`() {
        val asked = java.util.concurrent.CountDownLatch(1)
        val control = DesktopTunnelControl(
            coreEngine = core,
            protectionWanted = MutableStateFlow(true),
            privileges = DesktopPrivileges(nftBinary = "/nonexistent/nft"),
            localProxy = { LocalProxySettings() },
            requestPrivileges = {
                asked.countDown()
                null
            },
        )

        control.startVpnService()

        assertTrue("the system must be asked", asked.await(5, java.util.concurrent.TimeUnit.SECONDS))
        Thread.sleep(200)
        assertFalse("a handover must not leave listeners behind", core.isProxyRunning())
    }

    /**
     * A refusal is an answer, not a crash: the app keeps filtering what is
     * pointed at it and says what the system said, in the system's own words.
     */
    @Test
    fun `a refused ask leaves the local listeners and says why`() {
        val said = java.util.concurrent.CopyOnWriteArrayList<String>()
        val ports = LocalProxySettings(tcpPort = freeTcpPort(), dnsPort = freeDnsPort())
        val control = DesktopTunnelControl(
            coreEngine = core,
            protectionWanted = MutableStateFlow(true),
            privileges = DesktopPrivileges(nftBinary = "/nonexistent/nft"),
            localProxy = { ports },
            requestPrivileges = { "the privilege dialog was dismissed" },
            report = { said += it },
        )

        control.startVpnService()

        val deadline = System.currentTimeMillis() + 5_000
        while (System.currentTimeMillis() < deadline && !core.isProxyRunning()) Thread.sleep(50)
        assertEquals(listOf("the privilege dialog was dismissed"), said)
        assertTrue("a refusal still filters what is pointed here", core.isProxyRunning())
        assertEquals(ports.tcpPort, core.proxyStatus().tcpPort.toInt())
    }

    /** A port the OS just proved is free, released before it is used. */
    private fun freeTcpPort(): Int = ServerSocket(0).use { it.localPort }

    private fun freeDnsPort(): Int = DatagramSocket(0).use { it.localPort }
}
