package git.shin.adfree.model

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The desktop's own listener ports: both numbers are the user's to move, but
 * only a pair a listener can actually bind counts — below the privileged range
 * a bind needs root, and two listeners cannot share one port.
 */
class LocalProxySettingsTest {

    @Test
    fun `the shipped pair is usable`() {
        assertTrue(LocalProxySettings().isUsable)
        assertTrue(LocalProxySettings(tcpPort = 3129, dnsPort = 5300).isUsable)
    }

    @Test
    fun `a port below the privileged range is refused`() {
        assertFalse(LocalProxySettings(tcpPort = 1023, dnsPort = 5300).isUsable)
        assertFalse(LocalProxySettings(tcpPort = 3129, dnsPort = 80).isUsable)
        assertFalse(LocalProxySettings(tcpPort = 0, dnsPort = 0).isUsable)
    }

    @Test
    fun `one port cannot carry both listeners`() {
        assertFalse(LocalProxySettings(tcpPort = 5300, dnsPort = 5300).isUsable)
    }

    @Test
    fun `the edges of the range are the last usable numbers`() {
        assertTrue(LocalProxySettings(tcpPort = 1024, dnsPort = 65535).isUsable)
        assertFalse(LocalProxySettings(tcpPort = 65536, dnsPort = 5300).isUsable)
        assertFalse(LocalProxySettings(tcpPort = 3129, dnsPort = -1).isUsable)
    }

    @Test
    fun `localhost is filtered until the user says otherwise`() {
        // The shipped default is AdGuard's own: local traffic filtered, so a
        // pre-switch install and a fresh one behave the same.
        assertTrue(LocalProxySettings().filterLocalhost)
        assertFalse(LocalProxySettings(filterLocalhost = false).filterLocalhost)
        // The switch is not a port: an unusable pair does not become usable
        // because the loopback choice was made, nor the other way round.
        assertFalse(LocalProxySettings(tcpPort = 80, filterLocalhost = false).isUsable)
    }
}
