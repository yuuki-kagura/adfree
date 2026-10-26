package git.shin.adfree.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Only an IP literal can be dialed from the packet loop without a resolver. */
class ProxySettingsTest {

    @Test
    fun `IPv4 and IPv6 literals are accepted`() {
        assertEquals("192.168.1.10", normalizeProxyHost(" 192.168.1.10 "))
        assertEquals("::1", normalizeProxyHost("[::1]"))
        assertEquals("2001:db8::10", normalizeProxyHost("2001:db8::10"))
    }

    @Test
    fun `hostnames and URLs are rejected`() {
        assertNull(normalizeProxyHost("proxy.lan"))
        assertNull(normalizeProxyHost("socks5://192.168.1.10"))
        assertNull(normalizeProxyHost(""))
        assertNull(normalizeProxyHost("1.2.3.999"))
    }

    @Test
    fun `an endpoint is usable only with a literal address and a real port`() {
        assertTrue(ProxySettings(host = "192.168.1.10", port = 1080).isUsable)
        assertTrue(ProxySettings(host = "[::1]", port = 1080).isUsable)
        assertFalse(ProxySettings(host = "proxy.lan", port = 1080).isUsable)
        assertFalse(ProxySettings(host = "192.168.1.10", port = 0).isUsable)
        assertFalse(ProxySettings(host = "192.168.1.10", port = 70000).isUsable)
    }
}
