package git.shin.adfree.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Only endpoints the UDP forwarder can use may reach `core_set_resolver`. */
class DnsAddressTest {

    @Test
    fun `a bare IPv4 uses port 53`() {
        assertEquals(DnsEndpoint("1.1.1.1", 53), parseDnsEndpoint("1.1.1.1"))
    }

    @Test
    fun `an explicit port is kept`() {
        assertEquals(DnsEndpoint("1.1.1.1", 5353), parseDnsEndpoint(" 1.1.1.1:5353 "))
    }

    @Test
    fun `bracketed and bare IPv6 are accepted`() {
        assertEquals(DnsEndpoint("::1", 53), parseDnsEndpoint("::1"))
        assertEquals(DnsEndpoint("2001:db8::1", 53), parseDnsEndpoint("2001:db8::1"))
        assertEquals(DnsEndpoint("::1", 5353), parseDnsEndpoint("[::1]:5353"))
        assertEquals(DnsEndpoint("2001:db8::1", 53), parseDnsEndpoint("[2001:db8::1]"))
    }

    @Test
    fun `hostnames and encrypted-DNS URLs are rejected`() {
        assertNull(parseDnsEndpoint("dns.google"))
        assertNull(parseDnsEndpoint("https://1.1.1.1/dns-query"))
        assertNull(parseDnsEndpoint("tls://1.1.1.1"))
    }

    @Test
    fun `malformed addresses and ports are rejected`() {
        assertNull(parseDnsEndpoint(""))
        assertNull(parseDnsEndpoint("1.1.1.999"))
        assertNull(parseDnsEndpoint("1.1.1.1:"))
        assertNull(parseDnsEndpoint("1.1.1.1:0"))
        assertNull(parseDnsEndpoint("1.1.1.1:70000"))
        assertNull(parseDnsEndpoint("[::1"))
        assertNull(parseDnsEndpoint("[::1]x"))
    }
}
