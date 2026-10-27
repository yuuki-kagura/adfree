package git.shin.adfree.model

import org.junit.Assert.assertEquals
import org.junit.Test

/** The probe takes the same address form the resolver validator accepts. */
class DnsProviderProbeAddressTest {

    private fun provider(
        type: ProtocolType,
        address: String,
        port: Int,
    ) = DnsProvider(
        id = "test",
        name = "Test",
        address = address,
        type = type,
        description = "",
        isCustom = true,
        port = port,
    )

    @Test
    fun `plain transports append the stored port`() {
        assertEquals(
            "1.1.1.1:53",
            provider(ProtocolType.DNS_UDP, "1.1.1.1", 53).probeAddress(),
        )
        assertEquals(
            "dns.example:8853",
            provider(ProtocolType.DNS_DOT, "dns.example", 8853).probeAddress(),
        )
    }

    @Test
    fun `an IPv6 host is bracketed before the port`() {
        assertEquals(
            "[2606:4700::1111]:853",
            provider(ProtocolType.DNS_DOT, "2606:4700::1111", 853).probeAddress(),
        )
    }

    @Test
    fun `DoH keeps the complete URL`() {
        assertEquals(
            "https://dns.example:8443/dns-query",
            provider(
                ProtocolType.DNS_DOH,
                "https://dns.example:8443/dns-query",
                8443,
            ).probeAddress(),
        )
    }
}
