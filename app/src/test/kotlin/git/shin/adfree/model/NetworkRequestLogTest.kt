package git.shin.adfree.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import git.shin.adfree.core.LogEvent

/** Checks the mapping from a native log event into the UI model. */
class NetworkRequestLogTest {

    private fun event(
        action: Int,
        domain: String = "ads.example.com",
        ip: String = "1.2.3.4",
        rule: String = "||ads.example.com^",
        list: String = "AdGuard DNS filter",
        latencyNs: Int = 12_000,
        bytesSaved: Int = 48_000,
        id: Long = 1L,
        app: String = "",
        transport: Int = 0,
        roaming: Boolean = false,
        flowId: Long = 0L,
        url: String = "",
        dnsAnswer: String = "",
        bytesSent: Long = 0L,
        bytesRecv: Long = 0L,
    ) = LogEvent(
        id = id,
        tsMs = 1_700_000_000_000L,
        action = action,
        category = 0,
        domain = domain,
        ip = ip,
        rule = rule,
        listName = list,
        latencyNs = latencyNs,
        bytesSaved = bytesSaved,
        ipv6 = false,
        app = app,
        transport = transport,
        roaming = roaming,
        flowId = flowId,
        url = url,
        dnsAnswer = dnsAnswer,
        bytesSent = bytesSent,
        bytesRecv = bytesRecv,
    )

    @Test
    fun `blocked dns events map to the right status and protocol`() {
        val log = NetworkRequestLog.from(event(CoreActions.BLOCKED.toInt()))
        assertEquals(FilterStatus.BLOCKED, log.status)
        assertEquals(ProtocolType.DNS_UDP, log.protocol)
        assertEquals("ads.example.com", log.domain)
        assertEquals("||ads.example.com^", log.matchedRule)
        assertEquals("AdGuard DNS filter", log.filterListName)
        // 12 000 ns = 12 µs
        assertEquals(12L, log.latencyMicros)
        assertEquals(48_000L, log.dataSavedBytes)
        assertEquals(RequestCategory.AD, log.category)
    }

    @Test
    fun `tcp reset events map to tcp protocol`() {
        val log = NetworkRequestLog.from(event(CoreActions.TCP_RESET.toInt()))
        assertEquals(FilterStatus.BLOCKED, log.status)
        assertEquals(ProtocolType.TCP, log.protocol)
        assertTrue(log.dataSavedBytes > 0)
    }

    @Test
    fun `quic drops map to quic`() {
        val log = NetworkRequestLog.from(event(CoreActions.QUIC_DROP.toInt()))
        assertEquals(ProtocolType.QUIC, log.protocol)
    }

    @Test
    fun `allowed events keep no rule`() {
        val log = NetworkRequestLog.from(
            event(CoreActions.ALLOWED.toInt(), rule = "", list = "", bytesSaved = 0),
        )
        assertEquals(FilterStatus.ALLOWED, log.status)
        assertNull(log.matchedRule)
        assertNull(log.filterListName)
        assertEquals(ProtocolType.UDP, log.protocol)
        assertEquals(0L, log.dataSavedBytes)
    }

    @Test
    fun `category index maps to the ui category`() {
        val tracker = NetworkRequestLog.from(event(CoreActions.TCP_RESET.toInt()))
        assertEquals(RequestCategory.AD, tracker.category)
        assertEquals(RequestCategory.TRACKER, RequestCategory.fromIndex(1))
    }

    @Test
    fun `database row id becomes the list key`() {
        val log = NetworkRequestLog.from(event(CoreActions.BLOCKED.toInt(), id = 42L))
        assertEquals(42L, log.id)
    }

    @Test
    fun `an attributed event carries the package and a blank one is null`() {
        val owned = NetworkRequestLog.from(
            event(CoreActions.BLOCKED.toInt(), app = "com.example.browser"),
        )
        assertEquals("com.example.browser", owned.appPackage)
        assertNull(NetworkRequestLog.from(event(CoreActions.BLOCKED.toInt())).appPackage)
    }

    @Test
    fun `transport, url, dns answer and byte sizes survive the mapping`() {
        val log = NetworkRequestLog.from(
            event(
                CoreActions.ALLOWED.toInt(),
                transport = 2,
                roaming = true,
                flowId = 77L,
                url = "https://example.com/path",
                dnsAnswer = "10.0.0.2, 2001:db8::1",
                bytesSent = 120L,
                bytesRecv = 340L,
            ),
        )
        assertEquals(NetworkTransport.CELLULAR, log.transport)
        assertTrue(log.roaming)
        assertEquals(77L, log.flowId)
        assertEquals("https://example.com/path", log.url)
        assertEquals("10.0.0.2, 2001:db8::1", log.dnsAnswer)
        assertEquals(120L, log.bytesSent)
        assertEquals(340L, log.bytesReceived)
    }

    @Test
    fun `blank enrichment fields become null or unknown`() {
        val log = NetworkRequestLog.from(event(CoreActions.ALLOWED.toInt()))
        assertEquals(NetworkTransport.UNKNOWN, log.transport)
        assertNull(log.url)
        assertNull(log.dnsAnswer)
        assertEquals(0L, log.bytesSent)
        assertEquals(0L, log.bytesReceived)
    }
}
