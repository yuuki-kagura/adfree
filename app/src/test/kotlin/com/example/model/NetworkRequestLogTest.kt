package com.example.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import com.example.core.LogEvent

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
    ) = LogEvent(
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
    )

    @Test
    fun `blocked dns events map to the right status and protocol`() {
        val log = NetworkRequestLog.from(event(CoreActions.BLOCKED.toInt()), 1L)
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
        val log = NetworkRequestLog.from(event(CoreActions.TCP_RESET.toInt()), 2L)
        assertEquals(FilterStatus.BLOCKED, log.status)
        assertEquals(ProtocolType.TCP, log.protocol)
        assertTrue(log.dataSavedBytes > 0)
    }

    @Test
    fun `quic drops map to quic`() {
        val log = NetworkRequestLog.from(event(CoreActions.QUIC_DROP.toInt()), 3L)
        assertEquals(ProtocolType.QUIC, log.protocol)
    }

    @Test
    fun `allowed events keep no rule`() {
        val log = NetworkRequestLog.from(
            event(CoreActions.ALLOWED.toInt(), rule = "", list = "", bytesSaved = 0),
            4L,
        )
        assertEquals(FilterStatus.ALLOWED, log.status)
        assertNull(log.matchedRule)
        assertNull(log.filterListName)
        assertEquals(ProtocolType.UDP, log.protocol)
        assertEquals(0L, log.dataSavedBytes)
    }

    @Test
    fun `category index maps to the ui label`() {
        val tracker = NetworkRequestLog.from(event(CoreActions.TCP_RESET.toInt()), 5L)
        assertEquals(RequestCategory.AD, tracker.category)
        assertEquals("Tracker & Telemetry", RequestCategory.TRACKER.label)
    }
}
