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
        requestType: String = "",
        source: String = "",
        proto: Int = 0,
        tls: String = "",
        cipher: String = "",
        status: Int = 0,
        contentType: String = "",
        certSubject: String = "",
        certIssuer: String = "",
        certFrom: Long = 0L,
        certTo: Long = 0L,
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
        requestType = requestType,
        source = source,
        proto = proto,
        tls = tls,
        cipher = cipher,
        status = status,
        contentType = contentType,
        certSubject = certSubject,
        certIssuer = certIssuer,
        certFrom = certFrom,
        certTo = certTo,
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
        // The malicious-domain notice only fires on rows the core tagged with
        // CAT_MALWARE (rust/src/filter.rs: 5). If the two ever drift apart the
        // notice silently stops appearing, so the number is pinned here.
        assertEquals(RequestCategory.MALWARE, RequestCategory.fromIndex(5))
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

    @Test
    fun `the request type and the page that asked for it are carried over`() {
        val log = NetworkRequestLog.from(
            event(
                CoreActions.BLOCKED.toInt(),
                url = "https://cdn.example.com/app.css",
                requestType = "stylesheet",
                source = "https://shop.example/cart",
            ),
        )
        assertEquals("stylesheet", log.requestType)
        assertEquals("https://shop.example/cart", log.source)
        assertNull(
            "a row the core never classified has no type rather than a guessed one",
            NetworkRequestLog.from(event(CoreActions.BLOCKED.toInt())).requestType,
        )
        assertNull(NetworkRequestLog.from(event(CoreActions.BLOCKED.toInt())).source)
    }

    @Test
    fun `the name column is the url when there is one and a dns pseudo-url otherwise`() {
        val http = NetworkRequestLog.from(
            event(CoreActions.BLOCKED.toInt(), url = "https://cdn.example.com/app.css"),
        )
        assertEquals("https://cdn.example.com/app.css", http.displayName)
        val dns = NetworkRequestLog.from(
            event(CoreActions.BLOCKED.toInt(), requestType = "dns"),
        )
        assertEquals("dns://ads.example.com", dns.displayName)
        val plain = NetworkRequestLog.from(event(CoreActions.BLOCKED.toInt()))
        assertEquals("ads.example.com", plain.displayName)
    }

    @Test
    fun `the protocol the core recorded wins over the one the action implies`() {
        // An allowed HTTPS request used to read as plain UDP, because the only
        // thing the row said was "nothing was blocked".
        val https = NetworkRequestLog.from(
            event(CoreActions.ALLOWED.toInt(), proto = ProtocolType.HTTPS.code),
        )
        assertEquals(ProtocolType.HTTPS, https.protocol)
        val quic = NetworkRequestLog.from(
            event(CoreActions.ALLOWED.toInt(), proto = ProtocolType.QUIC.code),
        )
        assertEquals(ProtocolType.QUIC, quic.protocol)
        // A row from before the core said anything still falls back on the action.
        assertEquals(
            ProtocolType.DNS_UDP,
            NetworkRequestLog.from(event(CoreActions.BLOCKED.toInt(), proto = 0)).protocol,
        )
    }

    @Test
    fun `the tls and response facts ride on the row`() {
        val log = NetworkRequestLog.from(
            event(
                CoreActions.ALLOWED.toInt(),
                proto = ProtocolType.HTTPS.code,
                tls = "TLS 1.3",
                cipher = "TLS_AES_256_GCM_SHA384",
                status = 404,
                contentType = "text/html",
            ),
        )
        assertEquals("TLS 1.3", log.tlsVersion)
        assertEquals("TLS_AES_256_GCM_SHA384", log.cipher)
        assertEquals(404, log.httpResponseStatus)
        assertEquals("text/html", log.contentType)
    }

    @Test
    fun `a row with no encrypted session and no response names neither`() {
        val log = NetworkRequestLog.from(event(CoreActions.BLOCKED.toInt()))
        assertNull(log.tlsVersion)
        assertNull(log.cipher)
        assertNull(log.contentType)
        // Zero is the core's "never parsed an HTTP response", not status 0.
        assertNull(log.httpResponseStatus)
    }

    @Test
    fun `the certificate the session accepted says who signed it and for how long`() {
        val log = NetworkRequestLog.from(
            event(
                CoreActions.ALLOWED.toInt(),
                proto = ProtocolType.HTTPS.code,
                tls = "TLS 1.3",
                certSubject = "cdn.example.com",
                certIssuer = "DigiCert TLS RSA SHA256 2020 CA1",
                certFrom = 1_700_000_000_000L,
                certTo = 1_800_000_000_000L,
            ),
        )
        assertEquals("cdn.example.com", log.certSubject)
        assertEquals("DigiCert TLS RSA SHA256 2020 CA1", log.certIssuer)
        assertEquals(1_700_000_000_000L, log.certValidFrom)
        assertEquals(1_800_000_000_000L, log.certValidTo)
    }

    @Test
    fun `a row that never saw a certificate carries no certificate facts`() {
        // A refused host or a DNS answer has no leaf at all, and the core says
        // so with empty names and a window at zero. Reading that as "valid from
        // the epoch" would put a fact on the row the session never produced.
        val log = NetworkRequestLog.from(event(CoreActions.BLOCKED.toInt()))
        assertNull(log.certSubject)
        assertNull(log.certIssuer)
        assertNull(log.certValidFrom)
        assertNull(log.certValidTo)
    }
}
