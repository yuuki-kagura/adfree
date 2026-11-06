package git.shin.adfree.model

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The log search box accepts AdGuard's prefixes, and the whole point of a
 * prefix is that it *limits* the match: a term that would hit the rule text
 * must not answer for `url:`. These cases pin the limit, the negation, and the
 * combination of terms.
 */
class LogSearchTest {

    private val log = NetworkRequestLog(
        id = 1L,
        timestampMs = 1_730_000_000_000L,
        domain = "cdn.example.com",
        ipAddress = "10.0.0.1",
        protocol = ProtocolType.HTTPS,
        status = FilterStatus.BLOCKED,
        category = RequestCategory.AD,
        matchedRule = "||cdn.example.com^\$important,domain=shop.example",
        filterListName = "AdGuard Chinese filter",
        appPackage = "chrome",
        latencyMicros = 400,
        dataSavedBytes = 4_096,
        url = "https://cdn.example.com/banner.js",
        requestType = "script",
        source = "https://shop.example/cart",
    )

    @Test
    fun `a blank query hides nothing`() {
        assertTrue(matchesLogSearch(log, ""))
        assertTrue(matchesLogSearch(log, "   "))
    }

    @Test
    fun `a plain term looks in the address the rule the list and the app`() {
        listOf("cdn.example", "important", "Chinese", "chrome", "shop.example").forEach {
            assertTrue("$it matches", matchesLogSearch(log, it))
        }
        assertFalse(matchesLogSearch(log, "nothing.example"))
    }

    @Test
    fun `a plain term is not case sensitive`() {
        assertTrue(matchesLogSearch(log, "CDN.EXAMPLE"))
        assertTrue(matchesLogSearch(log, "adguard chinese"))
    }

    @Test
    fun `url keeps a term on the request address only`() {
        assertTrue(matchesLogSearch(log, "url:banner.js"))
        assertTrue(
            "the referrer is an address too",
            matchesLogSearch(log, "url:shop.example/cart"),
        )
        // `important` is in the rule and nowhere in the address, which is
        // exactly the row a plain search would have kept and url: must drop.
        assertTrue(matchesLogSearch(log, "important"))
        assertFalse(matchesLogSearch(log, "url:important"))
        assertFalse(matchesLogSearch(log, "url:chrome"))
    }

    @Test
    fun `minus url drops the rows that address mentions`() {
        assertFalse(matchesLogSearch(log, "-url:banner.js"))
        assertTrue(matchesLogSearch(log, "-url:doubleclick"))
        assertTrue(
            "the app is not an address",
            matchesLogSearch(log, "-url:chrome"),
        )
    }

    @Test
    fun `text keeps a term on the rule the list the app and the type`() {
        assertTrue(matchesLogSearch(log, "text:important"))
        assertTrue(matchesLogSearch(log, "text:script"))
        assertTrue(matchesLogSearch(log, "text:chrome"))
        // `banner.js` is only in the URL, so text: has nothing to find.
        assertFalse(matchesLogSearch(log, "text:banner.js"))
    }

    @Test
    fun `a negated term drops the rows that hold it`() {
        assertFalse(matchesLogSearch(log, "-text:script"))
        assertTrue(matchesLogSearch(log, "-text:stylesheet"))
        assertFalse(matchesLogSearch(log, "-text:important"))
        assertFalse(matchesLogSearch(log, "-chrome"))
    }

    @Test
    fun `several terms all have to hold`() {
        assertTrue(matchesLogSearch(log, "cdn text:script"))
        assertFalse(matchesLogSearch(log, "cdn text:stylesheet"))
        assertTrue(matchesLogSearch(log, "url:cdn -url:doubleclick text:chrome"))
    }

    @Test
    fun `a prefix with nothing after it is no constraint at all`() {
        // Typing `url:` and hunting for the rest is half a query, not a query
        // that matches nothing.
        assertTrue(matchesLogSearch(log, "url:"))
        assertTrue(matchesLogSearch(log, "text: -url:"))
        assertTrue(matchesLogSearch(log, "-"))
    }

    @Test
    fun `an unknown prefix stays the words the user typed`() {
        assertFalse(matchesLogSearch(log, "size:5000"))
        assertTrue(matchesLogSearch(log, "chrome domain=shop"))
    }

    @Test
    fun `the dns rows answer for their address`() {
        val dns = log.copy(
            url = null,
            domain = "api.adguard.org",
            requestType = "dns",
            source = null,
            matchedRule = null,
            filterListName = null,
            appPackage = null,
        )
        assertTrue("the pseudo-url the Name column shows is searchable", matchesLogSearch(dns, "api.adguard"))
        assertTrue(matchesLogSearch(dns, "text:dns"))
        assertFalse(matchesLogSearch(dns, "text:script"))
    }
}
