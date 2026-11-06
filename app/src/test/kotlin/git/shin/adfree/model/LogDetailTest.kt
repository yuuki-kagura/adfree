package git.shin.adfree.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The switches AdGuard's detail panel offers are only worth offering where this
 * app can actually change something: a rule the user wrote parks behind a `!`,
 * a downloaded list turns off whole. A switch that changes nothing teaches the
 * user that switches do not work, so what the panel does *not* offer is pinned
 * here as carefully as what it does.
 */
class LogDetailTest {

    private fun list(
        id: String,
        name: String,
        enabled: Boolean = true,
        customRules: List<String> = emptyList(),
    ) = FilterList(
        id = id,
        name = name,
        description = "",
        ruleCount = customRules.size,
        isEnabled = enabled,
        category = "ads",
        version = "",
        isCustom = customRules.isNotEmpty() || id == USER_LIST_ID,
        customRules = customRules,
    )

    private fun log(
        host: String,
        rule: String? = null,
        listName: String? = null,
    ) = NetworkRequestLog(
        id = 1L,
        timestampMs = 1_730_000_000_000L,
        domain = host,
        ipAddress = "93.184.216.34",
        protocol = ProtocolType.DNS_UDP,
        status = FilterStatus.BLOCKED,
        category = RequestCategory.AD,
        matchedRule = rule,
        filterListName = listName,
        appPackage = null,
        latencyMicros = 0L,
        dataSavedBytes = 0L,
    )

    @Test
    fun `a rule from an installed list turns that whole list off`() {
        val lists = listOf(list("easylist", "EasyList", enabled = true), list(USER_LIST_ID, "User", customRules = emptyList()))
        val switches = logRuleSwitches(
            log("ads.example.com", "||example.com^", "EasyList"),
            lists,
        )

        assertEquals(1, switches.size)
        val fired = switches.single()
        assertEquals(LogRuleSwitchKind.FILTER_LIST, fired.kind)
        assertEquals("easylist", fired.target)
        assertEquals("EasyList", fired.label)
        assertTrue(fired.enabled)
        // The rule itself stays visible under the list's name, which is where
        // the user reads what actually matched.
        assertEquals("||example.com^", fired.rule)
    }

    @Test
    fun `a list that is no longer installed gets no switch`() {
        val switches = logRuleSwitches(
            log("ads.example.com", "||example.com^", "A list since removed"),
            listOf(list("easylist", "EasyList")),
        )

        assertTrue("nothing here can be changed", switches.isEmpty())
    }

    @Test
    fun `the user's own rule is switched by itself`() {
        val lists = listOf(list(USER_LIST_ID, "User", customRules = listOf("||example.com^")))
        val switches = logRuleSwitches(log("example.com", "||example.com^"), lists)

        assertEquals(1, switches.size)
        assertEquals(LogRuleSwitchKind.USER_RULE, switches.single().kind)
        assertEquals("||example.com^", switches.single().target)
        assertTrue(switches.single().enabled)
    }

    @Test
    fun `an exception the user parked beside the host is offered switched off`() {
        // The rule was switched off earlier, so it speaks for nothing; the panel
        // says so instead of showing it as if it were still filtering.
        val lists = listOf(
            list(
                USER_LIST_ID,
                "User",
                customRules = listOf("!@@||cdn.example.com^"),
            ),
        )
        val switches = logRuleSwitches(log("cdn.example.com"), lists)

        assertEquals(1, switches.size)
        assertEquals("!@@||cdn.example.com^", switches.single().label)
        assertFalse(switches.single().enabled)
    }

    @Test
    fun `a rule about some other host is not offered`() {
        val lists = listOf(
            list(USER_LIST_ID, "User", customRules = listOf("||unrelated.net^", "@@||example.com^")),
        )
        val switches = logRuleSwitches(log("ads.example.com"), lists)

        assertEquals(listOf("@@||example.com^"), switches.map { it.target })
    }

    @Test
    fun `a parent domain rule speaks for its child`() {
        val lists = listOf(list(USER_LIST_ID, "User", customRules = listOf("||example.com^")))

        assertTrue(logRuleSwitches(log("deep.ads.example.com"), lists).isNotEmpty())
        assertTrue(logRuleSwitches(log("notexample.com"), lists).isEmpty())
    }

    @Test
    fun `a rule that is not anchored on a host gets no switch`() {
        // Path, cosmetic and wildcard rules need the URL to judge, which the
        // panel does not have for a row that never reached HTTP.
        val lists = listOf(
            list(
                USER_LIST_ID,
                "User",
                customRules = listOf("/banner/*", "##.ad-box", "||*.example.com^"),
            ),
        )

        assertTrue(logRuleSwitches(log("ads.example.com"), lists).isEmpty())
    }

    @Test
    fun `the rule that fired is listed once however it is written`() {
        val lists = listOf(list(USER_LIST_ID, "User", customRules = listOf("!||example.com^")))
        val switches = logRuleSwitches(log("example.com", "!||example.com^"), lists)

        assertEquals(1, switches.size)
    }

    @Test
    fun `only a real web address can be opened in a browser`() {
        assertTrue(logUrlOpenable("https://example.com/page"))
        assertTrue(logUrlOpenable("http://example.com"))
        assertFalse("a pseudo-url names nothing a browser can load", logUrlOpenable("dns://example.com"))
        assertFalse(logUrlOpenable("example.com/page"))
        assertFalse(logUrlOpenable(null))
        assertFalse(logUrlOpenable("ftp://example.com"))
    }

    @Test
    fun `a request that was never timed says nothing`() {
        // TLS-terminated connections are logged without a duration; a 0 there
        // would read as the fastest request the machine ever made.
        assertNull(logDurationLabel(0L))
        assertNull(logDurationLabel(-1L))
        assertEquals("900 µs", logDurationLabel(900L))
        val seconds = logDurationLabel(1_500L).orEmpty()
        assertTrue("expected a millisecond reading, got $seconds", seconds.endsWith(" ms"))
        assertFalse(seconds.startsWith("1500"))
    }

    private companion object {
        /** The id the repository gives the user-rules row. */
        const val USER_LIST_ID = "builtin_custom"
    }
}
