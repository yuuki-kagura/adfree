package git.shin.adfree.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The log sheet builds an AdGuard rule from one request row. */
class RuleFromLogTest {

    @Test
    fun `the exact host is offered before the shorter parent domain`() {
        assertEquals(
            listOf("||api.onesignal.com^", "||onesignal.com^"),
            ruleCandidates(RuleDraftKind.BLOCK, "api.onesignal.com"),
        )
    }

    @Test
    fun `a two label host has no parent candidate`() {
        assertEquals(
            listOf("||onesignal.com^"),
            ruleCandidates(RuleDraftKind.BLOCK, "onesignal.com"),
        )
    }

    @Test
    fun `allow candidates are exception rules`() {
        assertEquals(
            listOf("@@||config.ads.vungle.com^", "@@||ads.vungle.com^"),
            ruleCandidates(RuleDraftKind.ALLOW, "config.ads.vungle.com"),
        )
    }

    @Test
    fun `candidate input is normalised before it becomes a rule`() {
        assertEquals(
            listOf("||ads.example.com^", "||example.com^"),
            ruleCandidates(RuleDraftKind.BLOCK, "  ADS.Example.COM. "),
        )
    }

    @Test
    fun `app scope and priority keep the order the core asserts`() {
        assertEquals(
            "||api.onesignal.com^\$app=com.eup.heyjapan,important",
            composeRuleText(
                kind = RuleDraftKind.BLOCK,
                base = "||api.onesignal.com^",
                appPackage = "com.eup.heyjapan",
                appScoped = true,
                important = true,
            ),
        )
    }

    @Test
    fun `an allow rule never carries priority but can still be app scoped`() {
        assertEquals(
            "@@||ads.example.com^\$app=com.example.app",
            composeRuleText(
                kind = RuleDraftKind.ALLOW,
                base = "@@||ads.example.com^",
                appPackage = "com.example.app",
                appScoped = true,
                important = true,
            ),
        )
    }

    @Test
    fun `toggling both options off returns the plain candidate`() {
        assertEquals(
            "||ads.example.com^",
            composeRuleText(
                kind = RuleDraftKind.BLOCK,
                base = "||ads.example.com^",
                appPackage = "com.example.app",
                appScoped = false,
                important = false,
            ),
        )
    }

    @Test
    fun `options the user typed survive the toggles`() {
        assertEquals(
            "||ads.example.com^\$domain=shop.example,important",
            composeRuleText(
                kind = RuleDraftKind.BLOCK,
                base = "||ads.example.com^\$domain=shop.example",
                appPackage = "com.example.app",
                appScoped = false,
                important = true,
            ),
        )
    }

    @Test
    fun `a rewritten toggle replaces its own token instead of duplicating it`() {
        assertEquals(
            "||ads.example.com^\$app=com.other.app",
            composeRuleText(
                kind = RuleDraftKind.BLOCK,
                base = "||ads.example.com^\$app=com.example.app",
                appPackage = "com.other.app",
                appScoped = true,
                important = false,
            ),
        )
    }

    @Test
    fun `a package that cannot be an option value is refused`() {
        assertEquals(
            "||ads.example.com^",
            composeRuleText(
                kind = RuleDraftKind.BLOCK,
                base = "||ads.example.com^",
                appPackage = "com.example app,other",
                appScoped = true,
                important = false,
            ),
        )
    }

    @Test
    fun `cosmetic rules are left exactly as typed`() {
        val cosmetic = "ads.example.com##.banner"
        assertEquals(
            cosmetic,
            composeRuleText(
                kind = RuleDraftKind.BLOCK,
                base = cosmetic,
                appPackage = "com.example.app",
                appScoped = true,
                important = true,
            ),
        )
    }

    @Test
    fun `dns rows cannot be scoped to an app`() {
        assertFalse(appScopeSupported(ProtocolType.DNS_UDP, "com.example.app"))
        assertFalse(appScopeSupported(ProtocolType.DNS_DOH, "com.example.app"))
        assertTrue(appScopeSupported(ProtocolType.HTTPS, "com.example.app"))
        assertFalse(appScopeSupported(ProtocolType.HTTPS, null))
    }
}
