package git.shin.adfree.model

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The allowlist screen is a delete-first list: whatever it shows, the user is
 * one tap away from removing. So it must show only exception rules, and the row
 * label has to be the domain the rule is really about — a screen that lists
 * `||ads.example.com^` as an exception would let a tap delete the block the
 * user was trying to keep.
 */
class AllowlistRulesTest {

    @Test
    fun `a search box only lists exception rules`() {
        val rules = listOf(
            "||ads.example.com^",
            "@@||example.com^",
            "##.banner",
            "/ads/",
        )

        assertEquals(listOf("@@||example.com^"), allowlistRules(rules, ""))
        assertEquals(listOf("@@||example.com^"), allowlistRules(rules, "example"))
    }

    @Test
    fun `a query matches the host whatever its case`() {
        val rules = listOf("@@||News.Example.COM^", "@@||other.org^")

        assertEquals(listOf("@@||News.Example.COM^"), allowlistRules(rules, "EXAMPLE.com"))
        assertEquals(listOf("@@||other.org^"), allowlistRules(rules, "other"))
        assertEquals(rules, allowlistRules(rules, "  "))
    }

    @Test
    fun `a host is stripped of its rule decoration`() {
        assertEquals("example.com", allowlistHost("@@||example.com^"))
        assertEquals("example.com", allowlistHost("@@||example.com^\$important"))
        assertEquals("example.com", allowlistHost("@@example.com##.banner"))
        assertEquals("example.com", allowlistHost("@@||example.com"))
    }

    /**
     * Switching a row off rewrites it the way AdGuard parks a rule, `!` in
     * front. The screen still has to list it — the user switched it off from
     * here, so this is where it gets switched back on — and a parked block rule
     * stays out of this screen like any other block rule.
     */
    @Test
    fun `a parked exception is listed and reads as switched off`() {
        val rules = listOf("@@||a.test^", "!@@||b.test^", "||c.test^", "!||d.test^")

        assertEquals(listOf("@@||a.test^", "!@@||b.test^"), allowlistRules(rules, ""))
        assertEquals(listOf("!@@||b.test^"), allowlistRules(rules, "b.t"))
        assertEquals("b.test", allowlistHost("!@@||b.test^"))
        assertEquals(true, isAllowlistRule("@@||a.test^"))
        assertEquals(false, isAllowlistRule("!||d.test^"))
        assertEquals(true, allowlistRuleEnabled("@@||a.test^"))
        assertEquals(false, allowlistRuleEnabled("!@@||b.test^"))
    }

    @Test
    fun `switching a rule adds or removes the leading mark only`() {
        assertEquals("!@@||b.test^", withAllowlistRuleEnabled("@@||b.test^", false))
        assertEquals("@@||b.test^", withAllowlistRuleEnabled("!@@||b.test^", true))
        assertEquals("@@||b.test^", withAllowlistRuleEnabled("@@||b.test^", true))
        assertEquals("!@@||b.test^", withAllowlistRuleEnabled("!@@||b.test^", false))
    }
}
