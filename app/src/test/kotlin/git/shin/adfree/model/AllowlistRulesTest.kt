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
}
