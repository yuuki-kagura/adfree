package git.shin.adfree.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The rule builder writes what the core reads, so the two things that can go
 * wrong are worth pinning: a line it assembles must parse, and a line a user
 * types must be refused with a reason rather than saved to match nothing.
 */
class RuleSyntaxTest {

    @Test
    fun aBuiltRuleIsOneTheParserAccepts() {
        val rule = buildRule(
            decision = RuleDecision.BLOCK,
            pattern = "example.com",
            flags = setOf("third-party", "important"),
            types = setOf("image", "script"),
            app = "chrome",
            domainScope = "news.example",
        )
        assertEquals(
            "||example.com^\$third-party,important,script,image,app=chrome,domain=news.example",
            rule,
        )
        val parsed = parseRule(rule)
        assertTrue("built rules must parse: ${parsed.error}", parsed.valid)
        assertEquals(RuleDecision.BLOCK, parsed.decision)
        assertEquals("||example.com^", parsed.pattern)
        assertEquals("chrome", parsed.appScope)
        assertEquals("news.example", parsed.domainScope)
        assertTrue(parsed.has("image"))
    }

    @Test
    fun anExceptionKeepsItsAtAtAndThePattern() {
        val rule = buildRule(RuleDecision.ALLOW, "safe.example")
        assertEquals("@@||safe.example^", rule)
        assertEquals(RuleDecision.ALLOW, parseRule(rule).decision)
    }

    @Test
    fun aFullPatternTheUserTypedIsNotRewritten() {
        // A path pattern already says where it anchors; wrapping it in ||…^
        // would change what it matches.
        assertEquals("||example.com/ads/*", buildRule(RuleDecision.BLOCK, "||example.com/ads/*"))
        assertEquals("/ads\\d+\\//", buildRule(RuleDecision.BLOCK, "/ads\\d+\\//"))
    }

    @Test
    fun aModifierTheCoreDoesNotKnowIsNamed() {
        val parsed = parseRule("||example.com^\$bogus")
        assertFalse(parsed.valid)
        assertEquals(RuleError.UnknownModifier("bogus"), parsed.error)
    }

    @Test
    fun aModifierThatNeedsAValueIsNotAcceptedWithoutOne() {
        assertEquals(RuleError.MissingValue("app"), parseRule("||example.com^\$app").error)
        assertEquals(RuleError.MissingValue("domain"), parseRule("||example.com^\$domain=").error)
        assertNull(parseRule("||example.com^\$app=chrome").error)
    }

    @Test
    fun proseIsNotARule() {
        assertEquals(RuleError.Empty, parseRule("   ").error)
        assertEquals(RuleError.Empty, parseRule("! parked comment").error)
        assertEquals(RuleError.Pattern, parseRule("this is not a rule").error)
        assertEquals(RuleError.Regex, parseRule("/unterminated").error)
    }

    @Test
    fun aRuleMatchesTheRequestItWasWrittenFor() {
        assertTrue(ruleMatchesRequest("||example.com^", "example.com"))
        assertTrue("a subdomain is covered", ruleMatchesRequest("||example.com^", "cdn.example.com"))
        assertFalse(ruleMatchesRequest("||example.com^", "example.org"))
        assertTrue(
            "an exception still sees the request it excepts",
            ruleMatchesRequest("@@||example.com^", "example.com"),
        )
        assertTrue(ruleMatchesRequest("||example.com/ads/*", "example.com", "https://example.com/ads/banner.png"))
        assertFalse(ruleMatchesRequest("||example.com/ads/*", "example.com", "https://example.com/style.css"))
    }

    @Test
    fun aTypeModifierOnlyMatchesItsOwnType() {
        val rule = "||example.com^\$image"
        assertTrue(ruleMatchesRequest(rule, "example.com", requestType = "image"))
        assertFalse(ruleMatchesRequest(rule, "example.com", requestType = "script"))
        // Without a type to compare against, the rule is not ruled out.
        assertTrue(ruleMatchesRequest(rule, "example.com"))
    }

    @Test
    fun aDomainScopeLimitsWhereTheRuleRuns() {
        val rule = "||ads.example^\$domain=news.example"
        val scoped = parseRule(rule)
        assertEquals("news.example", scoped.domainScope)
        assertNotNull(scoped.pattern)
    }

    @Test
    fun theSummarySaysWhatTheRuleDoes() {
        val described = describeRule(parseRule("||example.com^\$third-party,important,image"))
        assertTrue(described.blocked)
        assertTrue(described.thirdParty)
        assertTrue(described.important)
        assertEquals(listOf("image"), described.types)
    }
}
