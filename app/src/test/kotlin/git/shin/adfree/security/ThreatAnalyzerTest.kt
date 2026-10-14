package git.shin.adfree.security

import git.shin.adfree.model.ThreatAnalysisResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**


 */
class ThreatAnalyzerTest {

    /**


     * fails as a regression signal rather than silently drifting.
     */
    private fun score(host: String): Int = analyzer.riskScore(host)

    private val analyzer = ThreatAnalyzer(
        repository = git.shin.adfree.data.AdGuardRepository(
            context = android.app.Application(),
            engine = git.shin.adfree.core.CoreEngine(),
        ),
        engine = git.shin.adfree.core.CoreEngine(),
    )

    @Test
    fun `known ad networks carry a clear signal`() {
        val hosts = listOf(
            "googleads.g.doubleclick.net",
            "graph.facebook.com",
            "adservice.google.com",
            "sdk.appsflyer.com",
        )
        for (host in hosts) {
            val value = score(host)
            // One keyword = 12 points: enough to separate it from a clean host (0),
            // but not enough for "High" — the blocklist is the real arbiter.
            assertTrue("$host scored $value, expected >= 12", value >= 12)
        }
    }

    @Test
    fun `several signals push a host into the high band`() {
        val value = score("ads.tracking.analytics.doubleclick.net")
        assertTrue("multi-signal host scored $value", value >= 50)
    }

    @Test
    fun `legitimate hosts score low`() {
        assertTrue(score("api.github.com") < 25)
        assertTrue(score("cdn.jsdelivr.net") < 25)
        assertTrue(score("vnexpress.net") < 25)
    }

    @Test
    fun `ad networks always outrank clean hosts`() {
        val adSites = listOf(
            "googleads.g.doubleclick.net",
            "graph.facebook.com",
            "sdk.appsflyer.com",
        )
        val clean = listOf("api.github.com", "vnexpress.net", "wikipedia.org")
        val lowestAd = adSites.minOf { score(it) }
        val highestClean = clean.maxOf { score(it) }
        assertTrue(
            "ad min=$lowestAd must exceed clean max=$highestClean",
            lowestAd > highestClean,
        )
    }

    @Test
    fun `score stays within bounds`() {
        assertTrue(score("a".repeat(200) + ".click") in 0..100)
        assertTrue(score("x.io") in 0..100)
    }

    @Test
    fun `heuristics do not flag punctuation`() {
        // Hosts never contain "://", so no points are added.
        assertEquals(0, score("").coerceAtLeast(0))
        assertFalse("host sạch không bị đánh dấu nguy hiểm", score("wikipedia.org") >= 75)
    }

    @Test
    fun `result carries rules and matched filter`() {
        val result = ThreatAnalysisResult(
            domain = "ads.example.com",
            riskScore = 72,
            riskLevel = "Cao",
            category = "Bất thường",
            summary = "…",
            suggestedRules = listOf("||ads.example.com^"),
            isBlockedByFilters = true,
            matchedRule = "||ads.example.com^",
            matchedList = "AdGuard DNS filter",
        )
        assertTrue(result.isBlockedByFilters)
        assertEquals("AdGuard DNS filter", result.matchedList)
    }
}
