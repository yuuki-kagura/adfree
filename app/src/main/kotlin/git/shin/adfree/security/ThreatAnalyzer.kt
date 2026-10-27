package git.shin.adfree.security

import git.shin.adfree.core.CoreEngine
import git.shin.adfree.data.AdGuardRepository
import git.shin.adfree.model.ThreatAnalysisResult
import git.shin.adfree.model.ThreatCategory
import git.shin.adfree.model.ThreatRiskLevel
import java.util.Locale

/**
 * Analyse a domain offline, entirely on the device.
 *
 * The old version called Gemini over the network with mock data. Now:
 * 1. ask the filter engine whether the domain is blocked, and by which rule;
 * 2. score risk from host shape, abused TLDs and known ad-network names;
 * 3. suggest a properly formatted AdGuard rule.
 *
 * No network, no API key, no battery spent.
 */
class ThreatAnalyzer(
    private val repository: AdGuardRepository,
    private val engine: CoreEngine,
) {

    fun analyze(domain: String): ThreatAnalysisResult {
        val host = domain.trim().lowercase(Locale.ROOT).removeSuffix(".")
        if (host.isBlank()) {
            return ThreatAnalysisResult(
                domain = domain,
                riskScore = 0,
                riskLevel = ThreatRiskLevel.UNKNOWN,
                category = ThreatCategory.EMPTY,
                suggestedRules = emptyList(),
            )
        }

        val (blocked, rule, list) = repository.checkHost(host)
        val score = riskScore(host)
        val category = when {
            blocked -> ThreatCategory.FILTER_BLOCKED
            score >= 60 -> ThreatCategory.SUSPICIOUS
            else -> ThreatCategory.UNKNOWN
        }

        val rules = mutableListOf("||$host^")
        if (score >= 60) rules += "||$host^\$important"
        if (!blocked && score >= 40) rules += "0.0.0.0 $host"

        return ThreatAnalysisResult(
            domain = host,
            riskScore = score,
            riskLevel = ThreatRiskLevel.fromScore(score),
            category = category,
            suggestedRules = rules,
            isBlockedByFilters = blocked,
            matchedRule = rule.ifBlank { null },
            matchedList = list.ifBlank { null },
        )
    }

    /** Kept internal so JVM tests can call it; used by [ThreatAnalyzerTest]. */
    internal fun riskScore(host: String): Int {
        var score = 0
        // 1. Technical shape of the host.
        val labels = host.split('.')
        val tld = labels.lastOrNull().orEmpty()
        if (labels.size >= 4) score += 15
        if (labels.any { it.length > 30 }) score += 15
        if (labels.any { it.count { c -> c.isDigit() } >= 4 }) score += 20
        if (host.contains("://")) score += 20

        // 2. Keywords typical of ads/trackers.
        // Well known ad/tracking networks that blocklists very often contain.
        val networkHints = listOf(
            "doubleclick", "googlesyndication", "facebook.net", "facebook.com",
            "appsflyer", "app-measurement", "branch.io", "adjust.com",
            "kochava", "crashlytics", "newrelic", "hotjar", "mixpanel",
            "amplitude", "segment.io", "taboola", "outbrain", "criteo",
            "adcolony", "applovin", "unityads", "chartboost", "vungle",
            "ironsrc", "smartadserver", "amazon-adsystem", "adnxs",
        )
        val adKeywords = listOf(
            "adservice", "doubleclick", "googlesyndication", "adsystem", "adnxs",
            "adcolony", "applovin", "unityads", "chartboost", "vungle", "ironsrc",
            "track", "analytics", "telemetry", "measure", "metrics", "beacon",
            "pixel", "count", "collect", "report", "crashlytics", "appsflyer",
            "branch", "adjust", "kochava", "singular", "mixpanel", "amplitude",
            "segment", "hotjar", "mouseflow", "crazyegg", "newrelic",
        )
        val keywordHits = adKeywords.count { host.contains(it) }
        val networkHits = networkHints.count { host.contains(it) }
        score += ((keywordHits + networkHits) * 12).coerceAtMost(48)

        // 3. TLD is a ONE-WAY signal: junk TLDs (.click, .xyz) raise risk because most
        // free ad networks use them. .com/.org do not lower the score — facebook.com
        // and wikipedia.org share that TLD, so penalising by TLD would erase the
        // signal of a genuinely suspicious host.
        if (tld in ABUSED_TLDS) score += 10

        // 4. Unusual length.
        if (host.length > 60) score += 10

        return score.coerceIn(0, 100)
    }

    private companion object {
        val ABUSED_TLDS = setOf(
            "click", "link", "top", "xyz", "info", "icu", "buzz", "monster", "rest",
            "cam", "surf", "space", "website", "online", "fit", "surf", "cf", "ga",
        )
    }
}
