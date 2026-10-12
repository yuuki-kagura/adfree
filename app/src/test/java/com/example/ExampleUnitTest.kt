package com.example

import com.example.engine.FilterEngine
import com.example.model.FilterStatus
import com.example.model.RequestCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

class FilterEngineTest {

    private lateinit var filterEngine: FilterEngine

    @Before
    fun setUp() {
        filterEngine = FilterEngine()
    }

    @Test
    fun testAdDomainIsBlocked() {
        val decision = filterEngine.evaluateDomain("googleads.g.doubleclick.net")
        assertEquals(FilterStatus.BLOCKED, decision.status)
        assertEquals(RequestCategory.AD, decision.category)
        assertNotNull(decision.matchedRule)
    }

    @Test
    fun testTrackerDomainIsBlocked() {
        val decision = filterEngine.evaluateDomain("telemetry.sdk.appsflyer.com")
        assertEquals(FilterStatus.BLOCKED, decision.status)
        assertEquals(RequestCategory.TRACKER, decision.category)
    }

    @Test
    fun testLegitimateDomainIsAllowed() {
        val decision = filterEngine.evaluateDomain("api.github.com")
        assertEquals(FilterStatus.ALLOWED, decision.status)
        assertNull(decision.matchedRule)
    }

    @Test
    fun testWhitelistOverridesBlock() {
        // First verify domain is blocked
        val pre = filterEngine.evaluateDomain("pagead2.googlesyndication.com")
        assertEquals(FilterStatus.BLOCKED, pre.status)

        // Add whitelist rule
        filterEngine.addUserCustomWhitelist("pagead2.googlesyndication.com")

        val post = filterEngine.evaluateDomain("pagead2.googlesyndication.com")
        assertEquals(FilterStatus.WHITELISTED, post.status)
    }

    @Test
    fun testCustomRuleAddition() {
        val testDomain = "custom-evil-tracker.example.org"
        val pre = filterEngine.evaluateDomain(testDomain)
        assertEquals(FilterStatus.ALLOWED, pre.status)

        filterEngine.addRule("||$testDomain^", "Custom Test Filter", RequestCategory.TRACKER)
        val post = filterEngine.evaluateDomain(testDomain)
        assertEquals(FilterStatus.BLOCKED, post.status)
    }

    @Test
    fun testDnsResolutionCache() {
        val domain = "fast-api.company.com"
        assertNull(filterEngine.getCachedDns(domain))

        filterEngine.putCachedDns(domain, "104.21.40.12")
        assertEquals("104.21.40.12", filterEngine.getCachedDns(domain))

        filterEngine.clearDnsCache()
        assertNull(filterEngine.getCachedDns(domain))
    }
}
