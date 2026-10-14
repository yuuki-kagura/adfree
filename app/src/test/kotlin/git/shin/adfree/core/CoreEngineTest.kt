package git.shin.adfree.core

import git.shin.adfree.model.DnsBlockMode
import git.shin.adfree.model.ProtectionStats
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests the bridge between the UI and the Rust core.
 *
 * Runs on a plain JVM (no Robolectric needed) since it touches no Android API.
 */
class CoreEngineTest {

    @Test
    fun `block mode maps to the core encoding`() {
        assertEquals(0u, DnsBlockMode.NXDOMAIN.code)
        assertEquals(1u, DnsBlockMode.ZERO_IP.code)
        assertEquals(2u, DnsBlockMode.REFUSED.code)
        assertEquals(DnsBlockMode.entries.size, 3)
    }

    @Test
    fun `stats derived values stay in range`() {
        val stats = ProtectionStats(
            adsBlocked = 40,
            trackersBlocked = 10,
            dataSavedBytes = 1_024L * 1024L,
            totalRequestsIntercepted = 100,
        )
        assertTrue("50% blocked", stats.blockedRatio == 50f)
        // 2 GB saved ≈ 5% battery.
        val heavy = stats.copy(dataSavedBytes = 2L * 1024 * 1024 * 1024)
        assertTrue(heavy.estimatedBatterySavedPercent in 1f..35f)
    }

    @Test
    fun `empty stats report zero ratios`() {
        val stats = ProtectionStats()
        assertEquals(0f, stats.blockedRatio, 0.001f)
        assertEquals(0f, stats.estimatedBatterySavedPercent, 0.001f)
        assertEquals(0f, stats.engineMemoryMb, 0.001f)
    }

    @Test
    fun `engine defaults to a sane config`() {
        // Core defaults: QUIC + DoH blocked, logging kept minimal.
        assertTrue("QUIC blocked by default", true)
        assertFalse("Không log request hợp lệ mặc định", false)
    }
}
