package git.shin.adfree.update

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class VersioningTest {

    @Test
    fun normalizeVersionStripsTagPrefixAndSuffix() {
        assertEquals("1.2.3", normalizeVersion("v1.2.3"))
        assertEquals("1.2.3", normalizeVersion(" 1.2.3-rc1 "))
        assertEquals("1.2.3", normalizeVersion("1.2.3+build7"))
        assertNull(normalizeVersion("1.2.x"))
        assertNull(normalizeVersion(""))
    }

    @Test
    fun isNewerVersionComparesDottedNumbers() {
        assertTrue(isNewerVersion("1.2.0", "1.1.9"))
        assertTrue(isNewerVersion("1.10", "1.9"))
        assertTrue(isNewerVersion("2.0", "1.99.99"))
        assertFalse(isNewerVersion("1.2.3", "1.2.3"))
        assertFalse(isNewerVersion("1.2", "1.2.1"))
        assertFalse(isNewerVersion("garbage", "1.0"))
    }

    @Test
    fun shouldOfferUpdateUsesReleaseTagAgainstBuildVersion() {
        assertTrue(shouldOfferUpdate("v1.2.0", "1.1.1"))
        assertFalse(shouldOfferUpdate("v1.1.1", "1.1.1"))
        assertFalse(shouldOfferUpdate("draft", "1.1.1"))
    }

    @Test
    fun dueForAutomaticCheckRunsFirstTimeAndAfterInterval() {
        val interval = 24L * 60 * 60 * 1000
        assertTrue(dueForAutomaticCheck(0L, 123L, interval))
        assertFalse(dueForAutomaticCheck(1_000L, 1_000L + interval - 1, interval))
        assertTrue(dueForAutomaticCheck(1_000L, 1_000L + interval, interval))
    }
}
