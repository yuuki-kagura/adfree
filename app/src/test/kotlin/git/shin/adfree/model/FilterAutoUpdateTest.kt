package git.shin.adfree.model

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The launch-time refresh must never download a body that is not due. */
class FilterAutoUpdateTest {

    private val hour = 60L * 60L * 1000L
    private val now = 1_700_000_000_000L

    @Test
    fun `zero hours disables the refresh`() {
        assertFalse(filterUpdateDue(now - 100 * hour, now, 0))
    }

    @Test
    fun `a list never downloaded is left to the startup path`() {
        // lastUpdatedMs == 0 means "no body on disk"; refreshFilesAndDownload
        // already downloads it and auto-update must not race it.
        assertFalse(filterUpdateDue(0, now, 24))
    }

    @Test
    fun `a fresh body is not downloaded again`() {
        assertFalse(filterUpdateDue(now - 5 * hour, now, 6))
        assertFalse(filterUpdateDue(now - 6 * hour + 1, now, 6))
    }

    @Test
    fun `a body exactly at the interval is due`() {
        assertTrue(filterUpdateDue(now - 6 * hour, now, 6))
        assertTrue(filterUpdateDue(now - 48 * hour, now, 24))
    }

    @Test
    fun `a future timestamp is ignored instead of treated as old`() {
        assertFalse(filterUpdateDue(now + hour, now, 24))
    }
}
