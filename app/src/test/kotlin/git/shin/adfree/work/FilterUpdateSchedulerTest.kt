package git.shin.adfree.work

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class FilterUpdateSchedulerTest {

    @Test
    fun `zero turns the periodic work off`() {
        assertNull(FilterUpdateScheduler.periodicHours(0))
        assertNull(FilterUpdateScheduler.periodicHours(-5))
    }

    @Test
    fun `a positive interval becomes the work period in hours`() {
        assertEquals(1L, FilterUpdateScheduler.periodicHours(1))
        assertEquals(24L, FilterUpdateScheduler.periodicHours(24))
        assertEquals(168L, FilterUpdateScheduler.periodicHours(168))
    }
}
