package git.shin.adfree.model

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The counters the home screen and the log chips print.
 *
 * The failure this guards is a label that grows with the traffic until it wraps
 * or clips, and a figure that changes when the unit does: a reader must be able
 * to compare `999` with `1K` without doing arithmetic.
 */
class CountFormatTest {

    @Test
    fun smallCountsStayExact() {
        assertEquals("0", CountFormat.compact(0))
        assertEquals("7", CountFormat.compact(7))
        assertEquals("999", CountFormat.compact(999))
    }

    @Test
    fun thousandsKeepOneDecimalUntilTheyDoNotNeedIt() {
        assertEquals("1K", CountFormat.compact(1_000))
        assertEquals("1.2K", CountFormat.compact(1_200))
        assertEquals("12.3K", CountFormat.compact(12_345))
        assertEquals("136K", CountFormat.compact(136_455))
    }

    @Test
    fun aUnitThatWouldRoundToFourDigitsIsPromoted() {
        // "1000K" is a worse answer than "1M", and the slot is sized for three
        // digits plus a suffix.
        assertEquals("1M", CountFormat.compact(999_999))
        assertEquals("1.2M", CountFormat.compact(1_234_567))
        assertEquals("3.4B", CountFormat.compact(3_400_000_000))
    }

    @Test
    fun trafficPicksTheUnitAReaderThinksIn() {
        assertEquals("512 KB", CountFormat.data(512L * 1024))
        assertEquals("12 MB", CountFormat.data(12L * 1024 * 1024))
        assertEquals("3.5 GB", CountFormat.data(3_730_882_560L))
        assertEquals("0 B", CountFormat.data(0))
    }

    @Test
    fun negativeCountersReadAsZero() {
        assertEquals("0", CountFormat.compact(-1))
    }
}
