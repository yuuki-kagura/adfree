package git.shin.adfree.model

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The filter detail sheet quotes the body length straight from the core; the
 * rounding rules have to stay stable so a "1.9 MB" never becomes "0 MB".
 */
class AssetSizeLabelTest {

    @Test
    fun `zero and negative stay zero`() {
        assertEquals("0 B", assetSizeLabel(0L))
        assertEquals("0 B", assetSizeLabel(-3L))
    }

    @Test
    fun `small bodies stay in bytes`() {
        assertEquals("512 B", assetSizeLabel(512L))
    }

    @Test
    fun `kilobytes floor to a whole number`() {
        assertEquals("1 KB", assetSizeLabel(1024L))
        assertEquals("1 KB", assetSizeLabel(1500L))
        assertEquals("100 KB", assetSizeLabel(102_400L))
    }

    @Test
    fun `megabytes use one decimal`() {
        assertEquals("1.0 MB", assetSizeLabel(1024L * 1024L))
        assertEquals("1.9 MB", assetSizeLabel(1_999_229L))
        // A real corpus: the 640 MB sample Apk aside, subscription bodies are
        // single-digit MB at most.
        assertEquals("32.0 MB", assetSizeLabel(33_554_432L))
    }
}
