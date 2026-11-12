package git.shin.adfree.desktop

import androidx.compose.ui.graphics.toAwtImage
import java.io.File
import javax.imageio.ImageIO
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The tray is the app's state in a place the user can see while the window is
 * hidden, and on Windows it is the *only* such place: the platform tray shows a
 * picture and a tooltip and nothing else.
 *
 * So the two pictures are written out here and compared — not pixel for pixel,
 * which would fail the first time the app icon is redrawn, but as "the paused
 * one is different, and it is different in the corner where a status mark
 * belongs". The files are left in `build/tmp` so a human can look at them.
 */
class TrayIconTest {

    private val out = File("build/tmp/tray-icon").apply { mkdirs() }

    @Test
    fun theFilteringIconIsTheAppIcon() {
        val file = File(out, "tray-on.png")
        ImageIO.write(pausedTrayGlyph(false).toAwtImage(), "png", file)
        assertTrue("the icon is written for eyeballing", file.isFile)
        assertTrue("and it is not empty", file.length() > 0)
    }

    @Test
    fun thePausedIconCarriesAMarkInTheCorner() {
        val on = pausedTrayGlyph(false).toAwtImage()
        val off = pausedTrayGlyph(true).toAwtImage()
        File(out, "tray-off.png").let { ImageIO.write(off, "png", it) }

        val w = minOf(on.width, off.width)
        val h = minOf(on.height, off.height)
        var differing = 0
        var cornerDiffering = 0
        for (x in 0 until w) {
            for (y in 0 until h) {
                if (on.getRGB(x, y) != off.getRGB(x, y)) {
                    differing += 1
                    // The mark is expected in the bottom-right quarter; a
                    // recolour of the whole icon would light up everywhere.
                    if (x > w / 2 && y > h / 2) cornerDiffering += 1
                }
            }
        }
        assertTrue("the paused icon is a different picture", differing > 0)
        assertTrue("the mark is a mark, not a recolour", differing < w * h / 2)
        assertTrue("and it sits in the corner", cornerDiffering > differing * 8 / 10)
    }

    /** Windows shows this on hover and nowhere else. */
    @Test
    fun theTooltipSaysWhatIsHappening() {
        assertTrue(trayTooltip(false).startsWith("AdFree"))
        assertTrue(trayTooltip(true).startsWith("AdFree"))
        assertNotEquals(trayTooltip(false), trayTooltip(true))
    }
}
