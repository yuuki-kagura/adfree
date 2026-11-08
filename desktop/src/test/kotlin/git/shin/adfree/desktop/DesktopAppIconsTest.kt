package git.shin.adfree.desktop

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A log row names the process the kernel names and shows the icon the desktop
 * names, and the two are never spelled alike: Chrome runs as `chrome` and
 * installs `google-chrome.desktop`. This is the translation, on made-up
 * directories so a machine's own application menu is not the test's business.
 */
class DesktopAppIconsTest {

    /** These bytes are a real 1×1 PNG: the decoder has to accept what it finds. */
    private val onePixelPng = byteArrayOf(
        0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15.toByte(), 0xC4.toByte(),
        0x89.toByte(), 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41,
        0x54, 0x78.toByte(), 0x9C.toByte(), 0x63, 0x00, 0x01, 0x00, 0x00,
        0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4.toByte(), 0x00,
        0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE.toByte(), 0x42, 0x60, 0x82.toByte(),
    )

    private fun fixture(): Pair<DesktopAppIcons, File> {
        val root = File(System.getProperty("java.io.tmpdir"), "adfree-icons-${System.nanoTime()}")
        val applications = File(root, "applications").apply { mkdirs() }
        File(applications, "google-chrome.desktop").writeText(
            """
            [Desktop Entry]
            Name=Google Chrome
            Exec=/usr/bin/google-chrome-stable %U
            Icon=google-chrome
            StartupWMClass=Google-chrome
            """.trimIndent(),
        )
        File(applications, "org.kde.konsole.desktop").writeText(
            """
            [Desktop Entry]
            Name=Konsole
            Exec=konsole
            Icon=org.kde.konsole
            """.trimIndent(),
        )
        val apps = File(root, "icons/hicolor/48x48/apps").apply { mkdirs() }
        File(apps, "google-chrome.png").writeBytes(onePixelPng)
        return DesktopAppIcons(listOf(applications), listOf(File(root, "icons"))) to root
    }

    @Test
    fun theProcessTheKernelNamesFindsTheIconTheDesktopNames() {
        val (icons, _) = fixture()
        // `chrome` is /proc/self/comm; `google-chrome` is what the entry ships.
        assertEquals("google-chrome", icons.iconName("chrome"))
        assertNotNull("the entry's icon has to decode", icons.icon("chrome"))
        // An exact name still wins over a partial one.
        assertEquals("org.kde.konsole", icons.iconName("konsole"))
    }

    @Test
    fun aProcessWithNoDesktopEntryHasNoIconRatherThanAGuess() {
        val (icons, _) = fixture()
        assertNull(icons.icon("definitely-not-a-program"))
    }

    /**
     * The bug that made Chrome's row blank: a wrapper entry that matches the
     * process name better than the real one but ships no `Icon=` won the
     * match and handed back nothing. A better name is worth less than an
     * answer.
     */
    @Test
    fun anEntryWithNoIconLosesToTheOneThatHasIt() {
        val (icons, root) = fixture()
        val applications = File(root, "applications")
        File(applications, "chrome-notify.desktop").writeText(
            """
            [Desktop Entry]
            Name=Chrome notification helper
            Exec=chrome-notify %u
            X-GNOME-Autostart-enabled=true
            """.trimIndent(),
        )
        // A fresh instance: entries are read once per lookup.
        val again = DesktopAppIcons(listOf(applications), listOf(File(root, "icons")))
        assertEquals("google-chrome", again.iconName("chrome"))
        assertNotNull(again.icon("chrome"))
    }

    @Test
    fun theIconIsLookedForWhereThemesKeepIt() {
        val (icons, root) = fixture()
        val found = icons.iconFile("google-chrome")
        assertNotNull(found)
        assertTrue(found!!.path.startsWith(File(root, "icons").path))
    }
}
