package git.shin.adfree.desktop

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The autostart entry is a machine-readable file another program reads, so what
 * matters is its exact text, not that a file appeared.
 */
class DesktopAutostartTest {

    @Test
    fun theSwitchWritesAndRemovesTheEntry() {
        val entry = File.createTempFile("adfree-autostart-", ".desktop")
        val autostart = DesktopAutostart(entry)
        autostart.sync(enabled = true, unitInstalled = false, appArgv = listOf("/usr/bin/java", "-jar", "app.jar"))
            .getOrThrow()
        assertTrue("the entry is on disk", autostart.installed())
        assertTrue("and is a desktop entry", entry.readText().startsWith("[Desktop Entry]"))
        autostart.sync(enabled = false, unitInstalled = false, appArgv = emptyList()).getOrThrow()
        assertFalse("the switch off means the file is gone", entry.isFile)
    }

    /**
     * Once the protection unit exists, login starts that unit rather than the
     * app: a window that has to hand itself over to a privileged instance every
     * morning is a window that flashes twice.
     */
    @Test
    fun anInstalledUnitIsWhatTheSessionStarts() {
        val entry = File.createTempFile("adfree-autostart-", ".desktop")
        DesktopAutostart(entry).sync(
            enabled = true,
            unitInstalled = true,
            appArgv = listOf("/usr/bin/java", "-jar", "app.jar"),
        ).getOrThrow()
        val text = entry.readText()
        assertTrue("the unit, not the app: $text", "Exec=systemctl --no-block restart adfree-desktop" in text)
        assertTrue("no path is needed for a unit", "Path=" !in text)
    }

    /**
     * The entry has to carry the directory the app was installed from, because
     * a session starts it from the home directory and the core is found
     * relative to the working directory.
     */
    @Test
    fun theAppEntryCarriesTheWorkingDirectory() {
        val entry = File.createTempFile("adfree-autostart-", ".desktop")
        DesktopAutostart(entry).sync(
            enabled = true,
            unitInstalled = false,
            appArgv = listOf("/usr/bin/java", "-jar", "app.jar"),
            workingDirectory = "/opt/adfree",
        ).getOrThrow()
        assertTrue("the core is found from here", "Path=/opt/adfree" in entry.readText())
    }

    /**
     * A classpath is one long word; a home directory with a space in it is not
     * one word at all unless the entry says so. `%` doubles because the spec
     * reads it as the start of a field code.
     */
    @Test
    fun aPathWithASpaceStaysOneArgument() {
        val text = DesktopAutostart(File("/tmp/x.desktop")).render(
            listOf("/usr/bin/java", "-cp", "/home/a b/lib/*", "MainKt", "--at=50%"),
        )
        assertTrue(
            "the space is quoted and the percent escaped: $text",
            "Exec=/usr/bin/java -cp \"/home/a b/lib/*\" MainKt --at=50%%" in text,
        )
        assertEquals(" ", " ")
    }
}
