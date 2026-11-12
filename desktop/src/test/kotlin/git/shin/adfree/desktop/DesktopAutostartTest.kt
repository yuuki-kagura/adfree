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

    /**
     * Windows has to start the app *elevated*, and only a task with the highest
     * run level does that without a UAC prompt at every logon. What `schtasks`
     * receives is therefore the contract, and it is checked as data.
     */
    @Test
    fun windowsGetsALogonTaskThatRunsElevated() {
        val argv = DesktopAutostart.schtasksCreate(listOf("C:\\Program Files\\AdFree\\AdFree.exe"))
        assertEquals("schtasks", argv.first())
        assertTrue("created, not modified", argv.contains("/Create"))
        assertEquals("adfree-desktop", argv[argv.indexOf("/TN") + 1])
        assertEquals(
            "\"C:\\Program Files\\AdFree\\AdFree.exe\"",
            argv[argv.indexOf("/TR") + 1],
        )
        assertEquals("at logon, not at boot", "ONLOGON", argv[argv.indexOf("/SC") + 1])
        assertEquals("with the administrator token", "HIGHEST", argv[argv.indexOf("/RL") + 1])
        assertTrue("repeatable", argv.contains("/F"))
    }

    @Test
    fun aWindowsPathWithoutSpacesIsNotQuoted() {
        assertEquals(
            "C:\\AdFree\\AdFree.exe --tray",
            windowsCommandLine(listOf("C:\\AdFree\\AdFree.exe", "--tray")),
        )
    }

    @Test
    fun theWindowsSwitchDrivesTheTaskRatherThanAFile() {
        val calls = mutableListOf<List<String>>()
        val autostart = DesktopAutostart(
            entry = File("/nonexistent/adfree/should-not-be-written.desktop"),
            isWindows = true,
            run = { argv ->
                calls += argv
                true
            },
        )
        autostart.sync(enabled = true, unitInstalled = true, appArgv = listOf("C:\\AdFree\\AdFree.exe"))
            .getOrThrow()
        assertEquals("one task command", 1, calls.size)
        assertTrue("and it creates the task", calls.single().contains("/Create"))
        autostart.sync(enabled = false, unitInstalled = true, appArgv = listOf("C:\\AdFree\\AdFree.exe"))
            .getOrThrow()
        assertTrue("switching off deletes it", calls.last().contains("/Delete"))
        assertFalse("no XDG file is left behind", File("/nonexistent/adfree").exists())
    }

    /** A refused task creation must not be reported as "autostart is on". */
    @Test
    fun aRefusedTaskIsAFailure() {
        val autostart = DesktopAutostart(
            entry = File("/nonexistent/adfree/should-not-be-written.desktop"),
            isWindows = true,
            run = { false },
        )
        assertTrue(
            "the failure reaches the caller",
            autostart.sync(enabled = true, unitInstalled = true, appArgv = listOf("C:\\AdFree\\AdFree.exe"))
                .isFailure,
        )
    }
}
