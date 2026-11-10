package git.shin.adfree.desktop

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The privileged unit wakes up in a session it did not start in. The values it
 * can read from the user manager, and the cookie it can find on disk, are what
 * keep that from being an `AWTError` on the first line.
 */
class DesktopSessionTest {

    @Test
    fun theUserManagersEnvironmentIsReadAsPairs() {
        val environment = DesktopSession.parseShowEnvironment(
            """
            LANG=vi_VN.UTF-8
            DISPLAY=:0
            XAUTHORITY=/run/user/1000/xauth_abc
            EMPTY=
            not a pair
            """.trimIndent(),
        )
        assertEquals(":0", environment["DISPLAY"])
        assertEquals("/run/user/1000/xauth_abc", environment["XAUTHORITY"])
        assertEquals("", environment["EMPTY"])
        assertTrue("a line without '=' is not a pair", "not a pair" !in environment)
    }

    /**
     * A new login does not rename the directory, it only adds a file: the
     * session's cookie has to be picked by time, because its name is random.
     */
    @Test
    fun theNewestCookieIsTheOneTheSessionJustWrote() {
        val directory = File.createTempFile("adfree-session-", "").let { it.delete(); it.mkdirs(); it }
        val old = File(directory, "xauth_old").apply { writeText("old"); setLastModified(1_000) }
        val fresh = File(directory, "xauth_new").apply { writeText("new"); setLastModified(2_000) }
        File(directory, "not-a-cookie").apply { writeText("x"); setLastModified(3_000) }

        assertEquals(fresh, DesktopSession.newestXAuthority(directory))
        assertTrue(old.isFile)
    }

    @Test
    fun aDirectoryWithNoCookieAnswersNothingRatherThanGuessing() {
        val directory = File.createTempFile("adfree-session-", "").let { it.delete(); it.mkdirs(); it }
        assertNull(DesktopSession.newestXAuthority(directory))
        assertNull(DesktopSession.newestXAuthority(null))
    }
}
