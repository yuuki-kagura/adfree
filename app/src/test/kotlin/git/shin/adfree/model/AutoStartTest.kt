package git.shin.adfree.model

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AutoStartTest {

    @Test
    fun `boot restores protection only when both switches are on`() {
        assertTrue(shouldStartOnBoot(autoStart = true, protectionWasOn = true))
        assertFalse(shouldStartOnBoot(autoStart = false, protectionWasOn = true))
        assertFalse(shouldStartOnBoot(autoStart = true, protectionWasOn = false))
        assertFalse(shouldStartOnBoot(autoStart = false, protectionWasOn = false))
    }
}
