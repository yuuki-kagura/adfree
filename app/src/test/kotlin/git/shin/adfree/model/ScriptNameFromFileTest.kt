package git.shin.adfree.model

import org.junit.Assert.assertEquals
import org.junit.Test

class ScriptNameFromFileTest {

    @Test
    fun stripsUserscriptSuffixes() {
        assertEquals("anti-adblock", scriptNameFromFile("anti-adblock.user.js"))
        assertEquals("helper", scriptNameFromFile("helper.js"))
        assertEquals("already-clean", scriptNameFromFile("already-clean"))
    }

    @Test
    fun fallsBackWhenThePickerHasNoName() {
        assertEquals("Tiện ích từ tệp", scriptNameFromFile(null))
        assertEquals("Tiện ích từ tệp", scriptNameFromFile("   "))
        assertEquals("Tiện ích từ tệp", scriptNameFromFile(".user.js"))
    }

    @Test
    fun capsLongNames() {
        val long = "x".repeat(200) + ".user.js"
        assertEquals(60, scriptNameFromFile(long).length)
    }
}
