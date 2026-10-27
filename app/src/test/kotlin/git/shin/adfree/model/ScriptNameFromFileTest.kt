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
    fun returnsBlankWhenThePickerHasNoName() {
        // The repository substitutes the localized fallback.
        assertEquals("", scriptNameFromFile(null))
        assertEquals("", scriptNameFromFile("   "))
        assertEquals("", scriptNameFromFile(".user.js"))
    }

    @Test
    fun capsLongNames() {
        val long = "x".repeat(200) + ".user.js"
        assertEquals(60, scriptNameFromFile(long).length)
    }
}
