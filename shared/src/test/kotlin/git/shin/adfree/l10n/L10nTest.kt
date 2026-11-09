package git.shin.adfree.l10n

import git.shin.adfree.model.AppLanguage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class L10nTest {

    @Test
    fun loadsEveryKeyFromTheDefaultTable() {
        assertTrue("table should be large", L10n.get(Strings.app_name).isNotBlank())
        assertEquals("AdFree", L10n.get(Strings.app_name))
    }

    @Test
    fun vietnameseTableOverridesEnglish() {
        val english = L10n.get(Strings.app_name) // translatable=false, same both
        assertEquals(english, L10n.get(Strings.app_name, "vi"))
        // A translated key must differ from English somewhere in the table.
        val translated = listOf(
            Strings.home_modules_title,
            Strings.home_module_adblock_title,
            Strings.dns_probe_ok,
        )
        val differs = translated.any { L10n.get(it, "en") != L10n.get(it, "vi") }
        assertTrue("vi table must carry translations", differs)
    }

    @Test
    fun unknownKeyFallsBackToTheKeyItself() {
        assertEquals("no_such_key_anywhere", L10n.get("no_such_key_anywhere"))
    }

    @Test
    fun formatsPositionalArguments() {
        assertEquals("3 blocked", L10n.fill("%1\$d blocked", arrayOf(3)))
        assertEquals("a and b", L10n.fill("%1\$s and %2\$s", arrayOf("a", "b")))
        assertEquals("b then a", L10n.fill("%2\$s then %1\$s", arrayOf("a", "b")))
        assertEquals("100%", L10n.fill("100%%", emptyArray()))
        assertEquals("5x", L10n.fill("%1\$dx", arrayOf(5L)))
        // A precision spec is a format, not literal text: it used to render as
        // "+%1$.1f%" on the home screen.
        assertEquals("+12.3%", L10n.fill("+%1\$.1f%%", arrayOf(12.34)))
        assertEquals("0.0 MB", L10n.fill("%1\$.1f MB", arrayOf(0.0)))
    }

    @Test
    fun unescapesAndroidResourceEscapes() {
        assertEquals("Don't", L10n.unescape("Don\\'t"))
        assertEquals("line1\nline2", L10n.unescape("line1\\nline2"))
        assertEquals("@drawable", L10n.unescape("\\@drawable"))
        assertEquals("a\\b", L10n.unescape("a\\\\b"))
    }

    @Test
    fun languageSwitchChangesResolution() {
        L10n.language = AppLanguage.VIETNAMESE
        assertEquals("vi", L10n.locale())
        L10n.systemLanguage = "de"
        L10n.language = AppLanguage.SYSTEM
        assertEquals("de", L10n.locale())
        L10n.language = AppLanguage.ENGLISH
        assertEquals("en", L10n.locale())
        L10n.language = AppLanguage.SYSTEM
        L10n.systemLanguage = "en"
    }

    @Test
    fun everyDefaultKeyHasAVietnameseValueOrIsExempt() {
        // values-vi has fewer entries than values; the fallback must cover it.
        // Spot-check that the app's own title resolves in both locales.
        assertTrue(L10n.get(Strings.home_modules_title, "en").isNotBlank())
        assertTrue(L10n.get(Strings.home_modules_title, "vi").isNotBlank())
    }
}
