package git.shin.adfree.l10n

import java.io.InputStream
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element

/**
 * The string tables and the [Strings] key list drift apart silently: a screen
 * asking for a key no table carries renders the key itself, and a key added to
 * one locale only shows half the translation. Both are checked against the
 * real tables rather than a hand-kept list, because the desktop shell wording
 * lands on both sides at once.
 */
class StringTableTest {

    private fun table(resource: String): Map<String, Boolean> {
        val stream = object {}.javaClass.classLoader.getResourceAsStream(resource)
            ?: error("$resource missing from the classpath")
        return stream.use(::documentEntries)
    }

    private fun documentEntries(stream: InputStream): Map<String, Boolean> {
        val document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(stream)
        val nodes = document.getElementsByTagName("string")
        return buildMap(nodes.length) {
            for (i in 0 until nodes.length) {
                val node = nodes.item(i) as Element
                put(node.getAttribute("name"), node.getAttribute("translatable") != "false")
            }
        }
    }

    private fun declaredKeys(): List<String> =
        Strings::class.java.fields
            .filter { it.type == String::class.java && java.lang.reflect.Modifier.isStatic(it.modifiers) }
            .map { it.get(null) as String }

    @Test
    fun everyDeclaredKeyIsInBothTables() {
        val english = table("l10n/strings-default.xml")
        val vietnamese = table("l10n/strings-vi.xml")
        val keys = declaredKeys()
        assertTrue("the key list should be large", keys.size > 1000)

        assertEquals("keys declared but in no table", emptyList<String>(), keys.filter { it !in english })
        // A brand key with no table entry at all is the bug this catches.
        val untranslated = english.filterValues { it }.keys - vietnamese.keys
        assertEquals("keys missing from the Vietnamese table", emptyList<String>(), untranslated.sorted())
    }

    @Test
    fun vietnameseTableHasNoKeysEnglishLacks() {
        val english = table("l10n/strings-default.xml")
        val orphaned = table("l10n/strings-vi.xml").keys - english.keys
        assertEquals("orphaned Vietnamese keys: $orphaned", emptyList<String>(), orphaned.sorted())
    }

    @Test
    fun desktopShellKeysResolveTranslatedInVietnamese() {
        // A vi entry copied from English is a translation bug the desktop shows
        // immediately, so the shell wording is checked to actually differ.
        listOf(
            Strings.tray_open,
            Strings.tray_exit,
            Strings.tray_hidden,
            Strings.header_check_updates,
            Strings.header_export_settings,
            Strings.header_import_settings,
            Strings.stats_clear_action,
            Strings.stats_clear_body,
        ).forEach { key ->
            val english = L10n.get(key, "en")
            val vietnamese = L10n.get(key, "vi")
            assertTrue("$key unresolved", english != key && vietnamese != key)
            assertTrue("$key identical in both tables", english != vietnamese)
        }
    }
}
