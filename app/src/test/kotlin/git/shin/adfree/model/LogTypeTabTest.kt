package git.shin.adfree.model

import git.shin.adfree.l10n.L10n
import git.shin.adfree.l10n.Strings
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The log's type tabs are a partition of the log: AdGuard's list has ten of
 * them, every row lands in exactly one, and the names they group are the ones
 * the core writes. If the two ever drift apart a row silently stops appearing
 * on every tab, so the drift is pinned here.
 */
class LogTypeTabTest {

    /** Every resource name `rust/src/events.rs::req_type::name` can produce. */
    private val coreNames = listOf(
        "other", "document", "stylesheet", "script", "xhr", "image",
        "font", "media", "websocket", "dns", "connection",
    )

    @Test
    fun `the tabs are adguard's own set in adguard's own order`() {
        assertEquals(
            listOf(
                LogTypeTab.ALL, LogTypeTab.HTML, LogTypeTab.CSS, LogTypeTab.JS,
                LogTypeTab.AJAX, LogTypeTab.IMAGE, LogTypeTab.MEDIA, LogTypeTab.DNS,
                LogTypeTab.CONNECTION, LogTypeTab.OTHER,
            ),
            LogTypeTab.ordered,
        )
    }

    @Test
    fun `every name the core writes lands on exactly one tab`() {
        for (name in coreNames) {
            val homes = LogTypeTab.ordered.filter { it != LogTypeTab.ALL && it.matches(name) }
            assertEquals("$name belongs to one tab", 1, homes.size)
        }
    }

    @Test
    fun `an unclassified row belongs to other`() {
        // Rows written before the core classified anything, and rows the engine
        // never saw a resource for, have no type at all. Dropping them from
        // every tab would hide history the user can still read.
        for (name in listOf(null, "")) {
            assertTrue(LogTypeTab.OTHER.matches(name))
            assertFalse(LogTypeTab.HTML.matches(name))
            assertTrue(LogTypeTab.ALL.matches(name))
        }
    }

    @Test
    fun `all is the tab that hides nothing`() {
        (coreNames + listOf(null, "", "nonsense")).forEach { name ->
            assertTrue(LogTypeTab.ALL.matches(name))
        }
    }

    @Test
    fun `a name no tab claims is collected by other rather than lost`() {
        assertTrue(LogTypeTab.OTHER.matches("ping"))
        assertFalse(LogTypeTab.DNS.matches("ping"))
    }

    @Test
    fun `a tab key round-trips and an unknown one falls back to all`() {
        LogTypeTab.ordered.forEach { assertEquals(it, LogTypeTab.of(it.key)) }
        assertEquals(LogTypeTab.ALL, LogTypeTab.of("nothing-like-a-tab"))
    }

    @Test
    fun `the type column labels resolve in both languages`() {
        try {
            L10n.language = AppLanguage.ENGLISH
            assertEquals(L10n.get(Strings.req_type_dns), requestTypeLabel("dns"))
            assertFalse(requestTypeLabel("dns") == Strings.req_type_dns)
            assertTrue(requestTypeLabel("stylesheet") != Strings.req_type_stylesheet)
            // An oddball name is not shown raw next to the tabs that group it.
            assertEquals(L10n.get(Strings.req_type_other), requestTypeLabel("ping"))
            assertEquals(L10n.get(Strings.req_type_other), requestTypeLabel(null))

            L10n.language = AppLanguage.VIETNAMESE
            assertTrue(
                "the Vietnamese table has to translate the type, not copy it",
                requestTypeLabel("document") != L10n.get(Strings.req_type_document, "en"),
            )
            assertEquals(requestTypeLabel("dns"), L10n.get(Strings.req_type_dns, "vi"))
        } finally {
            L10n.language = AppLanguage.SYSTEM
        }
    }
}
