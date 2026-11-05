package git.shin.adfree.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Data-only catalogue, but a duplicate id or a non-HTTPS URL silently
 * corrupts the Filters tab (two rows sharing stored state, a download that
 * can never succeed). These invariants are cheap to keep green.
 */
class FilterCatalogTest {

    @Test
    fun idsAreUniqueAndNonBlank() {
        val ids = FilterCatalog.filters.map { it.id }
        assertEquals(ids.size, ids.toSet().size)
        assertTrue(ids.all { it.isNotBlank() })
    }

    @Test
    fun everyEntryHasDownloadableMetadata() {
        for (filter in FilterCatalog.filters) {
            assertTrue("${filter.id}: name", filter.name.isNotBlank())
            assertTrue("${filter.id}: description", filter.descriptionKey.isNotBlank())
            assertTrue("${filter.id}: https url", filter.url.startsWith("https://"))
            assertTrue(
                "${filter.id}: format",
                filter.format == CatalogFilter.FORMAT_STANDARD ||
                    filter.format == CatalogFilter.FORMAT_HOSTS,
            )
        }
    }

    @Test
    fun everyGroupIsRepresented() {
        for (group in FilterGroup.entries) {
            assertNotNull(
                "group ${group.id} has no entry",
                FilterCatalog.filters.firstOrNull { it.group == group },
            )
        }
    }

    @Test
    fun byIdResolvesAndRejectsUnknownIds() {
        val first = FilterCatalog.filters.first()
        assertEquals(first, FilterCatalog.byId(first.id))
        assertNull(FilterCatalog.byId("no-such-filter"))
    }

    @Test
    fun localeTagsAreWellFormedAndOnlyOnLanguageFilters() {
        for (filter in FilterCatalog.filters) {
            for (tag in filter.locales) {
                assertTrue("${filter.id}: tag $tag", tag.matches(Regex("[a-z]{2}")))
            }
            if (filter.locales.isNotEmpty()) {
                assertEquals("${filter.id}: group", FilterGroup.LANGUAGE, filter.group)
            }
        }
    }

    @Test
    fun aVietnameseDeviceStartsWithAbpvn() {
        assertEquals(listOf("abpvn"), FilterCatalog.forLanguage("vi").map { it.id })
        // The Spanish/Portuguese filter serves both languages, as in AdGuard.
        assertEquals(listOf("ag-spanish"), FilterCatalog.forLanguage("pt").map { it.id })
        assertEquals(emptyList<CatalogFilter>(), FilterCatalog.forLanguage("en"))
        assertEquals(emptyList<CatalogFilter>(), FilterCatalog.forLanguage(""))
    }
}
