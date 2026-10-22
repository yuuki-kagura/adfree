package git.shin.adfree.model

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FilterMatchesQueryTest {

    private fun list(
        name: String = "AdGuard Base",
        description: String = "Bộ lọc quảng cáo",
        url: String? = "https://example.org/list.txt",
    ) = FilterList(
        id = "test",
        name = name,
        description = description,
        ruleCount = 0,
        isEnabled = true,
        category = "ad",
        version = "",
        subscriptionUrl = url,
    )

    @Test
    fun matchesNameAndDescriptionCaseInsensitively() {
        assertTrue(filterMatchesQuery(list(), "adguard"))
        assertTrue(filterMatchesQuery(list(), "QUẢNG CÁO"))
    }

    @Test
    fun matchesTheSourceUrl() {
        assertTrue(filterMatchesQuery(list(), "example.org"))
        assertFalse(filterMatchesQuery(list(url = null), "example.org"))
    }

    @Test
    fun blankQueryMatchesEverythingAndForeignTextDoesNot() {
        assertTrue(filterMatchesQuery(list(), "  "))
        assertFalse(filterMatchesQuery(list(), "không-có-gì-khớp"))
    }
}
