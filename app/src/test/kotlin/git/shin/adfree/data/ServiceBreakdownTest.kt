package git.shin.adfree.data

import git.shin.adfree.core.DomainUsage
import git.shin.adfree.model.ServiceUsage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The company labels come from a table the app may not have: the shipped copy
 * knows only the networks it was authored for, and a subscription can be absent,
 * empty or refused. The breakdown has to degrade to plain domain names instead of
 * guessing, and it has to stop calling itself a list of services when nothing
 * resolved. These tests pin that fallback to the two helpers the screen reads.
 */
class ServiceBreakdownTest {

    @Test
    fun `a missing dataset falls back to domain names`() {
        val rows = serviceRows(
            listOf(
                usage("doubleclick.net", "", blocked = 12, requests = 20),
                usage("unknown-tracker.example", "", blocked = 3, requests = 4),
            ),
        )
        assertFalse(servicesKnownByCompany(rows))
        assertEquals("doubleclick.net", rows.first().label)
        assertEquals("unknown-tracker.example", rows[1].label)
    }

    @Test
    fun `one resolved company is enough to name the section by service`() {
        val rows = serviceRows(
            listOf(
                usage("ads.doubleclick.net", "Google", blocked = 40, requests = 50),
                usage("unknown-tracker.example", "", blocked = 3, requests = 4),
            ),
        )
        assertTrue(servicesKnownByCompany(rows))
        assertEquals("Google", rows.first().label)
        // The row without a company still shows its domain, never a guess.
        assertEquals("unknown-tracker.example", rows[1].label)
        assertEquals("Google", ServiceUsage(domain = "doubleclick.net", company = "Google").label)
    }

    @Test
    fun `counts survive the conversion without reordering`() {
        val rows = serviceRows(
            listOf(
                usage("a.example", "A", blocked = 9, requests = 11, bytesSaved = 1_000L),
                usage("b.example", "", blocked = 1, requests = 2, bytesSaved = 0L),
            ),
        )
        assertEquals(9, rows[0].blocked)
        assertEquals(11, rows[0].requests)
        assertEquals(1_000L, rows[0].bytesSaved)
        // The core groups biggest-first; the UI must not resort and lose that.
        assertEquals(listOf("a.example", "b.example"), rows.map { it.domain })
    }

    @Test
    fun `the category a dataset carries joins the domain on the second line`() {
        val withCategory = serviceRows(listOf(usage("doubleclick.net", "Google", blocked = 1, requests = 2, category = "advertising")))
        val without = serviceRows(listOf(usage("doubleclick.net", "Google", blocked = 1, requests = 2)))
        assertEquals("doubleclick.net · advertising", serviceSubtitle(withCategory.first()))
        assertEquals("doubleclick.net", serviceSubtitle(without.first()))
    }

    private fun usage(
        domain: String,
        company: String,
        blocked: Int,
        requests: Int,
        bytesSaved: Long = 0L,
        category: String = "",
    ) = DomainUsage(
        domain = domain,
        company = company,
        category = category,
        blocked = blocked.toUInt(),
        requests = requests.toUInt(),
        bytesSaved = bytesSaved.toULong(),
    )
}
