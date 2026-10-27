package git.shin.adfree.data

import git.shin.adfree.model.UserScriptStoreItem
import git.shin.adfree.model.UserScriptStoreSort
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The store must degrade safely when Greasy Fork returns odd rows.
 *
 * The base Application is deliberate: the production one opens the native
 * core in `onCreate`, which a JVM test cannot load. This class only exercises
 * JSON parsing.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class UserScriptStoreTest {

    private fun entry(
        id: Int,
        codeUrl: String? = "https://update.greasyfork.org/scripts/$id/Test.user.js",
    ): JSONObject = JSONObject()
        .put("id", id)
        .put("name", "Script $id")
        .put("description", "Description $id")
        .put("url", "https://greasyfork.org/scripts/$id")
        .put("version", "1.$id")
        .put("daily_installs", 12)
        .put("total_installs", 34_000)
        .put("license", "MIT")
        .put("code_size", 1234)
        .put("code_url", codeUrl ?: JSONObject.NULL)

    @Test
    fun `parses the fields the sheet shows`() {
        val items = parseGreasyForkScripts(JSONArray().put(entry(7)).toString())

        assertEquals(1, items.size)
        val item = items[0]
        assertEquals(7L, item.id)
        assertEquals("Script 7", item.name)
        assertEquals("Description 7", item.description)
        assertEquals("https://update.greasyfork.org/scripts/7/Test.user.js", item.url)
        assertEquals("https://greasyfork.org/scripts/7", item.pageUrl)
        assertEquals("1.7", item.version)
        assertEquals(34_000, item.totalInstalls)
        assertEquals("MIT", item.license)
    }

    @Test
    fun `drops rows without a usable download url`() {
        val items = parseGreasyForkScripts(
            JSONArray()
                .put(entry(1, codeUrl = null))
                .put(entry(2, codeUrl = "javascript:alert(1)"))
                .put(entry(3))
                .toString(),
        )

        assertEquals(1, items.size)
        assertEquals(3L, items[0].id)
    }

    @Test
    fun `drops a source page that is not a web url`() {
        val row = entry(4).put("url", "javascript:alert(1)")
        val items = parseGreasyForkScripts(JSONArray().put(row).toString())

        assertEquals(1, items.size)
        assertEquals("", items[0].pageUrl)
    }

    @Test
    fun `caps the result list`() {
        val array = JSONArray()
        for (i in 0 until 60) array.put(entry(i))
        val items = parseGreasyForkScripts(array.toString())
        assertEquals(50, items.size)
        assertTrue(items.all { it.url.startsWith("https://") })
    }

    @Test
    fun `url keeps the first page and default sort byte identical`() {
        assertEquals(
            "https://api.greasyfork.org/en/scripts.json",
            greasyForkUrl("", 1, UserScriptStoreSort.RELEVANCE),
        )
    }

    @Test
    fun `url carries the page and the selected sort`() {
        assertEquals(
            "https://api.greasyfork.org/en/scripts.json?q=ad+block&page=2&sort=daily_installs",
            greasyForkUrl("ad block", 2, UserScriptStoreSort.DAILY_INSTALLS),
        )
        assertEquals(
            "https://api.greasyfork.org/en/scripts.json?page=3&sort=name",
            greasyForkUrl("", 3, UserScriptStoreSort.NAME),
        )
    }

    @Test
    fun `merging a page drops the same download url`() {
        val first = listOf(item(1), item(2))
        val second = listOf(item(2), item(3), item(3))
        val merged = mergeGreasyForkItems(first, second)

        assertEquals(listOf(1L, 2L, 3L), merged.map { it.id })
    }

    private fun item(id: Int) = UserScriptStoreItem(
        id = id.toLong(),
        name = "Script $id",
        description = "",
        url = "https://update.greasyfork.org/scripts/$id/Test.user.js",
        pageUrl = "https://greasyfork.org/scripts/$id",
        version = "1",
        dailyInstalls = 0,
        totalInstalls = 0,
        license = "",
        codeSizeBytes = 0,
    )
}
