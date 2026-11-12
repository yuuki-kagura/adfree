package git.shin.adfree.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What "installed" means for a userscript, and which ones the app runs without
 * being asked.
 *
 * A script the app downloads is GPL-3.0 code that belongs to somebody else, so it
 * is fetched from its own URL and never vendored; a script the core ships is a
 * file in the store the moment the app starts. The two differ in *where the body
 * comes from*, not in whether it may be on, and both of those are decided here.
 */
class UserScriptCatalogTest {

    private fun entry(id: String): CatalogUserScript =
        UserScriptCatalog.scripts.firstOrNull { it.id == id }
            ?: throw AssertionError("no catalogue entry named $id")

    @Test
    fun `the youtube and anti-adblock modules ship with the app and start on`() {
        for (id in listOf("adfree-extra", "adfree-youtube")) {
            val script = entry(id)
            assertTrue("$id is shipped by the core", script.builtin)
            assertTrue("$id is on out of the box", script.defaultEnabled)
        }
    }

    @Test
    fun `a shipped module also has a release URL so a fix does not wait`() {
        for (id in listOf("adfree-extra", "adfree-youtube")) {
            val script = entry(id)
            // The same body is published with each release, so a machine on an
            // older build refreshes it on the list pass. The name has to match
            // what the release workflow uploads, or the URL is a 404 that the
            // script list would report as a failed refresh forever.
            assertTrue(
                "${id}'s URL is a release asset: ${script.url}",
                script.url.startsWith("https://github.com/yuuki-kagura/adfree/releases/"),
            )
            assertTrue("${id}'s URL names the asset", script.url.endsWith("$id.user.js"))
        }
    }

    @Test
    fun `adguard extra is downloaded and on out of the box`() {
        val script = entry("adguard-extra")
        assertFalse("never vendored", script.builtin)
        assertTrue(script.defaultEnabled)
        // Fetched from AdGuard's own userscript endpoint rather than shipped:
        // shipping it would put GPL-3.0 code inside the app.
        assertTrue(script.url.startsWith("https://userscripts.adtidy.org/"))
    }

    @Test
    fun `a script nobody needs by default waits to be asked for`() {
        assertFalse(entry("disable-amp").defaultEnabled)
    }

    @Test
    fun `ids are unique`() {
        val ids = UserScriptCatalog.scripts.map { it.id }
        assertEquals(ids.size, ids.toSet().size)
    }
}
