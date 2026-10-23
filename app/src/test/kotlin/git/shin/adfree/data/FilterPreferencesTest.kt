package git.shin.adfree.data

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The choices have to survive a restart, and installs from before the blob
 * migration must keep theirs.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class FilterPreferencesTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    /** In-memory stand-in for the core's SQLite blob. */
    private class FakeStore : BlobStore {
        var value: String? = null
        var rejectsWrites = false

        override fun get(): String? = value

        override fun set(json: String): Boolean {
            if (rejectsWrites) return false
            value = json
            return true
        }
    }

    private val store = FakeStore()

    private fun prefs() = FilterPreferences(context, store)

    private fun legacy(block: android.content.SharedPreferences.Editor.() -> Unit) {
        context.getSharedPreferences("adfree_filters", Context.MODE_PRIVATE)
            .edit().apply(block).apply()
    }

    private fun legacyAll(): Map<String, *> =
        context.getSharedPreferences("adfree_filters", Context.MODE_PRIVATE).all

    @Test
    fun `a first run has no choices saved`() {
        assertNull(prefs().enabledCatalogIds())
        assertNull(prefs().userRules())
        assertEquals(emptyList<StoredFilter>(), prefs().customFilters())
        assertEquals(emptyList<StoredScript>(), prefs().scripts())
        // ON by default: the builtin scripts initialize as enabled, so the
        // master switch falling back to off left rows claiming work that
        // no script was doing.
        assertEquals(true, prefs().scriptsMasterEnabled())
    }

    @Test
    fun `choices come back unchanged`() {
        prefs().saveEnabledCatalogIds(setOf("adguard_base", "easy_list"))
        prefs().saveCustomFilters(
            listOf(StoredFilter("list_1", "My list", "https://x/y.txt", "hosts", true, "https://x"))
        )
        prefs().saveUserRules(listOf("||ads.example.com^", "@@||ok.example.com^"))
        prefs().saveScripts(listOf(StoredScript("s1", "Script", "desc", "https://x/s.js", true)))
        prefs().saveScriptsMasterEnabled(true)

        // A fresh instance, as after a restart.
        val fresh = prefs()
        assertEquals(setOf("adguard_base", "easy_list"), fresh.enabledCatalogIds())
        assertEquals(1, fresh.customFilters().size)
        assertEquals("hosts", fresh.customFilters()[0].format)
        assertEquals(listOf("||ads.example.com^", "@@||ok.example.com^"), fresh.userRules())
        assertEquals("Script", fresh.scripts()[0].name)
        assertTrue(fresh.scriptsMasterEnabled())
    }

    @Test
    fun `writing one key keeps the others`() {
        prefs().saveUserRules(listOf("||a.com^"))
        prefs().saveScripts(listOf(StoredScript("s1", "S", "", "https://x/s.js", true)))
        // Rules were written first and must survive the script write.
        assertEquals(listOf("||a.com^"), prefs().userRules())
        assertEquals(1, prefs().scripts().size)
    }

    @Test
    fun `the legacy SharedPreferences choices move into the store`() {
        legacy {
            putStringSet("enabled_catalog_ids", setOf("adguard_base"))
            putString("custom_filters", JSONArray().put(JSONObject().put("id", "c1").put("enabled", true)).toString())
            putString("user_rules", JSONArray().put(JSONObject().put("rule", "||legacy.example^")).toString())
            putString("userscripts", JSONArray().put(JSONObject().put("id", "s1").put("enabled", true)).toString())
            putBoolean("userscripts_master", true)
        }

        val fresh = prefs()
        assertEquals(setOf("adguard_base"), fresh.enabledCatalogIds())
        assertEquals(listOf("||legacy.example^"), fresh.userRules())
        assertEquals("c1", fresh.customFilters()[0].id)
        assertEquals("s1", fresh.scripts()[0].id)
        assertTrue(fresh.scriptsMasterEnabled())
        assertTrue("the legacy copy is dropped once the core accepted it", legacyAll().isEmpty())
    }

    @Test
    fun `a rejected migration keeps the legacy choices for the next launch`() {
        store.rejectsWrites = true
        legacy { putString("user_rules", JSONArray().put(JSONObject().put("rule", "||a.com^")).toString()) }

        assertEquals(listOf("||a.com^"), prefs().userRules())
        assertTrue("still there to retry later", legacyAll().containsKey("user_rules"))
    }

    @Test
    fun `backup restores filter choices but leaves local scripts alone`() {
        prefs().saveEnabledCatalogIds(setOf("adguard_base"))
        prefs().saveCustomFilters(
            listOf(StoredFilter("list_1", "Backup list", "https://x/y.txt", "hosts", true)),
        )
        prefs().saveUserRules(listOf("||backup.example^"))
        val backup = prefs().backupJson()

        // Change every backed-up key and add a device-local script.
        prefs().saveEnabledCatalogIds(setOf("other"))
        prefs().saveCustomFilters(emptyList())
        prefs().saveUserRules(listOf("||current.example^"))
        prefs().saveScripts(listOf(StoredScript("s1", "Local", "", "", true)))

        assertTrue(prefs().restoreBackup(backup))
        assertEquals(setOf("adguard_base"), prefs().enabledCatalogIds())
        assertEquals("Backup list", prefs().customFilters().single().name)
        assertEquals(listOf("||backup.example^"), prefs().userRules())
        assertEquals("s1", prefs().scripts().single().id)
    }

    @Test
    fun `a backup without filter keys returns the catalogue to defaults`() {
        prefs().saveEnabledCatalogIds(setOf("adguard_base"))
        prefs().saveUserRules(listOf("||a.com^"))

        assertTrue(prefs().restoreBackup(JSONObject()))
        assertNull(prefs().enabledCatalogIds())
        assertNull(prefs().userRules())
    }

    @Test
    fun `a rejected restore leaves the current choices alone`() {
        prefs().saveUserRules(listOf("||keep.example^"))
        val backup = prefs().backupJson()
        store.rejectsWrites = true

        assertFalse(prefs().restoreBackup(backup))
        assertTrue(prefs().userRules() == listOf("||keep.example^"))
    }
}
