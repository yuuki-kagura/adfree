package git.shin.adfree.data

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import git.shin.adfree.model.DnsBlockMode
import git.shin.adfree.model.ProtectionSettings
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The switches have to survive a restart: the VPN used to come back off and
 * HTTPS filtering forgot the user had ever opted in.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class SettingsPreferencesTest {

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

    private fun prefs() = SettingsPreferences(context, store)

    private fun legacy(raw: String) {
        context.getSharedPreferences("adfree_settings", Context.MODE_PRIVATE)
            .edit().putString("protection_settings", raw).apply()
    }

    private fun legacyRaw(): String? =
        context.getSharedPreferences("adfree_settings", Context.MODE_PRIVATE)
            .getString("protection_settings", null)

    @Test
    fun `a first run has nothing saved`() {
        assertNull("nothing stored yet must stay null", prefs().settings())
    }

    @Test
    fun `every saved switch comes back unchanged`() {
        val saved = ProtectionSettings(
            isProtectionActive = true,
            isAdBlockingEnabled = false,
            isTrackingProtectionEnabled = false,
            isDnsProtectionEnabled = false,
            isHttpsFilteringEnabled = true,
            isFirewallEnabled = false,
            isEcoBatteryModeEnabled = false,
            isStealthModeEnabled = false,
            blockQuic = false,
            blockDoh = false,
            logAllowedRequests = true,
            blockMode = DnsBlockMode.REFUSED,
            stripUtmTracking = false,
            blockWebRtcLeaks = false,
            disguiseUserAgent = true,
            blockThirdPartyCookies = false,
            selectedDnsProviderId = "cloudflare",
        )
        prefs().save(saved)
        // A fresh instance, as after a restart.
        assertEquals(saved, prefs().settings())
    }

    @Test
    fun `a switch added after the fact falls back to its default`() {
        // A blob from an older install lacks every key the model grew since.
        store.value = JSONObject().put("protection", true).put("https", true).toString()

        val loaded = prefs().settings()!!
        assertTrue(loaded.isProtectionActive)
        assertTrue(loaded.isHttpsFilteringEnabled)
        val defaults = ProtectionSettings()
        assertEquals(defaults.blockMode, loaded.blockMode)
        assertEquals(defaults.selectedDnsProviderId, loaded.selectedDnsProviderId)
        assertEquals(defaults.isStealthModeEnabled, loaded.isStealthModeEnabled)
    }

    @Test
    fun `a corrupted blob is treated as a first run`() {
        store.value = "{not json"
        assertNull(prefs().settings())
    }

    @Test
    fun `the legacy SharedPreferences blob moves into the store on first read`() {
        val stored = JSONObject().put("protection", true).put("https", true).toString()
        legacy(stored)

        val loaded = prefs().settings()!!
        assertTrue(loaded.isProtectionActive)
        assertTrue(loaded.isHttpsFilteringEnabled)
        assertEquals("the core now owns the blob", stored, store.value)
        assertNull("the legacy copy is dropped once the core accepted it", legacyRaw())
    }

    @Test
    fun `a rejected migration keeps the legacy blob for the next launch`() {
        store.rejectsWrites = true
        val stored = JSONObject().put("protection", true).toString()
        legacy(stored)

        assertTrue(prefs().settings()!!.isProtectionActive)
        assertEquals("still there to retry later", stored, legacyRaw())
        assertNull(store.value)
    }
}
