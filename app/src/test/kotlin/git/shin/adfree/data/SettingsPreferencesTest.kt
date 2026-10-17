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

    private fun prefs() = SettingsPreferences(context)

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
        val stored = JSONObject().put("protection", true).put("https", true).toString()
        context.getSharedPreferences("adfree_settings", Context.MODE_PRIVATE)
            .edit().putString("protection_settings", stored).apply()

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
        context.getSharedPreferences("adfree_settings", Context.MODE_PRIVATE)
            .edit().putString("protection_settings", "{not json").apply()
        assertNull(prefs().settings())
    }
}
