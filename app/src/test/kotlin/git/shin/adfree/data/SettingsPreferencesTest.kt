package git.shin.adfree.data

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import git.shin.adfree.model.DnsBlockMode
import git.shin.adfree.model.DnsProvider
import git.shin.adfree.model.ProtectionSettings
import git.shin.adfree.model.ProtocolType
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
            isFullEchEnabled = true,
            isFirewallEnabled = false,
            isEcoBatteryModeEnabled = false,
            isStealthModeEnabled = false,
            blockQuic = false,
            blockDoh = false,
            blockDot = false,
            filterAutoUpdateHours = 6,
            logAllowedRequests = true,
            blockMode = DnsBlockMode.REFUSED,
            stripUtmTracking = false,
            blockWebRtcLeaks = false,
            disguiseUserAgent = true,
            blockThirdPartyCookies = false,
            selectedDnsProviderId = "cloudflare",
            httpsSkipHosts = listOf("bank.example", "*.internal.test"),
            httpsOnlyHosts = listOf("shop.example"),
            httpsOnlyMode = true,
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
        assertEquals(defaults.httpsSkipHosts, loaded.httpsSkipHosts)
        assertEquals(defaults.httpsOnlyHosts, loaded.httpsOnlyHosts)
        assertEquals(defaults.httpsOnlyMode, loaded.httpsOnlyMode)
        assertEquals(
            "auto-update defaults to one day, not off",
            24,
            loaded.filterAutoUpdateHours,
        )
        assertEquals(
            "full ECH is opt-in, an old blob must not turn it on",
            false,
            loaded.isFullEchEnabled,
        )
    }

    @Test
    fun `an old encrypted-dns switch carries over to DoT`() {
        // Blobs written before blockDot existed only had the DoH flag; the two
        // transports share one settings switch, so DoT must inherit it.
        store.value = JSONObject().put("blockDoh", false).toString()
        assertEquals(false, prefs().settings()!!.blockDot)
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

    @Test
    fun `firewall overrides and custom dns survive a settings write`() {
        val first = prefs()
        first.saveAppFirewall(
            listOf(StoredAppFirewall("com.example.browser", false, true, false, true)),
        )
        first.saveCustomDnsProviders(
            listOf(
                DnsProvider(
                    id = "custom_1",
                    name = "My resolver",
                    address = "1.2.3.4",
                    type = ProtocolType.DNS_UDP,
                    description = "Tùy chỉnh",
                    isCustom = true,
                ),
            ),
        )
        // The settings collector writes after a switch changes; it must merge
        // into the same blob instead of dropping the two arrays above.
        first.save(ProtectionSettings(isAdBlockingEnabled = false))

        val second = prefs()
        assertEquals(false, second.settings()!!.isAdBlockingEnabled)
        assertEquals(
            listOf(StoredAppFirewall("com.example.browser", false, true, false, true)),
            second.appFirewall(),
        )
        assertEquals("My resolver", second.customDnsProviders().single().name)
        assertEquals("1.2.3.4", second.customDnsProviders().single().address)
    }

    @Test
    fun `backup restores switches, firewall and custom dns together`() {
        val first = prefs()
        first.save(
            ProtectionSettings(
                isAdBlockingEnabled = false,
                selectedDnsProviderId = "custom_1",
            ),
        )
        first.saveAppFirewall(
            listOf(StoredAppFirewall("com.example.browser", false, true, false, true)),
        )
        first.saveCustomDnsProviders(
            listOf(
                DnsProvider(
                    id = "custom_1",
                    name = "Backup resolver",
                    address = "1.2.3.4",
                    type = ProtocolType.DNS_UDP,
                    description = "Tùy chỉnh",
                    isCustom = true,
                ),
            ),
        )
        val backup = first.backupJson()!!

        // Replace everything with different values.
        first.save(
            ProtectionSettings(
                isAdBlockingEnabled = true,
                selectedDnsProviderId = "cloudflare",
            ),
        )
        first.saveAppFirewall(emptyList())
        first.saveCustomDnsProviders(emptyList())

        assertTrue(first.restoreBackup(backup))
        assertEquals(false, first.settings()!!.isAdBlockingEnabled)
        assertEquals("custom_1", first.settings()!!.selectedDnsProviderId)
        assertEquals(1, first.appFirewall().size)
        assertEquals("Backup resolver", first.customDnsProviders().single().name)
    }

    @Test
    fun `a rejected settings restore does not overwrite the blob`() {
        prefs().save(ProtectionSettings(isAdBlockingEnabled = false))
        val backup = prefs().backupJson()!!
        val before = store.value
        store.rejectsWrites = true

        assertFalse(prefs().restoreBackup(backup))
        assertEquals(before, store.value)
    }
}
