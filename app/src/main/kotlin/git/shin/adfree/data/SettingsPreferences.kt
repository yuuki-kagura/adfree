package git.shin.adfree.data

import android.content.Context
import android.util.Log
import git.shin.adfree.model.DnsBlockMode
import git.shin.adfree.model.ProtectionSettings
import org.json.JSONObject

/** Where the settings blob is persisted; the Rust core owns the real one. */
interface SettingsBlobStore {
    fun get(): String?
    fun set(json: String): Boolean
}

/** The blob as stored by the core, in its SQLite database. */
object CoreSettingsBlobStore : SettingsBlobStore {
    override fun get(): String? =
        runCatching { git.shin.adfree.core.coreSettingsGet() }.getOrNull()

    override fun set(json: String): Boolean =
        runCatching { git.shin.adfree.core.coreSettingsSet(json) }.getOrDefault(false)
}

/**
 * The protection switches, kept across launches.
 *
 * Leaving them in memory turned the app into a blocker that had to be re-armed
 * by hand on every launch: the VPN came back off, and HTTPS filtering forgot
 * the user had ever opted in. One JSON blob covers the whole settings model;
 * a key that is absent (an older install, a switch added later) falls back to
 * the model default, so adding a switch never invalidates what was saved.
 *
 * The blob itself lives in the core's database — this class only owns the
 * JSON schema. Installs from before the migration kept it in
 * SharedPreferences: the first read hands that copy to the core and drops it,
 * and a core that refuses the write keeps the copy for the next launch.
 */
class SettingsPreferences(
    context: Context,
    private val store: SettingsBlobStore = CoreSettingsBlobStore,
) {

    private val legacy = context.getSharedPreferences("adfree_settings", Context.MODE_PRIVATE)

    /** The saved switches, or null when the app was never configured. */
    fun settings(): ProtectionSettings? {
        val raw = store.get() ?: migrateLegacy() ?: return null
        return parse(raw)
    }

    fun save(settings: ProtectionSettings) {
        if (!store.set(encode(settings))) {
            Log.w(TAG, "core refused the settings blob; retrying on the next change")
        }
    }

    /** Moves a pre-migration blob out of SharedPreferences; null when there is none. */
    private fun migrateLegacy(): String? {
        val raw = legacy.getString(KEY_SETTINGS, null) ?: return null
        if (store.set(raw)) {
            legacy.edit().remove(KEY_SETTINGS).apply()
        }
        // Either way this launch uses the value it read.
        return raw
    }

    private fun parse(raw: String): ProtectionSettings? = runCatching {
        val json = JSONObject(raw)
        val defaults = ProtectionSettings()
        defaults.copy(
            isProtectionActive =
                json.optBoolean("protection", defaults.isProtectionActive),
            isAdBlockingEnabled =
                json.optBoolean("adBlocking", defaults.isAdBlockingEnabled),
            isTrackingProtectionEnabled =
                json.optBoolean("tracking", defaults.isTrackingProtectionEnabled),
            isDnsProtectionEnabled =
                json.optBoolean("dns", defaults.isDnsProtectionEnabled),
            isHttpsFilteringEnabled =
                json.optBoolean("https", defaults.isHttpsFilteringEnabled),
            isFirewallEnabled =
                json.optBoolean("firewall", defaults.isFirewallEnabled),
            isEcoBatteryModeEnabled =
                json.optBoolean("eco", defaults.isEcoBatteryModeEnabled),
            isStealthModeEnabled =
                json.optBoolean("stealth", defaults.isStealthModeEnabled),
            blockQuic = json.optBoolean("blockQuic", defaults.blockQuic),
            blockDoh = json.optBoolean("blockDoh", defaults.blockDoh),
            logAllowedRequests =
                json.optBoolean("logAllowed", defaults.logAllowedRequests),
            blockMode = DnsBlockMode.entries
                .firstOrNull { it.name == json.optString("blockMode") }
                ?: defaults.blockMode,
            stripUtmTracking =
                json.optBoolean("stripUtm", defaults.stripUtmTracking),
            blockWebRtcLeaks =
                json.optBoolean("blockWebRtc", defaults.blockWebRtcLeaks),
            disguiseUserAgent =
                json.optBoolean("disguiseUa", defaults.disguiseUserAgent),
            blockThirdPartyCookies =
                json.optBoolean("blockCookies", defaults.blockThirdPartyCookies),
            selectedDnsProviderId =
                json.optString("dnsProvider", defaults.selectedDnsProviderId),
        )
    }.getOrNull()

    private fun encode(settings: ProtectionSettings): String = JSONObject()
        .put("protection", settings.isProtectionActive)
        .put("adBlocking", settings.isAdBlockingEnabled)
        .put("tracking", settings.isTrackingProtectionEnabled)
        .put("dns", settings.isDnsProtectionEnabled)
        .put("https", settings.isHttpsFilteringEnabled)
        .put("firewall", settings.isFirewallEnabled)
        .put("eco", settings.isEcoBatteryModeEnabled)
        .put("stealth", settings.isStealthModeEnabled)
        .put("blockQuic", settings.blockQuic)
        .put("blockDoh", settings.blockDoh)
        .put("logAllowed", settings.logAllowedRequests)
        .put("blockMode", settings.blockMode.name)
        .put("stripUtm", settings.stripUtmTracking)
        .put("blockWebRtc", settings.blockWebRtcLeaks)
        .put("disguiseUa", settings.disguiseUserAgent)
        .put("blockCookies", settings.blockThirdPartyCookies)
        .put("dnsProvider", settings.selectedDnsProviderId)
        .toString()

    private companion object {
        const val TAG = "AdFreePrefs"
        const val KEY_SETTINGS = "protection_settings"
    }
}
