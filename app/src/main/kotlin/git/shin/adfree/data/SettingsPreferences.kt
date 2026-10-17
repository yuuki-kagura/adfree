package git.shin.adfree.data

import android.content.Context
import git.shin.adfree.model.DnsBlockMode
import git.shin.adfree.model.ProtectionSettings
import org.json.JSONObject

/**
 * The protection switches, kept across launches.
 *
 * Leaving them in memory turned the app into a blocker that had to be re-armed
 * by hand on every launch: the VPN came back off, and HTTPS filtering forgot
 * the user had ever opted in. One JSON blob covers the whole settings model;
 * a key that is absent (an older install, a switch added later) falls back to
 * the model default, so adding a switch never invalidates what was saved.
 */
class SettingsPreferences(context: Context) {

    private val prefs = context.getSharedPreferences("adfree_settings", Context.MODE_PRIVATE)

    /** The saved switches, or null when the app was never configured. */
    fun settings(): ProtectionSettings? {
        val raw = prefs.getString(KEY_SETTINGS, null) ?: return null
        return runCatching {
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
    }

    fun save(settings: ProtectionSettings) {
        val json = JSONObject()
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
        prefs.edit().putString(KEY_SETTINGS, json.toString()).apply()
    }

    private companion object {
        const val KEY_SETTINGS = "protection_settings"
    }
}
