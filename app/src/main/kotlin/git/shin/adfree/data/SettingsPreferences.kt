package git.shin.adfree.data

import android.content.Context
import android.util.Log
import git.shin.adfree.model.DnsBlockMode
import git.shin.adfree.model.DnsProvider
import git.shin.adfree.model.ProtectionSettings
import git.shin.adfree.model.ProtocolType
import org.json.JSONArray
import org.json.JSONObject

/** One per-app firewall choice, persisted without the display-only fields. */
data class StoredAppFirewall(
    val packageName: String,
    val cellular: Boolean,
    val wifi: Boolean,
    val filtered: Boolean,
    val screenOff: Boolean,
)

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
    private val store: BlobStore = CoreSettingsBlobStore,
) {

    private val legacy = context.getSharedPreferences("adfree_settings", Context.MODE_PRIVATE)

    /** The saved switches, or null when the app was never configured. */
    fun settings(): ProtectionSettings? {
        val raw = store.get() ?: migrateLegacy() ?: return null
        return parse(raw)
    }

    @Synchronized
    fun save(settings: ProtectionSettings) {
        // Merge into the existing blob: the same row also holds app-firewall
        // overrides and custom DNS providers, and replacing it here would
        // erase them every time a switch changes.
        val json = currentJson() ?: JSONObject()
        writeSettings(json, settings)
        if (!store.set(json.toString())) {
            Log.w(TAG, "core refused the settings blob; retrying on the next change")
        }
    }

    /** Non-default per-app choices; an absent package means all defaults. */
    fun appFirewall(): List<StoredAppFirewall> = decodeArray(KEY_APP_FIREWALL) { obj ->
        StoredAppFirewall(
            packageName = obj.getString("package"),
            cellular = obj.optBoolean("cellular", true),
            wifi = obj.optBoolean("wifi", true),
            filtered = obj.optBoolean("filtered", true),
            screenOff = obj.optBoolean("screenOff", false),
        )
    }

    @Synchronized
    fun saveAppFirewall(rules: List<StoredAppFirewall>) =
        encodeArray(KEY_APP_FIREWALL, rules) { rule ->
            JSONObject()
                .put("package", rule.packageName)
                .put("cellular", rule.cellular)
                .put("wifi", rule.wifi)
                .put("filtered", rule.filtered)
                .put("screenOff", rule.screenOff)
        }

    /** Custom resolvers only; the built-in list is code and is never stored. */
    fun customDnsProviders(): List<DnsProvider> = decodeArray(KEY_DNS_PROVIDERS) { obj ->
        DnsProvider(
            id = obj.getString("id"),
            name = obj.optString("name"),
            address = obj.optString("address"),
            type = ProtocolType.entries
                .firstOrNull { it.name == obj.optString("type") }
                ?: ProtocolType.DNS_UDP,
            description = obj.optString("description"),
            isCustom = true,
            pingMs = obj.optInt("pingMs", 12),
        )
    }

    @Synchronized
    fun saveCustomDnsProviders(providers: List<DnsProvider>) =
        encodeArray(KEY_DNS_PROVIDERS, providers) { provider ->
            JSONObject()
                .put("id", provider.id)
                .put("name", provider.name)
                .put("address", provider.address)
                .put("type", provider.type.name)
                .put("description", provider.description)
                .put("pingMs", provider.pingMs)
        }

    /** A copy of the raw settings object for the backup file. */
    fun backupJson(): JSONObject? = currentJson()?.let { JSONObject(it.toString()) }

    /** Replaces the whole settings blob (switches, app rules, custom DNS). */
    @Synchronized
    fun restoreBackup(settings: JSONObject): Boolean {
        // Validate before touching the store: a malformed settings object must
        // leave the current blob alone.
        runCatching { parse(settings.toString()) }.getOrNull() ?: return false
        return store.set(settings.toString())
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
            isFullEchEnabled =
                json.optBoolean("fullEch", defaults.isFullEchEnabled),
            isFirewallEnabled =
                json.optBoolean("firewall", defaults.isFirewallEnabled),
            isEcoBatteryModeEnabled =
                json.optBoolean("eco", defaults.isEcoBatteryModeEnabled),
            isStealthModeEnabled =
                json.optBoolean("stealth", defaults.isStealthModeEnabled),
            blockQuic = json.optBoolean("blockQuic", defaults.blockQuic),
            blockDoh = json.optBoolean("blockDoh", defaults.blockDoh),
            // Older blobs had one DoH/DoT switch; carry its value over so a
            // user who turned encrypted-DNS blocking off does not get DoT
            // blocked again after the upgrade.
            blockDot = json.optBoolean(
                "blockDot",
                json.optBoolean("blockDoh", defaults.blockDot),
            ),
            filterAutoUpdateHours = json.optInt(
                "filterAutoUpdateHours",
                defaults.filterAutoUpdateHours,
            ).coerceIn(0, 168),
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
            httpsSkipHosts =
                optStringList(json, "httpsSkipHosts") ?: defaults.httpsSkipHosts,
            httpsOnlyHosts =
                optStringList(json, "httpsOnlyHosts") ?: defaults.httpsOnlyHosts,
            httpsOnlyMode =
                json.optBoolean("httpsOnlyMode", defaults.httpsOnlyMode),
        )
    }.getOrNull()

    /** A stored array of strings; `null` when the key was never written. */
    private fun optStringList(json: JSONObject, key: String): List<String>? {
        val array = json.optJSONArray(key) ?: return null
        return (0 until array.length())
            .mapNotNull { array.optString(it).takeIf(String::isNotBlank) }
    }

    private fun writeSettings(json: JSONObject, settings: ProtectionSettings) {
        json
            .put("protection", settings.isProtectionActive)
            .put("adBlocking", settings.isAdBlockingEnabled)
            .put("tracking", settings.isTrackingProtectionEnabled)
            .put("dns", settings.isDnsProtectionEnabled)
            .put("https", settings.isHttpsFilteringEnabled)
            .put("fullEch", settings.isFullEchEnabled)
            .put("firewall", settings.isFirewallEnabled)
            .put("eco", settings.isEcoBatteryModeEnabled)
            .put("stealth", settings.isStealthModeEnabled)
            .put("blockQuic", settings.blockQuic)
            .put("blockDoh", settings.blockDoh)
            .put("blockDot", settings.blockDot)
            .put("filterAutoUpdateHours", settings.filterAutoUpdateHours)
            .put("logAllowed", settings.logAllowedRequests)
            .put("blockMode", settings.blockMode.name)
            .put("stripUtm", settings.stripUtmTracking)
            .put("blockWebRtc", settings.blockWebRtcLeaks)
            .put("disguiseUa", settings.disguiseUserAgent)
            .put("blockCookies", settings.blockThirdPartyCookies)
            .put("dnsProvider", settings.selectedDnsProviderId)
            .put("httpsSkipHosts", JSONArray(settings.httpsSkipHosts))
            .put("httpsOnlyHosts", JSONArray(settings.httpsOnlyHosts))
            .put("httpsOnlyMode", settings.httpsOnlyMode)
    }

    private fun currentJson(): JSONObject? {
        val raw = store.get() ?: migrateLegacy() ?: return null
        return runCatching { JSONObject(raw) }.getOrNull()
    }

    private fun <T> decodeArray(key: String, decode: (JSONObject) -> T): List<T> =
        currentJson()?.optJSONArray(key)?.let { array ->
            runCatching {
                (0 until array.length()).map { decode(array.getJSONObject(it)) }
            }.getOrDefault(emptyList())
        } ?: emptyList()

    private fun <T> encodeArray(key: String, items: List<T>, encode: (T) -> JSONObject) {
        val json = currentJson() ?: JSONObject()
        val array = JSONArray()
        items.forEach { array.put(encode(it)) }
        json.put(key, array)
        if (!store.set(json.toString())) {
            Log.w(TAG, "core refused the settings blob; retrying on the next change")
        }
    }

    private companion object {
        const val TAG = "AdFreePrefs"
        const val KEY_SETTINGS = "protection_settings"
        const val KEY_APP_FIREWALL = "app_firewall"
        const val KEY_DNS_PROVIDERS = "custom_dns_providers"
    }
}
