package git.shin.adfree.data

import android.content.Context
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject

/** Snapshot of a user-added filter list (body lives under `files/filters/`). */
data class StoredFilter(
    val id: String,
    val name: String,
    val url: String,
    val format: String,
    val enabled: Boolean,
    val homepage: String? = null,
    /** The trusted bit (KB §Trusted filters); a custom list starts untrusted. */
    val trusted: Boolean = false,
)

/** Snapshot of a userscript (body lives under `files/scripts/`). */
data class StoredScript(
    val id: String,
    val name: String,
    val description: String,
    val url: String,
    val enabled: Boolean,
)

/**
 * Filter and script choices, kept across launches.
 *
 * Deliberately narrow: the catalogue itself is code, so only the user's
 * deviations are stored — which catalogue entries are on, which custom lists
 * and scripts exist, and the user rules. One small JSON blob covers all of it.
 *
 * The blob lives in the core's database (row 2); installs from before the
 * migration kept the same values as several SharedPreferences keys, which the
 * first read folds into one blob and drops once the core accepted it.
 */
class FilterPreferences(
    context: Context,
    private val store: BlobStore = CoreFiltersBlobStore,
) {

    private val legacy = context.getSharedPreferences("adfree_filters", Context.MODE_PRIVATE)

    /** Null on the first run: the caller falls back to the catalogue defaults. */
    fun enabledCatalogIds(): Set<String>? =
        blob().optJSONArray(KEY_ENABLED)?.let { array ->
            (0 until array.length()).mapNotNull { array.optString(it) }.toSet()
        }

    fun saveEnabledCatalogIds(ids: Set<String>) =
        update { it.put(KEY_ENABLED, JSONArray(ids.toList())) }

    fun customFilters(): List<StoredFilter> = decodeArray(KEY_CUSTOM_FILTERS) { obj ->
        StoredFilter(
            id = obj.getString("id"),
            name = obj.optString("name"),
            url = obj.optString("url"),
            format = obj.optString("format", "standard"),
            enabled = obj.optBoolean("enabled", true),
            homepage = obj.optString("homepage").takeIf { it.isNotBlank() },
            trusted = obj.optBoolean("trusted", false),
        )
    }

    fun saveCustomFilters(filters: List<StoredFilter>) =
        encodeArray(KEY_CUSTOM_FILTERS, filters) { f ->
            JSONObject()
                .put("id", f.id)
                .put("name", f.name)
                .put("url", f.url)
                .put("format", f.format)
                .put("enabled", f.enabled)
                .put("homepage", f.homepage.orEmpty())
                .put("trusted", f.trusted)
        }

    /** Null when nothing was ever saved (starter rules then apply). */
    fun userRules(): List<String>? = decodeArrayOrNull(KEY_USER_RULES) { it.getString("rule") }

    fun saveUserRules(rules: List<String>) =
        encodeArray(KEY_USER_RULES, rules) { rule -> JSONObject().put("rule", rule) }

    fun scripts(): List<StoredScript> = decodeArray(KEY_SCRIPTS) { obj ->
        StoredScript(
            id = obj.getString("id"),
            name = obj.optString("name"),
            description = obj.optString("description"),
            url = obj.optString("url"),
            enabled = obj.optBoolean("enabled", false),
        )
    }

    fun saveScripts(scripts: List<StoredScript>) = encodeArray(KEY_SCRIPTS, scripts) { s ->
        JSONObject()
            .put("id", s.id)
            .put("name", s.name)
            .put("description", s.description)
            .put("url", s.url)
            .put("enabled", s.enabled)
    }

    /**
     * The master switch defaults to ON. The builtin catalogue disagrees
     * otherwise: its scripts initialize as enabled (repository seeds
     * `isEnabled = true`), so a row visibly says "running" while the core
     * gate say off. AdGuard ships with the extensions switch on too.
     */
    fun scriptsMasterEnabled(): Boolean = blob().optBoolean(KEY_SCRIPTS_MASTER, true)

    fun saveScriptsMasterEnabled(enabled: Boolean) = update { it.put(KEY_SCRIPTS_MASTER, enabled) }

    // ------------------------------------------------------------- plumbing

    /** The blob, migrated from SharedPreferences on the first read. */
    private fun blob(): JSONObject {
        store.get()?.let { raw ->
            runCatching { JSONObject(raw) }.getOrNull()?.let { return it }
        }
        return migrateLegacy() ?: JSONObject()
    }

    private fun update(block: (JSONObject) -> Unit) {
        val json = blob()
        block(json)
        if (!store.set(json.toString())) {
            Log.w(TAG, "core refused the filters blob; retrying on the next change")
        }
    }

    private fun <T> decodeArray(key: String, decode: (JSONObject) -> T): List<T> =
        decodeArrayOrNull(key, decode) ?: emptyList()

    private fun <T> decodeArrayOrNull(key: String, decode: (JSONObject) -> T): List<T>? =
        blob().optJSONArray(key)?.let { array ->
            runCatching {
                (0 until array.length()).map { decode(array.getJSONObject(it)) }
            }.getOrDefault(emptyList())
        }

    private fun <T> encodeArray(key: String, items: List<T>, encode: (T) -> JSONObject) {
        val array = JSONArray()
        items.forEach { array.put(encode(it)) }
        update { it.put(key, array) }
    }

    /** One-time move from the old multi-key SharedPreferences layout. */
    private fun migrateLegacy(): JSONObject? {
        if (legacy.all.isEmpty()) return null
        val json = JSONObject()
        legacy.getStringSet(KEY_ENABLED, null)?.let { ids ->
            json.put(KEY_ENABLED, JSONArray(ids.toList()))
        }
        for (key in listOf(KEY_CUSTOM_FILTERS, KEY_USER_RULES, KEY_SCRIPTS)) {
            legacy.getString(key, null)?.let { raw ->
                runCatching { json.put(key, JSONArray(raw)) }
            }
        }
        if (legacy.contains(KEY_SCRIPTS_MASTER)) {
            json.put(KEY_SCRIPTS_MASTER, legacy.getBoolean(KEY_SCRIPTS_MASTER, false))
        }
        // The legacy copy stays when the core refused (store not open yet);
        // either way this launch uses the values it read.
        if (store.set(json.toString())) {
            legacy.edit().clear().apply()
        }
        return json
    }

    private companion object {
        const val TAG = "AdFreeFilters"
        const val KEY_ENABLED = "enabled_catalog_ids"
        const val KEY_CUSTOM_FILTERS = "custom_filters"
        const val KEY_USER_RULES = "user_rules"
        const val KEY_SCRIPTS = "userscripts"
        const val KEY_SCRIPTS_MASTER = "userscripts_master"
    }
}
