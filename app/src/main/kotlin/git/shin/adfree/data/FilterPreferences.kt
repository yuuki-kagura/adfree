package git.shin.adfree.data

import android.content.Context
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
 * and scripts exist, and the user rules. Small JSON blobs in
 * SharedPreferences are plenty; nothing here needs a database.
 */
class FilterPreferences(context: Context) {

    private val prefs = context.getSharedPreferences("adfree_filters", Context.MODE_PRIVATE)

    /** Null on the first run: the caller falls back to the catalogue defaults. */
    fun enabledCatalogIds(): Set<String>? =
        if (prefs.contains(KEY_ENABLED)) prefs.getStringSet(KEY_ENABLED, emptySet()).orEmpty() else null

    fun saveEnabledCatalogIds(ids: Set<String>) {
        prefs.edit().putStringSet(KEY_ENABLED, ids).apply()
    }

    fun customFilters(): List<StoredFilter> = decodeArray(KEY_CUSTOM_FILTERS) { obj ->
        StoredFilter(
            id = obj.getString("id"),
            name = obj.optString("name"),
            url = obj.optString("url"),
            format = obj.optString("format", "standard"),
            enabled = obj.optBoolean("enabled", true),
            homepage = obj.optString("homepage").takeIf { it.isNotBlank() },
        )
    }

    fun saveCustomFilters(filters: List<StoredFilter>) = encodeArray(KEY_CUSTOM_FILTERS, filters) { f ->
        JSONObject()
            .put("id", f.id)
            .put("name", f.name)
            .put("url", f.url)
            .put("format", f.format)
            .put("enabled", f.enabled)
            .put("homepage", f.homepage.orEmpty())
    }

    /** Null when nothing was ever saved (starter rules then apply). */
    fun userRules(): List<String>? =
        if (prefs.contains(KEY_USER_RULES)) {
            decodeArray(KEY_USER_RULES) { it.getString("rule") }
        } else {
            null
        }

    fun saveUserRules(rules: List<String>) = encodeArray(KEY_USER_RULES, rules) { rule ->
        JSONObject().put("rule", rule)
    }

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

    fun scriptsMasterEnabled(): Boolean = prefs.getBoolean(KEY_SCRIPTS_MASTER, false)

    fun saveScriptsMasterEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_SCRIPTS_MASTER, enabled).apply()
    }

    // ------------------------------------------------------------- plumbing

    private fun <T> decodeArray(key: String, decode: (JSONObject) -> T): List<T> {
        val raw = prefs.getString(key, null) ?: return emptyList()
        return runCatching {
            val array = JSONArray(raw)
            (0 until array.length()).map { decode(array.getJSONObject(it)) }
        }.getOrDefault(emptyList())
    }

    private fun <T> encodeArray(key: String, items: List<T>, encode: (T) -> JSONObject) {
        val array = JSONArray()
        items.forEach { array.put(encode(it)) }
        prefs.edit().putString(key, array.toString()).apply()
    }

    private companion object {
        const val KEY_ENABLED = "enabled_catalog_ids"
        const val KEY_CUSTOM_FILTERS = "custom_filters"
        const val KEY_USER_RULES = "user_rules"
        const val KEY_SCRIPTS = "userscripts"
        const val KEY_SCRIPTS_MASTER = "userscripts_master"
    }
}
