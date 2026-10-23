package git.shin.adfree.data

import org.json.JSONObject

/** The two blobs a backup carries: settings and the user's filter choices. */
data class BackupPayload(
    val settings: JSONObject,
    val filters: JSONObject,
)

/** Result shown in the Settings snackbar after an export or restore. */
data class BackupResult(val ok: Boolean, val message: String)

/**
 * Envelope for `adfree-backup.json`.
 *
 * The core already persists both blobs as JSON, so a backup is just those two
 * objects plus a format/version header. Keeping the schema here (rather than
 * in the core) means Linux/Windows ports can read the same file without
 * knowing anything about SQLite.
 */
object BackupCodec {

    const val FORMAT = "adfree-backup"
    const val VERSION = 1

    private const val KEY_FORMAT = "format"
    private const val KEY_VERSION = "version"
    private const val KEY_EXPORTED_AT = "exportedAtMs"
    private const val KEY_SETTINGS = "settings"
    private const val KEY_FILTERS = "filters"

    private val FILTER_KEYS = listOf(
        "enabled_catalog_ids",
        "custom_filters",
        "user_rules",
    )

    fun encode(
        settings: JSONObject?,
        filters: JSONObject,
        nowMs: Long = System.currentTimeMillis(),
    ): String = JSONObject()
        .put(KEY_FORMAT, FORMAT)
        .put(KEY_VERSION, VERSION)
        .put(KEY_EXPORTED_AT, nowMs)
        .put(KEY_SETTINGS, settings ?: JSONObject())
        .put(KEY_FILTERS, filters)
        .toString(2)

    /** Null for a foreign file, a future version or a malformed filter key. */
    fun decode(raw: String): BackupPayload? {
        val root = runCatching { JSONObject(raw) }.getOrNull() ?: return null
        if (root.optString(KEY_FORMAT) != FORMAT) return null
        val version = root.optInt(KEY_VERSION, 0)
        if (version !in 1..VERSION) return null

        val settings = if (root.has(KEY_SETTINGS)) {
            root.optJSONObject(KEY_SETTINGS) ?: return null
        } else {
            // A first-run install has no settings blob; restoring it should
            // return every switch to its model default.
            JSONObject()
        }
        val filters = root.optJSONObject(KEY_FILTERS) ?: return null
        for (key in FILTER_KEYS) {
            if (filters.has(key) && filters.optJSONArray(key) == null) return null
        }
        return BackupPayload(settings, filters)
    }
}
