package git.shin.adfree.data

/**
 * A JSON blob kept by the core; the platform owns the schema.
 *
 * The core stores each blob in its own SQLite row, so a port only has to hand
 * over a data root — nothing on the platform side persists these.
 */
interface BlobStore {
    fun get(): String?
    fun set(json: String): Boolean
}

/** The protection switches (row 1 in the core's store). */
object CoreSettingsBlobStore : BlobStore {
    override fun get(): String? =
        runCatching { git.shin.adfree.core.coreSettingsGet() }.getOrNull()

    override fun set(json: String): Boolean =
        runCatching { git.shin.adfree.core.coreSettingsSet(json) }.getOrDefault(false)
}

/** The filter and script choices (row 2 in the core's store). */
object CoreFiltersBlobStore : BlobStore {
    override fun get(): String? =
        runCatching { git.shin.adfree.core.coreFiltersGet() }.getOrNull()

    override fun set(json: String): Boolean =
        runCatching { git.shin.adfree.core.coreFiltersSet(json) }.getOrDefault(false)
}
