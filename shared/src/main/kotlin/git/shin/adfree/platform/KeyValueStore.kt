package git.shin.adfree.platform

/**
 * A tiny key/value persistence seam. Android backs it with SharedPreferences,
 * the desktop host with a properties file.
 */
interface KeyValueStore {

    fun getString(key: String): String?

    fun putString(key: String, value: String?)

    fun getBoolean(key: String, default: Boolean): Boolean

    fun putBoolean(key: String, value: Boolean)
}
