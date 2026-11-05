package git.shin.adfree.platform

/**
 * Picking and writing user files. Android backs this with SAF document
 * launchers and hands `content://` URIs around as strings; the desktop host
 * answers with real files and hands paths. The UI only ever passes the opaque
 * [uriText] back into these methods.
 */
interface FileHost {

    /** Opens the picker; the picked document's uri, null when cancelled. */
    suspend fun openText(): String?

    /** Opens the save dialog; the created document's uri, null when cancelled. */
    suspend fun createDocument(suggestedName: String, mime: String): String?

    /** Reads a picked document's body, null when it cannot be opened. */
    fun readText(uriText: String): String?

    /** Writes [text] into a document chosen by [createDocument]. */
    fun writeText(uriText: String, text: String): Boolean

    /** The name the document picker shows for [uriText]. */
    fun displayName(uriText: String): String

    /** Keeps read access across restarts (SAF persistable permission; no-op on desktop). */
    fun persistRead(uriText: String)
}
