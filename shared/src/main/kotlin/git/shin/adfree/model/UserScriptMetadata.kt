package git.shin.adfree.model

/**
 * Header fields of a userscript the UI can explain without running it.
 *
 * The core parses the header itself to decide where a script runs; this is the
 * read-only copy for the detail sheet. Only `@match`, `@include`, `@version`,
 * `@run-at` and `@grant` are kept — enough to answer "what does this touch?"
 * without pretending to re-implement the userscript engine.
 */
data class UserScriptMetadata(
    val version: String = "",
    /** `@match` and `@include` patterns, in header order, duplicates dropped. */
    val patterns: List<String> = emptyList(),
    val grants: List<String> = emptyList(),
    val runAt: String = "",
) {
    /**
     * True when the script asks for APIs that reach outside the page it runs
     * on (cross-origin requests, raw `window`, clipboard). The detail sheet
     * says so in words; AdGuard's install flow warns for the same reason.
     */
    val hasBroadAccess: Boolean
        get() = grants.any { grant ->
            grant != "none" && (
                grant == "unsafeWindow" ||
                    grant.startsWith("GM_xmlhttpRequest") ||
                    grant == "GM_download" ||
                    grant == "GM_setClipboard" ||
                    grant == "GM_openInTab"
                )
        }
}

/**
 * Reads a userscript header. Bodies that are not userscripts (no
 * `==UserScript==` block) yield empty metadata instead of guessing from `//`
 * comments in the code.
 */
fun parseUserScriptMetadata(body: String): UserScriptMetadata {
    if (body.isBlank()) return UserScriptMetadata()

    var version = ""
    var runAt = ""
    val patterns = mutableListOf<String>()
    val grants = mutableListOf<String>()
    var inHeader = false
    var scanned = 0

    for (raw in body.lineSequence()) {
        val line = raw.trim()
        if (!inHeader) {
            // A licence banner may precede the block, but do not scan the whole
            // script: a `// @match` inside code must never be metadata.
            if (line.contains("==UserScript==")) inHeader = true
            if (++scanned > 120) break
            continue
        }
        if (line.contains("==/UserScript==")) break
        if (line.isEmpty()) continue

        val match = HEADER_FIELD.matchEntire(line) ?: continue
        val key = match.groupValues[1].lowercase()
        val value = match.groupValues[2].trim()
        if (value.isEmpty()) continue
        when (key) {
            "version" -> if (version.isEmpty()) version = value
            "run-at" -> if (runAt.isEmpty()) runAt = value
            "match", "include" -> patterns += value
            "grant" -> grants += value
        }
    }

    return UserScriptMetadata(
        version = version,
        patterns = patterns.distinct(),
        grants = grants.distinct(),
        runAt = runAt,
    )
}

/** `// @key value` — the only shape a userscript header field takes. */
private val HEADER_FIELD = Regex("""^//\s*@([A-Za-z][\w-]*)\s+(.+)$""")
