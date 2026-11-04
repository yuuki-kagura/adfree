package git.shin.adfree.model

/**
 * Reduces what the user typed in an HTTPS website field to the host pattern
 * the core matches against the TLS SNI.
 *
 * The core accepts `example.com`, `*.example.com`, and URLs pasted from a
 * browser (`https://Example.com:443/path` → `example.com`). Doing the same
 * normalization here keeps the stored list clean and lets the dialog show an
 * error before anything is saved. `null` means the text is not a host.
 */
fun normalizeHttpsHost(raw: String): String? {
    var value = raw.trim().lowercase()
    if (value.isEmpty()) return null
    value = value.substringAfter("://", value)
    value = value.substringBefore('/').substringBefore('?').substringBefore('#')
    if (!value.startsWith("[")) {
        val colon = value.lastIndexOf(':')
        val port = if (colon >= 0) value.substring(colon + 1) else ""
        if (colon > 0 && port.isNotEmpty() && port.all { it.isDigit() }) {
            value = value.substring(0, colon)
        }
    }
    value = value.trimEnd('.').trimStart('.')
    if (value.isEmpty() || value.any { it.isWhitespace() }) return null
    // SNI carries punycode for internationalized names; accepting unicode here
    // would store a pattern that can never match.
    if (value.any { it.code >= 128 }) return null
    if (value.any { !(it.isLetterOrDigit() || it == '.' || it == '-' || it == '_' || it == '*' || it == ':') }) {
        return null
    }
    // Punctuation-only input ("...", "*.") is not a host.
    if (value.none { it.isLetterOrDigit() }) return null
    return value
}
