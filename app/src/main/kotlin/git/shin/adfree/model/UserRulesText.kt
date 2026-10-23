package git.shin.adfree.model

/**
 * Cleans a user-rules file before it reaches the core.
 *
 * AdGuard comments start with `!`; hosts files use `#`. A leading `#` is only
 * kept when it is part of a cosmetic marker (`##`, `#%#`, `#@#`, `#$#`, `#?#`)
 * so a global cosmetic rule survives while a hosts-style comment does not.
 * Blank lines and duplicates are dropped, and order is preserved.
 */
fun parseUserRulesText(text: String): List<String> =
    text.removePrefix("\uFEFF")
        .lineSequence()
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .filterNot { isCommentLine(it) }
        .distinct()
        .toList()

private fun isCommentLine(line: String): Boolean {
    if (line.startsWith("!")) return true
    if (!line.startsWith("#")) return false
    // "# comment" and "#comment" are hosts comments; "##.ad" and "#%#..." are
    // cosmetic rules and must survive an import.
    return line.length < 2 || line[1] !in "#%@$?"
}

/**
 * Turns a typed domain (or a complete `@@` exception rule) into an AdGuard
 * exception rule. Returns null for input that cannot be a hostname, so the
 * editor can show an inline error instead of persisting a rule that silently
 * matches nothing.
 */
fun userWhitelistRule(input: String): String? {
    val trimmed = input.trim()
    if (trimmed.isEmpty()) return null
    if (trimmed.startsWith("@@")) {
        return parseUserRulesText(trimmed).firstOrNull()?.takeIf { it.length > 2 }
    }
    val withoutScheme = when {
        trimmed.startsWith("https://", ignoreCase = true) -> trimmed.substring(8)
        trimmed.startsWith("http://", ignoreCase = true) -> trimmed.substring(7)
        else -> trimmed
    }
    val host = withoutScheme
        .substringBefore('/')
        .substringBefore('?')
        .substringBefore('#')
        .trim()
        .trimEnd('.')
        .lowercase()
    if (host.isEmpty()) return null
    // A port, path or wildcard exception is not a bare host. Keep the input
    // grammar narrow: letters, digits, dots, hyphens, underscores and `*`.
    if (!host.matches(Regex("^[a-z0-9*._-]+$"))) return null
    return "@@||$host^"
}
