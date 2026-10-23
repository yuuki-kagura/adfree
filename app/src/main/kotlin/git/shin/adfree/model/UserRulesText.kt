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
