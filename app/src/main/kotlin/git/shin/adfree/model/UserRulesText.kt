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
    val host = typedHost(trimmed) ?: return null
    return "@@||$host^"
}

/**
 * Turns a typed domain or URL into a blocking rule. Complete rule syntax is
 * kept verbatim, so cosmetic (`##.ad`) and hosts-style lines still work; a
 * bare host becomes `||host^` instead of a literal that matches nothing.
 */
fun userBlockRule(input: String): String? {
    val trimmed = input.trim()
    if (trimmed.isEmpty()) return null
    if (trimmed.startsWith("@@")) {
        return parseUserRulesText(trimmed).firstOrNull()?.takeIf { it.length > 2 }
    }
    val rule = parseUserRulesText(trimmed).firstOrNull() ?: return null
    if (hasExplicitRuleSyntax(trimmed)) return rule
    // Everything else is a typed host or URL. If it is not a valid ASCII
    // host (a telex keyboard can leave accents behind), reject it instead of
    // persisting a rule that silently matches nothing.
    return typedHost(trimmed)?.let { "||$it^" }
}

/**
 * The exception rules in a user-rules list, narrowed by a search box.
 *
 * Only `@@` lines belong here: a blocking rule shown in an allowlist screen
 * would be deleted by a user who thinks it is an exception, and the screen has
 * no way to tell the two apart afterwards. The query matches against the rule's
 * host as well as its raw text, so `example` finds `@@||example.com^`.
 */
fun allowlistRules(rules: List<String>, query: String): List<String> {
    val exceptions = rules.filter { it.startsWith("@@") }
    val needle = query.trim().lowercase()
    if (needle.isEmpty()) return exceptions
    return exceptions.filter { it.lowercase().contains(needle) || allowlistHost(it).contains(needle) }
}

/** The host an exception rule is about, for display and for search. */
fun allowlistHost(rule: String): String =
    rule.removePrefix("@@")
        .removePrefix("||")
        .substringBefore('^')
        .substringBefore('#')
        .substringBefore('$')
        .trim()
        .lowercase()

private fun hasExplicitRuleSyntax(input: String): Boolean =
    input.startsWith("||") ||
        input.startsWith("/") ||
        input.contains('$') ||
        Regex("#[#%$@?]").containsMatchIn(input) ||
        Regex("""^\d{1,3}(\.\d{1,3}){3}\s+\S+""").containsMatchIn(input)

private fun typedHost(input: String): String? {
    val withoutScheme = when {
        input.startsWith("https://", ignoreCase = true) -> input.substring(8)
        input.startsWith("http://", ignoreCase = true) -> input.substring(7)
        else -> input
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
    return host
}
