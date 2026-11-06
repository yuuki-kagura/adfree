package git.shin.adfree.model

/**
 * The log's search box, read the way AdGuard reads it: plain terms match
 * anywhere in a row, and a term can be limited to one half of it.
 *
 * `url:` keeps a term on the request address (and the page it came from),
 * `text:` keeps it on the rule, the list, the app and the request type.
 * Either can be negated with a leading `-`, so `-url:doubleclick` drops the
 * rows that address mentions. Terms are ANDed; a row has to satisfy every one
 * of them.
 */
private enum class SearchField { ANY, URL, TEXT }

private data class SearchTerm(val text: String, val field: SearchField, val negated: Boolean)

/** Whether [log] satisfies every term of [query]; a blank query matches all. */
fun matchesLogSearch(log: NetworkRequestLog, query: String): Boolean =
    parseLogSearch(query).all { term ->
        val haystack = searchHaystack(log, term.field)
        haystack.contains(term.text, ignoreCase = true) != term.negated
    }

private fun parseLogSearch(query: String): List<SearchTerm> =
    query.split(' ', '\t', '\n').mapNotNull { raw ->
        var text = raw
        var negated = false
        if (text.startsWith("-")) {
            negated = true
            text = text.substring(1)
        }
        val field = fieldPrefix(text)?.let { (name, rest) ->
            text = rest
            if (name == "url") SearchField.URL else SearchField.TEXT
        } ?: SearchField.ANY
        if (text.isBlank()) null else SearchTerm(text.trim(), field, negated)
    }

/** `name:` at the head of a term, when the name is one this parser knows. */
private fun fieldPrefix(text: String): Pair<String, String>? {
    val colon = text.indexOf(':')
    if (colon <= 0) return null
    val name = text.substring(0, colon).lowercase()
    if (name != "url" && name != "text") return null
    return name to text.substring(colon + 1)
}

private fun searchHaystack(log: NetworkRequestLog, field: SearchField): String = when (field) {
    SearchField.ANY -> listOfNotNull(
        log.displayName,
        log.source,
        log.matchedRule,
        log.filterListName,
        log.appPackage,
        log.requestType,
        log.dnsAnswer,
    ).joinToString(" ")

    SearchField.URL -> listOfNotNull(log.url, log.domain, log.source).joinToString(" ")

    // The rule and the list are the words a filter author types, the app and
    // the type are the two columns beside them, and the type is matched by the
    // name the core wrote rather than the label the table renders.
    SearchField.TEXT -> listOfNotNull(
        log.matchedRule,
        log.filterListName,
        log.appPackage,
        log.requestType,
    ).joinToString(" ")
}
