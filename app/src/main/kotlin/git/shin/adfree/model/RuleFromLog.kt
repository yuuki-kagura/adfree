package git.shin.adfree.model

enum class RuleDraftKind {
    BLOCK,
    ALLOW,
}

/**
 * A request-detail row turned into the rule the user is about to confirm.
 *
 * [appScopable] is false for DNS lookups: the core attributes a DNS query only
 * after deciding it, so an `$app=` modifier there would be stored and never run.
 */
data class RuleDraft(
    val kind: RuleDraftKind,
    val host: String,
    val appPackage: String?,
    val appScopable: Boolean,
)

private val dnsProtocols = setOf(ProtocolType.DNS_UDP, ProtocolType.DNS_DOT, ProtocolType.DNS_DOH)

fun appScopeSupported(protocol: ProtocolType, appPackage: String?): Boolean =
    !appPackage.isNullOrBlank() && protocol !in dnsProtocols

/** Most specific candidate first, then the same rule one label shorter. */
fun ruleCandidates(kind: RuleDraftKind, host: String): List<String> {
    val clean = host.trim().trimEnd('.').lowercase()
    if (clean.isEmpty()) return emptyList()
    val hosts = buildList {
        add(clean)
        val labels = clean.split('.')
        if (labels.size >= 3) add(labels.drop(1).joinToString("."))
    }
    return hosts.map { candidateFor(kind, it) }
}

private fun candidateFor(kind: RuleDraftKind, host: String): String =
    if (kind == RuleDraftKind.ALLOW) "@@||$host^" else "||$host^"

/**
 * Applies the sheet's option toggles to a rule, keeping any option the user
 * typed themselves. Only the sheet's own `app=` and `important` tokens are
 * rewritten, so editing the text field is never silently discarded.
 */
fun composeRuleText(
    kind: RuleDraftKind,
    base: String,
    appPackage: String?,
    appScoped: Boolean,
    important: Boolean,
): String {
    val trimmed = base.trim()
    if (trimmed.isEmpty() || !optionsEditable(trimmed)) return trimmed
    val separator = trimmed.indexOf('$')
    val pattern = if (separator < 0) trimmed else trimmed.substring(0, separator)
    val kept = if (separator < 0) {
        emptyList()
    } else {
        trimmed.substring(separator + 1)
            .split(',')
            .map { it.trim() }
            .filter { it.isNotEmpty() && it != "important" && !it.startsWith("app=") }
    }
    val options = buildList {
        addAll(kept)
        if (appScoped) appScopeToken(appPackage)?.let { add(it) }
        if (kind == RuleDraftKind.BLOCK && important) add("important")
    }
    return if (options.isEmpty()) {
        pattern
    } else {
        pattern + "\$" + options.joinToString(",")
    }
}

/** Cosmetic and bracket-form rules carry their options elsewhere; leave them alone. */
private fun optionsEditable(rule: String): Boolean =
    !Regex("#[#%$@?]").containsMatchIn(rule) && !rule.startsWith("[")

private fun appScopeToken(appPackage: String?): String? {
    val pkg = appPackage?.trim().orEmpty()
    return if (pkg.isNotEmpty() && !pkg.any { it.isWhitespace() || it == ',' || it == '$' }) {
        "app=$pkg"
    } else {
        null
    }
}
