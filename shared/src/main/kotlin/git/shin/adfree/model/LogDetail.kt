package git.shin.adfree.model

/**
 * Something the detail panel can switch off and back on for one request.
 *
 * AdGuard's panel lists every rule that spoke for the request with a switch on
 * each row. Only two kinds of switch can be honored here: a rule the user wrote,
 * which parks behind AdGuard's own `!` mark, and the subscription a list rule
 * came from, which switches as a whole. A single rule inside a downloaded body
 * is not editable — offering a switch for it would write a control that changes
 * nothing, so the panel shows that rule as text instead.
 */
enum class LogRuleSwitchKind {
    USER_RULE,
    FILTER_LIST,
}

data class LogRuleSwitch(
    val kind: LogRuleSwitchKind,
    /** The line the user reads: the rule text, or the list it came from. */
    val label: String,
    /** What the switch acts on: the stored rule text, or the filter list id. */
    val target: String,
    val enabled: Boolean,
    /** The rule that fired, when the switch is the whole list that owns it. */
    val rule: String? = null,
)

/**
 * The rules that speak for this request, the applied one first.
 *
 * The core reports the owning list by the same name the repository pushed, so a
 * row can be traced back to the switch that turns it off. When no list answers
 * (a rule from a body that has since been removed, or the built-in security
 * list) the rule keeps its place in the panel as text and gets no switch.
 */
fun logRuleSwitches(log: NetworkRequestLog, filterLists: List<FilterList>): List<LogRuleSwitch> {
    val custom = filterLists.firstOrNull { it.isCustom }?.customRules.orEmpty()
    val host = log.domain.trim().trimEnd('.').lowercase()
    val switches = mutableListOf<LogRuleSwitch>()

    log.matchedRule?.let { matched ->
        val listName = log.filterListName?.trim()?.lowercase()
        val list = filterLists.firstOrNull {
            !it.isCustom && it.name.trim().lowercase() == listName
        }
        val stored = custom.firstOrNull { allowlistRuleBody(it) == allowlistRuleBody(matched) }
        when {
            list != null -> switches += LogRuleSwitch(
                kind = LogRuleSwitchKind.FILTER_LIST,
                label = list.name,
                target = list.id,
                enabled = list.isEnabled,
                rule = matched,
            )

            stored != null -> switches += userRuleSwitch(stored)
            else -> Unit
        }
    }

    custom.forEach { rule ->
        if (switches.any { it.target == rule }) return@forEach
        if (!ruleSpeaksForHost(allowlistRuleBody(rule), host)) return@forEach
        switches += userRuleSwitch(rule)
    }
    return switches
}

private fun userRuleSwitch(stored: String) = LogRuleSwitch(
    kind = LogRuleSwitchKind.USER_RULE,
    label = stored,
    target = stored,
    enabled = allowlistRuleEnabled(stored),
)

/**
 * True when a rule is about this host: the same name or one of its parents.
 *
 * Only host-anchored rules qualify. A path, cosmetic or wildcard rule cannot be
 * checked against a hostname alone, and a switch that rests on a guess would
 * tell the user a rule was turned off when it may never have applied.
 */
private fun ruleSpeaksForHost(body: String, host: String): Boolean {
    if (host.isEmpty()) return false
    val pattern = body.removePrefix("@@").trim()
    if (!pattern.startsWith("||")) return false
    val ruleHost = pattern.removePrefix("||")
        .substringBefore('^')
        .substringBefore('$')
        .trim()
        .trimEnd('.')
        .lowercase()
    if (ruleHost.isEmpty() || ruleHost.contains('*')) return false
    return host == ruleHost || host.endsWith(".$ruleHost")
}

/**
 * AdGuard's "Open in browser" only appears for a row that really is a web
 * address: a `dns://` or bare-host pseudo-url has nothing for a browser to load.
 */
fun logUrlOpenable(url: String?): Boolean =
    url != null && (url.startsWith("http://", ignoreCase = true) || url.startsWith("https://", ignoreCase = true))

/**
 * How long the engine took, or null when it never measured.
 *
 * Connections that TLS termination handled are logged without a duration; a `0`
 * there would read as an impossibly fast request rather than as no answer, so
 * the row is left out.
 */
fun logDurationLabel(micros: Long): String? = when {
    micros <= 0L -> null
    micros >= 1_000L -> "${"%.1f".format(micros / 1_000.0)} ms"
    else -> "$micros µs"
}
