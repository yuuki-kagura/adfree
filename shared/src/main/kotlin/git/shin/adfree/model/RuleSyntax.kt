package git.shin.adfree.model

/**
 * The rule grammar the rule builder offers, and the parser that checks it.
 *
 * AdGuard for Windows lets a rule be assembled instead of typed: pick what it
 * does, give it a pattern, hang modifiers off it, and read the finished line
 * before saving. That only works if the app can say what a half-typed line
 * means, so this file is the single place that reads one — the editor shows
 * its verdict, and the same reading decides whether a rule matches a request
 * in the log.
 *
 * It is deliberately narrower than the core's parser: it accepts what the
 * builder can produce and what the user can reasonably expect to type, and
 * refuses the rest with a reason instead of storing a rule that silently
 * matches nothing.
 */

/** A modifier the builder offers as a switch, with the words the UI shows. */
data class RuleModifier(
    /** The token written into the rule, without `$`. */
    val token: String,
    val labelKey: String,
)

/** Request types a rule can be narrowed to, in the order AdGuard lists them. */
val RULE_TYPE_MODIFIERS: List<RuleModifier> = listOf(
    RuleModifier("document", "rule_type_document"),
    RuleModifier("subdocument", "rule_type_subdocument"),
    RuleModifier("script", "rule_type_script"),
    RuleModifier("stylesheet", "rule_type_stylesheet"),
    RuleModifier("image", "rule_type_image"),
    RuleModifier("xmlhttprequest", "rule_type_xhr"),
    RuleModifier("media", "rule_type_media"),
    RuleModifier("font", "rule_type_font"),
    RuleModifier("websocket", "rule_type_websocket"),
    RuleModifier("other", "rule_type_other"),
)

/** The switches above the type filters: flags that change how a rule applies. */
val RULE_FLAG_MODIFIERS: List<RuleModifier> = listOf(
    RuleModifier("third-party", "rule_flag_third_party"),
    RuleModifier("important", "rule_flag_important"),
    RuleModifier("match-case", "rule_flag_match_case"),
)

/**
 * Every modifier name the core understands, from its option table
 * (`rust/src/filter.rs`). A name outside this set is the mistake a typed rule
 * makes most often, so the builder names it rather than saving it.
 */
private val knownModifiers: Set<String> = setOf(
    "third-party", "3p", "first-party", "1p", "important", "match-case",
    "document", "doc", "subdocument", "frame", "script", "stylesheet", "css",
    "image", "media", "object", "object-subrequest", "xmlhttprequest", "xhr",
    "websocket", "font", "other", "all", "ping", "beacon",
    "app", "domain", "method", "denyallow", "badfilter",
    "removeparam", "queryprune", "replace", "content", "redirect", "redirect-rule",
    "empty", "mp4", "jsinject", "elemhide", "generichide", "genericblock",
    "specifichide", "extension", "popup", "popunder", "stealth", "cookie",
    "header", "jsonprune", "hls", "network", "uritransform", "client",
    "csp", "permissions", "referrerpolicy", "inline-script", "inline-font",
    "rewrite", "urlblock", "shortcut", "webrtc", "websocket",
)

/** How the rule decides: block, or `@@` exception. */
enum class RuleDecision { BLOCK, ALLOW }

/** What a typed or assembled line means, or why it cannot be saved. */
data class ParsedRule(
    val decision: RuleDecision,
    /** The blocking part, with `@@` and the `$options` removed. */
    val pattern: String,
    /** Raw modifier tokens, in the order they were written. */
    val modifiers: List<String>,
    /** True for `##`-style rules, which are not network rules at all. */
    val cosmetic: Boolean = false,
    /** Why the rule cannot be used, or null when it can. */
    val error: RuleError? = null,
) {
    val valid: Boolean get() = error == null

    fun has(token: String): Boolean =
        modifiers.any { it.equals(token, ignoreCase = true) || it.startsWith("$token=", ignoreCase = true) }

    /** `$app=` and `$domain=` leave the pattern alone but narrow where it runs. */
    val appScope: String? get() = valueOf("app")

    val domainScope: String? get() = valueOf("domain")

    fun valueOf(name: String): String? =
        modifiers.firstOrNull { it.startsWith("$name=", ignoreCase = true) }
            ?.substringAfter('=')
            ?.takeIf { it.isNotBlank() }
}

/** Why a line is not a rule the core would use. */
sealed interface RuleError {
    val argument: String get() = ""

    /** Nothing typed, or only whitespace and comments. */
    data object Empty : RuleError

    /** The pattern is not a hostname, a URL or a wildcard pattern. */
    data object Pattern : RuleError

    /** `/…/` that never closes, or closes on nothing. */
    data object Regex : RuleError

    /** A modifier the core does not know. */
    data class UnknownModifier(override val argument: String) : RuleError

    /** A known modifier missing the value it cannot work without. */
    data class MissingValue(override val argument: String) : RuleError

    /** A cosmetic rule, which a network rule editor cannot compose. */
    data object Cosmetic : RuleError
}

/**
 * Reads one line the way the core will, minus the parts that need the request:
 * the pattern, whether it is an exception, and which modifiers ride on it.
 */
fun parseRule(text: String): ParsedRule {
    val raw = text.trim()
    if (raw.isEmpty()) return ParsedRule(RuleDecision.BLOCK, "", emptyList(), error = RuleError.Empty)
    if (raw.startsWith("!") || (raw.startsWith("#") && !isCosmeticRule(raw))) {
        return ParsedRule(RuleDecision.BLOCK, "", emptyList(), error = RuleError.Empty)
    }
    val cosmetic = isCosmeticRule(raw)
    val body = raw.removePrefix("@@")
    val decision = if (raw.startsWith("@@")) RuleDecision.ALLOW else RuleDecision.BLOCK

    if (cosmetic) {
        // A cosmetic rule is legal, it just is not something the builder can
        // assemble: say so, and let the raw editor keep it.
        return ParsedRule(decision, body, emptyList(), cosmetic = true)
    }

    val separator = body.indexOf('$')
    val pattern = (if (separator < 0) body else body.substring(0, separator)).trim()
    val modifiers = if (separator < 0) {
        emptyList()
    } else {
        body.substring(separator + 1).split(',').map { it.trim() }.filter { it.isNotEmpty() }
    }

    val regex = pattern.length >= 2 && pattern.startsWith("/") && pattern.endsWith("/")
    if (pattern.startsWith("/") && !regex) {
        return ParsedRule(decision, pattern, modifiers, error = RuleError.Regex)
    }
    if (regex && pattern.length == 2) {
        return ParsedRule(decision, pattern, modifiers, error = RuleError.Regex)
    }
    if (!regex && !isUsablePattern(pattern)) {
        return ParsedRule(decision, pattern, modifiers, error = RuleError.Pattern)
    }

    modifiers.forEach { token ->
        val negated = token.startsWith("~")
        val bare = if (negated) token.substring(1) else token
        val name = bare.substringBefore('=').lowercase()
        if (name.isEmpty()) return ParsedRule(decision, pattern, modifiers, error = RuleError.UnknownModifier(bare))
        if (name !in knownModifiers) {
            return ParsedRule(decision, pattern, modifiers, error = RuleError.UnknownModifier(name))
        }
        if (needsValue(name) && !bare.contains('=')) {
            return ParsedRule(decision, pattern, modifiers, error = RuleError.MissingValue(name))
        }
        if (bare.contains('=') && bare.substringAfter('=').isBlank()) {
            return ParsedRule(decision, pattern, modifiers, error = RuleError.MissingValue(name))
        }
    }
    return ParsedRule(decision, pattern, modifiers)
}

private fun needsValue(name: String): Boolean = name in setOf(
    "app", "domain", "method", "denyallow", "redirect", "redirect-rule",
    "replace", "csp", "header", "jsonprune", "hls", "uritransform", "removeparam",
    "queryprune", "client", "referrerpolicy", "permissions", "shortcut",
)

private fun isCosmeticRule(line: String): Boolean = Regex("#[#%$@?]").containsMatchIn(line)

/**
 * A pattern is usable when it is a host-shaped thing, a URL, or an explicit
 * AdGuard pattern (`||…^`, `|http…|`, `*`). Anything else — a sentence, a
 * half-typed URL with a space in it — would be stored and never match.
 */
private fun isUsablePattern(pattern: String): Boolean {
    val body = pattern.removePrefix("||").removePrefix("|").removeSuffix("|").removeSuffix("^")
    if (body.isEmpty()) return false
    if (body.any { it.isWhitespace() }) return false
    // AdGuard wildcards and anchors, plus the characters a host or a path has.
    return body.all { c -> c.isLetterOrDigit() || c in "._-*/:?=&%~+@[]" }
}

/**
 * Whether a rule would act on a request, as far as a host, a URL and a type can
 * tell. Exceptions are read like their blocking twins: the question the UI
 * asks ("would this rule see that request?") has the same answer for both.
 */
fun ruleMatchesRequest(
    rule: String,
    host: String,
    url: String? = null,
    requestType: String? = null,
    thirdParty: Boolean? = null,
): Boolean {
    val parsed = parseRule(rule)
    if (!parsed.valid || parsed.cosmetic) return false
    val scope = parsed.domainScope
    if (scope != null) {
        val scoped = scope.contains(host, ignoreCase = true) || host.endsWith("." + scope.trimStart('~'), ignoreCase = true)
        if (!scoped) return false
    }
    val types = parsed.modifiers.filter { it.substringBefore('=').lowercase() in typeNames }
    if (types.isNotEmpty() && requestType != null) {
        val wanted = types.any { it.equals(requestType, ignoreCase = true) || typeAliases(it) == requestType.lowercase() }
        if (!wanted) return false
    }
    if (parsed.has("third-party") && thirdParty != null && !thirdParty) return false
    if (parsed.has("first-party") && thirdParty != null && thirdParty) return false
    return patternMatches(parsed.pattern, host, url)
}

private val typeNames = setOf(
    "document", "doc", "subdocument", "frame", "script", "stylesheet", "css",
    "image", "media", "font", "xmlhttprequest", "xhr", "websocket", "other", "ping", "beacon",
)

private fun typeAliases(token: String): String? = when (token.lowercase()) {
    "doc" -> "document"
    "frame" -> "subdocument"
    "css" -> "stylesheet"
    "xhr" -> "xmlhttprequest"
    "beacon" -> "ping"
    else -> null
}

private fun patternMatches(pattern: String, host: String, url: String?): Boolean {
    val needle = pattern.lowercase()
    if (needle.length > 2 && needle.startsWith("/") && needle.endsWith("/")) {
        val regex = runCatching { Regex(pattern.substring(1, pattern.length - 1)) }.getOrNull() ?: return false
        return candidates(host, url).any { regex.containsMatchIn(it) }
    }
    // `||` anchors at a host name, so it is matched against the host and the
    // host-plus-path; a bare pattern is a plain substring test over the URL.
    val hostAnchored = needle.startsWith("||")
    var body = needle.removePrefix("||")
    val absolute = body.startsWith("|")
    body = body.removePrefix("|").removeSuffix("^").removeSuffix("|")
    if (body.isEmpty()) return false
    val regex = Regex(
        "^" + body.split('*').joinToString(".*") { Regex.escape(it) },
    )
    if (hostAnchored) {
        // `||host^` covers the host and its subdomains, and a pattern that
        // keeps going after the host (`||host/path*`) covers the paths under
        // it — so the match may start one label in.
        val hostBody = body.substringBefore('/')
        val rest = body.removePrefix(hostBody)
        val labelBoundary = hostBody.removePrefix("*")
        val covered = listOf(host.lowercase()) + listOfNotNull(hostPath(host, url))
        return covered.any { candidate ->
            val plain = candidate.removePrefix("www.")
            val atHost = plain == labelBoundary ||
                plain.startsWith("$labelBoundary/") ||
                plain.endsWith(".$labelBoundary") ||
                plain.contains(".$labelBoundary/")
            if (!atHost) return@any false
            if (rest.isEmpty() || rest == "^") return@any true
            val tail = plain.substring(plain.indexOf(labelBoundary) + labelBoundary.length)
            if (tail.isEmpty()) return@any false
            Regex("^" + rest.split('*').joinToString(".*") { Regex.escape(it) }.removeSuffix(".*"))
                .containsMatchIn(tail)
        }
    }
    val haystacks = candidates(host, url)
    return haystacks.any { haystack ->
        val match = regex.find(haystack)
        if (match != null && match.range.first == 0) return@any true
        // An unanchored pattern is a substring test, which is what a rule like
        // `ads/banner` means; an anchored one is not.
        !absolute && !hostAnchored && regex.containsMatchIn(haystack)
    }
}

/** The request as the pattern sees it: the URL without its scheme, or the host. */
private fun hostPath(host: String, url: String?): String? {
    val withoutScheme = url?.substringAfter("://") ?: return null
    return withoutScheme.lowercase().ifEmpty { host.lowercase() }
}

private fun candidates(host: String, url: String?): List<String> = buildList {
    add(host.lowercase())
    hostPath(host, url)?.let { add(it) }
    url?.lowercase()?.let { add(it) }
}.distinct()

/**
 * Assembles the line the builder's controls describe. Options with no value and
 * options with one are written in the order the builder shows them, so two
 * users who pick the same things get the same rule.
 */
fun buildRule(
    decision: RuleDecision,
    pattern: String,
    flags: Set<String> = emptySet(),
    types: Set<String> = emptySet(),
    app: String? = null,
    domainScope: String? = null,
    /** Modifiers the builder has no control for, carried over verbatim. */
    extraTokens: List<String> = emptyList(),
): String {
    val trimmed = pattern.trim()
    val base = when {
        trimmed.isEmpty() -> ""
        trimmed.startsWith("||") || trimmed.startsWith("|") || trimmed.startsWith("/") -> trimmed
        else -> "||" + trimmed.removePrefix("@@").trimStart('|').removeSuffix("^") + "^"
    }
    val tokens = buildList {
        addAll(extraTokens.map { it.trim() }.filter { it.isNotEmpty() })
        addAll(RULE_FLAG_MODIFIERS.map { it.token }.filter { it in flags })
        addAll(RULE_TYPE_MODIFIERS.map { it.token }.filter { it in types })
        app?.trim()?.takeIf { it.isNotEmpty() }?.let { add("app=$it") }
        domainScope?.trim()?.takeIf { it.isNotEmpty() }?.let { add("domain=$it") }
    }
    val body = if (tokens.isEmpty()) base else "$base\$${tokens.joinToString(",")}"
    return if (decision == RuleDecision.ALLOW) "@@$body" else body
}

/** The one-line summary the builder shows above the finished rule. */
fun describeRule(parsed: ParsedRule): RuleDescription {
    val blocked = parsed.decision == RuleDecision.BLOCK
    val types = parsed.modifiers.filter { it.substringBefore('=').lowercase() in typeNames }
    return RuleDescription(
        decision = parsed.decision,
        blocked = blocked,
        pattern = parsed.pattern,
        thirdParty = parsed.has("third-party") || parsed.has("3p"),
        important = parsed.has("important"),
        matchCase = parsed.has("match-case"),
        types = types,
        app = parsed.appScope,
        domainScope = parsed.domainScope,
        cosmetic = parsed.cosmetic,
    )
}

/** What a parsed rule adds up to, for display rather than for matching. */
data class RuleDescription(
    val decision: RuleDecision,
    val blocked: Boolean,
    val pattern: String,
    val thirdParty: Boolean,
    val important: Boolean,
    val matchCase: Boolean,
    val types: List<String>,
    val app: String?,
    val domainScope: String?,
    val cosmetic: Boolean,
)
