package git.shin.adfree.model

/**
 * The address the stealth section tells a site the request came through, in the
 * form the core parses.
 *
 * `""` means no mask. A literal comes back with the brackets folded off, so
 * `[2001:db8::1]` and `2001:db8::1` are the same address. `null` means the text
 * is not an address at all: it stays in the field and no header is added, which
 * is what makes typing an address one digit at a time harmless.
 */
fun normalizeMaskIp(raw: String): String? {
    val text = raw.trim().removeSurrounding("[", "]")
    if (text.isEmpty()) return ""
    return text.takeIf(::isIpLiteral)
}
