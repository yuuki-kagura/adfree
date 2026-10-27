package git.shin.adfree.model

import java.net.InetAddress

/**
 * Outbound SOCKS5 endpoint for TCP flows (routing mode).
 *
 * The host stays an IP literal because the core dials it from the packet loop:
 * resolving a name there would stall every flow. Credentials are optional and
 * only sent when both halves are present (RFC 1929).
 */
data class ProxySettings(
    val enabled: Boolean = false,
    val host: String = "",
    val port: Int = 1080,
    val username: String = "",
    val password: String = "",
) {
    /** Ready to route: a literal address and a real port. */
    val isUsable: Boolean
        get() = normalizeProxyHost(host) != null && port in 1..65535
}

/**
 * The SOCKS5 host the core can dial: an IPv4/IPv6 literal, never a name.
 *
 * Brackets from `[::1]` are stripped so the value is exactly what the core
 * parses. `null` means the text is not an address.
 */
fun normalizeProxyHost(raw: String): String? {
    val host = raw.trim().removeSurrounding("[", "]")
    return host.takeIf(::isIpLiteral)
}

internal fun isIpLiteral(host: String): Boolean {
    val v4 = host.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")) &&
        host.split('.').all { it.toIntOrNull()?.let { octet -> octet in 0..255 } == true }
    if (v4) return true
    if (!host.contains(':')) return false
    if (!host.matches(Regex("^[0-9a-fA-F:.]+$"))) return false
    // Let the platform validate IPv6 compression; a numeric-only host that
    // fails here is malformed, not a name to resolve.
    return runCatching { InetAddress.getByName(host) }.isSuccess
}
