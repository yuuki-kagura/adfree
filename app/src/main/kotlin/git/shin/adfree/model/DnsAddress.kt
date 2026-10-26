package git.shin.adfree.model

import java.net.InetAddress

/** A resolver endpoint the Rust core can actually send plain DNS/UDP to. */
data class DnsEndpoint(val host: String, val port: Int)

/**
 * Parses `IP`, `IP:port`, `[IPv6]` and `[IPv6]:port`.
 *
 * The core's `core_set_resolver` takes an `IpAddr` and the upstream sends plain
 * UDP. A hostname or an `https://…` URL would be accepted by the old parser,
 * then silently dropped by the core (leaving the previous resolver active), so
 * those forms are rejected here and surfaced as a settings error instead.
 */
fun parseDnsEndpoint(raw: String): DnsEndpoint? {
    val address = raw.trim()
    if (address.isEmpty()) return null
    if (
        address.startsWith("https://", ignoreCase = true) ||
        address.startsWith("http://", ignoreCase = true) ||
        address.startsWith("tls://", ignoreCase = true)
    ) {
        return null
    }

    val host: String
    val portText: String?
    if (address.startsWith("[")) {
        val close = address.indexOf(']')
        if (close < 0) return null
        host = address.substring(1, close)
        val rest = address.substring(close + 1)
        portText = when {
            rest.isEmpty() -> null
            rest.startsWith(":") -> rest.substring(1)
            else -> return null
        }
    } else if (address.count { it == ':' } == 1) {
        host = address.substringBefore(':')
        portText = address.substringAfter(':')
    } else {
        // No port, or an unbracketed IPv6 literal where colons are address
        // separators rather than host/port.
        host = address
        portText = null
    }

    if (!isIpLiteral(host)) return null
    val port = if (portText == null) 53 else portText.toIntOrNull() ?: return null
    if (port !in 1..65535) return null
    return DnsEndpoint(host, port)
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
