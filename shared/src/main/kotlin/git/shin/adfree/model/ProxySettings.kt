package git.shin.adfree.model

import java.net.InetAddress

/**
 * Outbound SOCKS5 endpoint for TCP and UDP flows (routing mode).
 *
 * The host stays an IP literal because the core dials it from the packet loop:
 * resolving a name there would stall every flow. Credentials are optional and
 * only sent when both halves are present (RFC 1929).
 */
data class ProxySettings(
    val enabled: Boolean = false,
    val automatic: Boolean = true,
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
 * Where the desktop's own filtering listeners are raised — AdGuard for Windows'
 * shape: a local HTTP(S) proxy and a local DNS server that the machine's
 * traffic is redirected onto.
 *
 * Both numbers are the user's to move, because a machine that already runs
 * something on them has to be worked around rather than reformatted. Below
 * [MIN_LISTENER_PORT] a bind needs root, and a listener that cannot bind is a
 * filter that quietly relays, so a pair that does not fit is refused rather
 * than clamped behind the user's back.
 *
 * [filterLocalhost] is AdGuard for Windows' "Filter localhost": on, this
 * machine's own conversations are filtered like any other; off, they keep
 * whatever they were talking to — a local dev server, the stub resolver —
 * and the redirect rules step aside for loopback destinations.
 */
data class LocalProxySettings(
    val tcpPort: Int = 3129,
    val dnsPort: Int = 5300,
    val filterLocalhost: Boolean = true,
) {
    /** Two listeners, two numbers, both ours to take. */
    val isUsable: Boolean
        get() = tcpPort in MIN_LISTENER_PORT..MAX_PORT &&
            dnsPort in MIN_LISTENER_PORT..MAX_PORT &&
            tcpPort != dnsPort

    companion object {
        /** Must match `MIN_LISTENER_PORT` in `rust/src/proxy/mod.rs`. */
        const val MIN_LISTENER_PORT = 1024
        const val MAX_PORT = 65535
    }
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

fun isIpLiteral(host: String): Boolean {
    val v4 = host.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")) &&
        host.split('.').all { it.toIntOrNull()?.let { octet -> octet in 0..255 } == true }
    if (v4) return true
    if (!host.contains(':')) return false
    if (!host.matches(Regex("^[0-9a-fA-F:.]+$"))) return false
    // Let the platform validate IPv6 compression; a numeric-only host that
    // fails here is malformed, not a name to resolve.
    return runCatching { InetAddress.getByName(host) }.isSuccess
}
