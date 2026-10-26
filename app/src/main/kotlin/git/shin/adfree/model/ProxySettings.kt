package git.shin.adfree.model

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
