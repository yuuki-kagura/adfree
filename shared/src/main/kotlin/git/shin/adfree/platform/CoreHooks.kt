package git.shin.adfree.platform

/**
 * The two core hooks that cannot live in shared code: putting the CA where the
 * OS installer can reach it, and answering whether the OS already trusts it.
 */
fun interface CaExporter {
    /** Copies the PEM where a user can pick it; returns the display name. */
    fun export(pem: String): String?
}

fun interface CaTrustChecker {
    fun isTrusted(pem: String): Boolean
}
