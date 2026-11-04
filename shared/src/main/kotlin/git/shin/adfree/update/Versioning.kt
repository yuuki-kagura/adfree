package git.shin.adfree.update

/**
 * Pure version arithmetic for the OTA check, kept free of Android and network
 * so it is unit-testable on the host.
 */

/** Strips a leading `v` and any prerelease/build suffix, keeping dotted digits. */
public fun normalizeVersion(raw: String): String? {
    val value = raw.trim().removePrefix("v")
    val core = value.substringBefore('-').substringBefore('+')
    if (core.isBlank()) return null
    val parts = core.split('.')
    if (parts.any { it.toIntOrNull() == null }) return null
    return parts.joinToString(".")
}

public fun isNewerVersion(
    latest: String,
    current: String,
): Boolean {
    val latestParts = versionParts(latest) ?: return false
    val currentParts = versionParts(current) ?: return false
    for (index in 0 until maxOf(latestParts.size, currentParts.size)) {
        val left = latestParts.getOrElse(index) { 0 }
        val right = currentParts.getOrElse(index) { 0 }
        if (left != right) return left > right
    }
    return false
}

/**
 * Whether a release tagged [version] should be offered to a build reporting
 * [versionName]. The release bot only bumps the tag when something shipped,
 * so a newer tag is the whole rule here; versionCode is verified again against
 * the downloaded APK before the installer is opened.
 */
public fun shouldOfferUpdate(
    version: String,
    versionName: String,
): Boolean = normalizeVersion(version)?.let { isNewerVersion(it, versionName) } == true

public fun versionParts(version: String): List<Int>? =
    normalizeVersion(version)?.split('.')?.mapNotNull { it.toIntOrNull() }

/**
 * Whether an automatic check is due: never run before, or at least one
 * interval since the last stamp. The stamp is written *before* the request so
 * an unreachable releases API is retried once per interval, not once per
 * screen-on.
 */
public fun dueForAutomaticCheck(
    lastCheckMs: Long,
    nowMs: Long,
    intervalMs: Long,
): Boolean {
    if (lastCheckMs == 0L) return true
    return nowMs - lastCheckMs >= intervalMs
}
