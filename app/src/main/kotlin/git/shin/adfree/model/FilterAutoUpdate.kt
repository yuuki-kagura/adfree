package git.shin.adfree.model

/** Default refresh interval, in hours (AdGuard's default is also one day). */
const val DEFAULT_FILTER_AUTO_UPDATE_HOURS = 24

/**
 * Whether a downloaded filter body is old enough to refresh on app launch.
 *
 * A body with no timestamp (never downloaded, or imported from a file) is left
 * alone: the startup path already downloads missing subscriptions, and a local
 * file is not a subscription to refresh. A timestamp in the future (clock skew)
 * is also ignored rather than treated as infinitely old.
 */
fun filterUpdateDue(lastUpdatedMs: Long, nowMs: Long, hours: Int): Boolean {
    if (hours <= 0) return false
    if (lastUpdatedMs <= 0L) return false
    if (lastUpdatedMs >= nowMs) return false
    val interval = hours.toLong() * 60L * 60L * 1000L
    return nowMs - lastUpdatedMs >= interval
}
