package git.shin.adfree.vpn

/**
 * What the notification and the Quick Settings tile show. Pause is a runtime
 * state only: the persisted protection switch stays on, the tunnel stays up,
 * and the next process resumes filtering.
 */
enum class VpnUiState { OFF, ON, PAUSED }

fun vpnUiState(active: Boolean, paused: Boolean): VpnUiState = when {
    !active -> VpnUiState.OFF
    paused -> VpnUiState.PAUSED
    else -> VpnUiState.ON
}

/**
 * Broadcasts the VPN service understands. The constants live outside the
 * service so JVM tests can assert them without loading an Android class.
 */
object VpnActions {
    const val START = "com.adfree.START_VPN"
    const val STOP = "com.adfree.STOP_VPN"
    const val PAUSE = "com.adfree.PAUSE_VPN"
    const val RESUME = "com.adfree.RESUME_VPN"

    /** Stop from the notification: the stored protection switch goes off. */
    const val DISABLE = "com.adfree.DISABLE_PROTECTION"

    /**
     * Re-post the ongoing notification without touching the tunnel. Needed
     * when POST_NOTIFICATIONS is granted after the service already called
     * `startForeground`: Android dropped that first notification silently.
     */
    const val REFRESH_NOTIFICATION = "com.adfree.REFRESH_NOTIFICATION"
}

/** The pause/resume button the notification shows for [paused]. */
fun vpnToggleAction(paused: Boolean): String =
    if (paused) VpnActions.RESUME else VpnActions.PAUSE

/**
 * Whether the user has to be told protection went away. Both halves are needed:
 * a stop the user asked for has already turned the remembered switch off by the
 * time the service dies, and a reconfigure stop leaves `wasRunning` false before
 * `onDestroy` runs, so neither produces an alert for a tunnel that was meant to
 * come back. A revoke or a system kill leaves the switch on with a live tunnel,
 * and that is the case the user did not choose.
 */
fun shouldReportDroppedProtection(wasRunning: Boolean, protectionExpected: Boolean): Boolean =
    wasRunning && protectionExpected
