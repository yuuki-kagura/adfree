package git.shin.adfree.platform

import kotlinx.coroutines.flow.StateFlow

/**
 * The VPN tunnel the protection switch drives. Android backs it with
 * VpnService; the desktop host runs the engine in-process and answers that a
 * tunnel is always up once the core is.
 */
interface TunnelControl {

    /** True while the OS reports the tunnel established. */
    val isVpnActive: StateFlow<Boolean>

    /** Tunnel up per the OS *and* the core: a dispatched start can still fail. */
    fun isTunnelUp(): Boolean

    /** True when the system VPN consent dialog has to be raised first. */
    fun needsConsent(): Boolean

    fun startVpnService()

    fun stopVpnService()

    fun restartVpnService()

    /** The consent dialog answered; unblocks the pending start. */
    fun onPermissionResult(granted: Boolean)

    /** Re-posts or clears the ongoing-VPN status notification. */
    fun refreshStatusNotification()
}
