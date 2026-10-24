package git.shin.adfree.vpn

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import git.shin.adfree.core.CoreEngine
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Coordinates the VPN lifecycle plus the consent flow (on/off switch and the
 * pending-permission state).
 *
 * Dropped the `Random.nextLong()` "traffic simulation" from the old version:
 * with no real packets there are no logs, which matches reality.
 */
class VpnController(
    private val context: Context,
    private val coreEngine: CoreEngine,
) {
    private val _isVpnActive = MutableStateFlow(false)
    val isVpnActive: StateFlow<Boolean> = _isVpnActive.asStateFlow()

    private val mainHandler = Handler(Looper.getMainLooper())
    private val restartRunnable = Runnable {
        // A stop-then-start can be cancelled by turning protection off.
        if (coreEngine.wantsStart) startVpnService()
    }

    /** The user flipped the switch in the UI. */
    val wantsStart: StateFlow<Boolean> = coreEngine.wantsVpnStateFlow

    /** Whether VPN consent has been granted (null = not asked yet). */
    private val _permissionGranted = MutableStateFlow<Boolean?>(null)
    val permissionGranted: StateFlow<Boolean?> = _permissionGranted.asStateFlow()

    fun prepareIfNeeded(): Intent? = VpnService.prepare(context)

    fun onPermissionResult(granted: Boolean) {
        _permissionGranted.value = granted
        if (granted && coreEngine.wantsStart) startVpnService()
    }

    fun startVpnService() {
        coreEngine.markWantsStart()
        if (VpnService.prepare(context) != null) {
            _permissionGranted.value = false
            return
        }
        _isVpnActive.value = true
        runCatching {
            context.startService(
                Intent(context, AdGuardVpnService::class.java).apply {
                    action = AdGuardVpnService.ACTION_START_VPN
                },
            )
        }
    }

    fun stopVpnService() {
        coreEngine.markWantsStop()
        _isVpnActive.value = false
        runCatching {
            context.startService(
                Intent(context, AdGuardVpnService::class.java).apply {
                    action = AdGuardVpnService.ACTION_STOP_VPN
                },
            )
        }
    }

    /**
     * Rebuild the tunnel so app exclusions take effect. `wantsStart` stays
     * true, hence the separate stop path: the service must tear down before a
     * fresh `establish()` can pick up the new disallowed-app list.
     */
    fun restartVpnService() {
        if (!_isVpnActive.value) return
        mainHandler.removeCallbacks(restartRunnable)
        _isVpnActive.value = false
        runCatching {
            context.startService(
                Intent(context, AdGuardVpnService::class.java).apply {
                    action = AdGuardVpnService.ACTION_STOP_VPN
                },
            )
        }
        mainHandler.postDelayed(restartRunnable, RESTART_DELAY_MS)
    }

    fun onVpnStarted() {
        _isVpnActive.value = true
        _permissionGranted.value = true
    }

    fun onVpnStopped() {
        _isVpnActive.value = false
    }

    private companion object {
        /** Long enough for `onDestroy` to finish before the next start. */
        const val RESTART_DELAY_MS = 1_500L
    }
}
