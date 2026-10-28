package git.shin.adfree.vpn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.service.quicksettings.TileService
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import git.shin.adfree.AdGuardApplication
import git.shin.adfree.MainActivity
import git.shin.adfree.R
import git.shin.adfree.core.CoreEngine
import git.shin.adfree.ui.Localization
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
        refreshTile()
    }

    /**
     * [fromBackground] is for boot and Quick Settings starts: Android requires
     * `startForegroundService` there, and the service promotes its
     * notification before doing any binder work.
     */
    fun startVpnService(fromBackground: Boolean = false) {
        coreEngine.markWantsStart()
        if (VpnService.prepare(context) != null) {
            _permissionGranted.value = false
            refreshTile()
            return
        }
        _isVpnActive.value = true
        val intent = Intent(context, AdGuardVpnService::class.java).apply {
            action = AdGuardVpnService.ACTION_START_VPN
        }
        runCatching {
            if (fromBackground) {
                ContextCompat.startForegroundService(context, intent)
            } else {
                context.startService(intent)
            }
        }.onFailure { error ->
            // Android 12+ can refuse a foreground start made from the
            // background (`ForegroundServiceStartNotAllowedException`, an
            // IllegalStateException). Nothing is running, so the only useful
            // follow-up is a tap-to-open notification.
            Log.w(TAG, "VPN service start refused", error)
            if (fromBackground) notifyStartRefused()
        }
        refreshTile()
    }

    /**
     * Pauses or resumes filtering while the tunnel stays up. The service owns
     * the notification update; the tile calls this directly.
     */
    fun setPaused(paused: Boolean) {
        coreEngine.setProtectionPaused(paused)
        if (_isVpnActive.value) {
            runCatching {
                context.startService(
                    Intent(context, AdGuardVpnService::class.java).apply {
                        action = if (paused) VpnActions.PAUSE else VpnActions.RESUME
                    },
                )
            }
        }
        refreshTile()
    }

    fun isPaused(): Boolean = coreEngine.isProtectionPaused()

    /**
     * Re-posts the ongoing status notification. A permission granted after the
     * service called `startForeground` did not resurrect the notification the
     * system dropped, so the UI asks for a fresh one.
     */
    fun refreshStatusNotification() {
        if (!_isVpnActive.value) return
        runCatching {
            context.startService(
                Intent(context, AdGuardVpnService::class.java).apply {
                    action = AdGuardVpnService.ACTION_REFRESH_NOTIFICATION
                },
            )
        }
    }

    /** The service calls this after it flips the pause flag itself. */
    fun onPauseChanged() = refreshTile()

    private fun notifyStartRefused() {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        val ui = Localization.wrap(
            context,
            AdGuardApplication.instance.container.repository.settings.value.appLanguage,
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(
                    AdGuardVpnService.NOTIFICATION_CHANNEL_ID,
                    ui.getString(R.string.vpn_channel_name),
                    NotificationManager.IMPORTANCE_DEFAULT,
                ).apply {
                    description = ui.getString(R.string.vpn_channel_description)
                },
            )
        }
        val open = PendingIntent.getActivity(
            context,
            3,
            Intent(context, MainActivity::class.java).apply {
                action = MainActivity.ACTION_ENABLE_PROTECTION
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or
                    Intent.FLAG_ACTIVITY_CLEAR_TOP or
                    Intent.FLAG_ACTIVITY_SINGLE_TOP
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notification = NotificationCompat.Builder(
            context,
            AdGuardVpnService.NOTIFICATION_CHANNEL_ID,
        )
            .setContentTitle(ui.getString(R.string.vpn_start_blocked_title))
            .setContentText(ui.getString(R.string.vpn_start_blocked_text))
            .setSmallIcon(R.drawable.ic_qs_shield)
            .setContentIntent(open)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .build()
        runCatching { manager.notify(START_REFUSED_ID, notification) }
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
        refreshTile()
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
        refreshTile()
    }

    fun onVpnStopped() {
        _isVpnActive.value = false
        refreshTile()
    }

    /** Asks the system to redraw the tile without waiting for the shade to open. */
    private fun refreshTile() {
        runCatching {
            TileService.requestListeningState(
                context,
                ComponentName(context, AdFreeTileService::class.java),
            )
        }
    }

    private companion object {
        /** Long enough for `onDestroy` to finish before the next start. */
        const val RESTART_DELAY_MS = 1_500L
        const val TAG = "VpnController"
        const val START_REFUSED_ID = 1002
    }
}
