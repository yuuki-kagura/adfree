package git.shin.adfree.vpn

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import git.shin.adfree.AdGuardApplication
import git.shin.adfree.MainActivity
import git.shin.adfree.R
import git.shin.adfree.ui.Localization

/**
 * Quick Settings tile. Tapping it toggles the tunnel without opening the app;
 * when VPN consent is missing it opens the app so the system dialog can be
 * shown (a tile cannot request consent itself).
 */
class AdFreeTileService : TileService() {

    private val container get() = AdGuardApplication.instance.container

    override fun onStartListening() {
        super.onStartListening()
        updateTile()
    }

    override fun onClick() {
        super.onClick()
        if (isLocked) unlockAndRun { toggle() } else toggle()
    }

    private fun toggle() {
        val controller = container.vpnController
        if (controller.isVpnActive.value) {
            container.repository.toggleProtection(false)
            controller.stopVpnService()
            updateTile()
            return
        }
        if (VpnService.prepare(this) == null) {
            container.repository.toggleProtection(true)
            controller.startVpnService(fromBackground = true)
            updateTile()
        } else {
            openForConsent()
        }
    }

    private fun updateTile() {
        val tile = qsTile ?: return
        val active = container.vpnController.isVpnActive.value
        val ui = Localization.wrap(this, container.repository.settings.value.appLanguage)
        tile.state = if (active) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = ui.getString(R.string.app_name)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = ui.getString(
                if (active) R.string.tile_state_on else R.string.tile_state_off,
            )
        }
        tile.updateTile()
    }

    // The PendingIntent overload only exists on API 34+, so pre-34 devices
    // need the Intent call that lint cannot see is SDK-guarded.
    @SuppressLint("StartActivityAndCollapseDeprecated")
    private fun openForConsent() {
        val intent = Intent(this, MainActivity::class.java).apply {
            action = MainActivity.ACTION_ENABLE_PROTECTION
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or
                Intent.FLAG_ACTIVITY_CLEAR_TOP or
                Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startActivityAndCollapse(
                PendingIntent.getActivity(
                    this,
                    0,
                    intent,
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                ),
            )
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }
}
