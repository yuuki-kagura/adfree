package git.shin.adfree.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import git.shin.adfree.AdGuardApplication
import git.shin.adfree.model.shouldStartOnBoot

/**
 * Brings the tunnel back after a reboot (or an app update) when the user left
 * start-on-boot enabled and protection was on.
 *
 * The system broadcast is delivered before any Activity exists, so the
 * Application has already hydrated the persisted settings by the time this
 * runs. VPN consent cannot be requested from a receiver; the controller
 * records the missing consent and the next launch asks for it.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context?, intent: Intent?) {
        if (context == null) return
        val action = intent?.action ?: return
        if (action !in BOOT_ACTIONS) return
        val app = context.applicationContext as? AdGuardApplication ?: return
        val container = app.container
        if (!shouldStartOnBoot(
                autoStart = container.repository.settings.value.autoStart,
                protectionWasOn = container.repository.protectionWasOn(),
            )
        ) {
            return
        }
        Log.i(TAG, "restoring protection after $action")
        container.vpnController.startVpnService(fromBackground = true)
    }

    private companion object {
        const val TAG = "BootReceiver"

        /** AOSP plus the vendor broadcasts some ROMs send instead of boot. */
        val BOOT_ACTIONS = setOf(
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED,
            "android.intent.action.QUICKBOOT_POWERON",
            "com.htc.intent.action.QUICKBOOT_POWERON",
        )
    }
}
