package git.shin.adfree.automation

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import git.shin.adfree.AdGuardApplication

/**
 * Tasker-style automation: another app asks for protection on or off.
 *
 * Nothing here happens without the user having turned the feature on in
 * Settings and passed the token that screen shows - an exported receiver is
 * reachable by every installed app, and a broadcast that could switch
 * protection off silently is a worse outcome than no automation at all. The
 * sender must target this package, which is what Tasker's "Send Intent" does
 * with its Target field; an untargeted broadcast with these actions is not
 * delivered to a manifest receiver on Android 8+ anyway.
 */
class AutomationReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context?, intent: Intent?) {
        if (context == null) return
        val action = intent?.action ?: return
        if (action != ACTION_ENABLE && action != ACTION_DISABLE) return
        val app = context.applicationContext as? AdGuardApplication ?: return
        val container = app.container
        if (!container.repository.automation.authorize(intent.getStringExtra(EXTRA_TOKEN))) {
            // Deliberately without the presented value: a partial log of a
            // secret invites partial guesses.
            Log.w(TAG, "ignored $action from an unauthorised broadcast")
            return
        }
        if (action == ACTION_ENABLE) {
            Log.i(TAG, "automation: enabling protection")
            container.repository.toggleProtection(true)
            // Consent cannot be requested from a receiver. The controller
            // records that it is missing and the next launch asks for it,
            // exactly as the boot path does.
            container.vpnController.startVpnService(fromBackground = true)
        } else {
            Log.i(TAG, "automation: disabling protection")
            container.repository.toggleProtection(false)
            container.vpnController.stopVpnService()
        }
    }

    companion object {
        // Its own namespace, not MainActivity.ACTION_ENABLE_PROTECTION: that one
        // is the *activity* action the tile and the notification use, and one
        // string serving two components with different trust levels makes the
        // exported surface unreadable straight from the manifest.
        const val ACTION_ENABLE = "git.shin.adfree.automation.ENABLE_PROTECTION"
        const val ACTION_DISABLE = "git.shin.adfree.automation.DISABLE_PROTECTION"

        /** Extra carrying the token from the Settings row. */
        const val EXTRA_TOKEN = "token"

        private const val TAG = "AutomationReceiver"
    }
}
