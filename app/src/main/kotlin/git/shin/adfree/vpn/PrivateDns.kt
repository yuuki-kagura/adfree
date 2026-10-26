package git.shin.adfree.vpn

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings

/**
 * Android's Private DNS bypasses the tunnel's resolver: strict mode (DoT to a
 * named provider) sends every lookup straight out, and RSTing port 853 there
 * leaves the device with no resolution at all. The core's DoT switch is
 * therefore only applied while this is off, and the UI says why the filter is
 * weaker instead of letting the tunnel look broken.
 */
object PrivateDns {

    enum class Mode { OFF, AUTOMATIC, STRICT }

    // The Settings constants for these are hidden API; the keys themselves are
    // stable and are what the system UI writes.
    private const val MODE_SETTING = "private_dns_mode"
    private const val SPECIFIER_SETTING = "private_dns_specifier"
    private const val ACTION_SETTINGS = "android.settings.PRIVATE_DNS_SETTINGS"
    private const val ACTION_NETWORK_PROVIDERS = "android.settings.NETWORK_PROVIDER_SETTINGS"

    fun mode(context: Context): Mode {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return Mode.OFF
        val raw = runCatching {
            Settings.Global.getString(context.contentResolver, MODE_SETTING)
        }.getOrNull()
        return when (raw) {
            "hostname" -> Mode.STRICT
            "opportunistic" -> Mode.AUTOMATIC
            else -> Mode.OFF
        }
    }

    fun isEnabled(context: Context): Boolean = mode(context) != Mode.OFF

    /** The setting a running tunnel watches so the DoT policy follows it. */
    val modeUri: Uri
        get() = Settings.Global.getUriFor(MODE_SETTING)

    fun hostname(context: Context): String? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return null
        return runCatching {
            Settings.Global.getString(context.contentResolver, SPECIFIER_SETTING)
        }.getOrNull()?.takeIf { it.isNotBlank() }
    }

    /**
     * Opens the Private DNS page, falling back to Network & internet on builds
     * that do not export the dedicated action (some AOSP images).
     */
    fun openSettings(context: Context) {
        // The dedicated page is not exported everywhere; the provider list it
        // lives under is the next best stop, and Network & internet always
        // exists as the last resort.
        val candidates = listOf(
            ACTION_SETTINGS,
            ACTION_NETWORK_PROVIDERS,
            Settings.ACTION_WIRELESS_SETTINGS,
            Settings.ACTION_SETTINGS,
        )
        for (action in candidates) {
            val intent = Intent(action).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            if (runCatching { context.startActivity(intent) }.isSuccess) return
        }
    }
}
