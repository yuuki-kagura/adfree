package git.shin.adfree.platform

import git.shin.adfree.model.AppLanguage

/** What the OS reports about Private DNS (TLS) enforcement, as Android sees it. */
enum class DnsPrivacyMode { OFF, AUTOMATIC, STRICT, UNKNOWN }

/**
 * The device screens and prompts the UI reaches for: toasts, URLs, battery
 * and notification settings, the certificate installer. Android implements
 * this with real intents; the desktop host answers with no-ops and honest
 * "unsupported" values.
 */
interface PlatformHost {

    fun toast(text: String)

    fun openUrl(url: String)

    fun notificationsEnabled(): Boolean

    fun openNotificationSettings()

    /** Asks the OS for the notification permission (Android 13+; no-op else). */
    fun requestNotificationPermission()

    fun ignoringBatteryOptimizations(): Boolean

    fun openBatterySettings()

    fun requestIgnoreBatteryOptimizations()

    /** The MIUI battery whitelist entry for this app, null off MIUI. */
    fun miuiNoRestrictApps(): String?

    fun privateDnsMode(): DnsPrivacyMode

    fun openPrivateDnsSettings()

    /** Walks the user to the OS screen that installs a CA certificate. */
    fun openCertificateInstaller()

    fun openAppDetails(packageName: String)

    /** The device locale tag, e.g. "en" or "vi". */
    fun deviceLanguage(): String

    /** This app's package id, used by settings deep links. */
    fun packageName(): String
}

/** Kept separate from [PlatformHost] so a desktop host can reuse the parts it can honour. */
fun interface LogSink {
    fun line(line: String)
}
