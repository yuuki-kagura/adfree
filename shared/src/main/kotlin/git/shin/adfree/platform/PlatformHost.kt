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

    // Capabilities: the UI hides what this platform genuinely cannot do
    // instead of offering a control that answers nothing. Defaults keep the
    // Android host (and every existing implementation) unchanged.

    /** A system tunnel (Android's VpnService) can be established here. */
    fun supportsSystemTunnel(): Boolean = true

    /** The OS has notification channels the app can open and post to. */
    fun supportsNotifications(): Boolean = true

    /** The OS has a battery-optimization whitelist to exempt this app from. */
    fun supportsBatteryOptimization(): Boolean = true

    /** The OS can be walked to a screen that installs a CA certificate. */
    fun supportsCertificateInstaller(): Boolean = true

    /** The OS exposes an installed-app catalogue (apps, firewall by app). */
    fun supportsAppCatalogue(): Boolean = true

    /**
     * How traffic reaches the filter when this platform has no system tunnel.
     * Android answers nothing — its VpnService captures the device without
     * the user configuring anything. A desktop names the local listeners and
     * the redirect that puts traffic onto them, so the screen can show the
     * address a browser can be pointed at instead of a switch that promises
     * capture which never happens.
     */
    fun localProxyStatus(): List<Pair<String, String>> = emptyList()

    /**
     * The host can ask the system for the privilege that putting the machine's
     * own traffic onto the filter needs. Android gets it from the VPN consent
     * dialog it already raises, so it leaves this off; a desktop has no tunnel
     * to consent to and would otherwise have to send the user to a terminal.
     */
    fun supportsPrivilegedEngine(): Boolean = false

    /**
     * Restarts the app where it can hold that privilege, then closes this
     * window — the listeners are handed over, not duplicated. Null when the
     * request went through; otherwise what the system said, in its own words,
     * because it is a technical answer rather than a screen message.
     */
    fun requestPrivilegedEngine(): String? = null

    /**
     * The shell draws a window header: the section name, one step back, and
     * the app-wide menu (settings export/import, activity export). A phone
     * gets all three from the system — the status bar, the back gesture and
     * the per-screen app bars — so Android leaves this off; a desktop window
     * has an OS title bar that says nothing about where you are in the app.
     */
    fun supportsWindowHeader(): Boolean = false
}

/** Kept separate from [PlatformHost] so a desktop host can reuse the parts it can honour. */
fun interface LogSink {
    fun line(line: String)
}
