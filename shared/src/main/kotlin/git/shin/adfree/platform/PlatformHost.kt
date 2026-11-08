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
     * The platform raises its own local listeners, so their ports are the
     * user's to move and Settings says where they are. Android's listeners
     * are not configurable — it has none; the tunnel takes the device — so it
     * leaves this off rather than showing two numbers nothing binds.
     */
    fun supportsLocalProxyPorts(): Boolean = false

    /**
     * Restarts the app where it can hold the privilege that putting the
     * machine's own traffic onto the filter needs, then closes this window —
     * the listeners are handed over, not duplicated. Android gets that privilege
     * from the VPN consent dialog it already raises and leaves this alone; a
     * desktop has no tunnel to consent to. Null when the request went through;
     * otherwise what the system said, in its own words, because it is a
     * technical answer rather than a screen message.
     */
    fun requestPrivilegedEngine(): String? = null

    /**
     * The host can put the CA into the *system* trust store through its own
     * elevation prompt. Android leaves this off — it has `su` and reports that
     * through the core's root-trust status; a desktop has neither a
     * terminal-worthy sudo nor an OS certificate screen, and sending the user
     * to one of those is how HTTPS filtering ends up permanently off.
     */
    fun supportsSystemCaInstall(): Boolean = false

    /**
     * Asks the system, in its own words and with its own dialog, to install the
     * application CA. Null when the certificate is in the store now; otherwise
     * the system's answer, including a dismissed dialog.
     */
    fun installSystemCa(): String? = null

    /**
     * The host can also take the CA back out of the system trust store.
     *
     * Separate from [supportsSystemCaInstall] because the two are not the same
     * authority on every platform: a desktop asks polkit for both, while a
     * phone has `su` and reports it through the core's root-trust status.
     */
    fun supportsSystemCaRemoval(): Boolean = false

    /**
     * Asks the system to remove the application CA. Null when it is gone from
     * every store the host owns; otherwise the system's answer.
     */
    fun removeSystemCa(): String? = null

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
