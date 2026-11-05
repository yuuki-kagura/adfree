package git.shin.adfree.platform

import git.shin.adfree.model.AppLanguage
import java.io.Writer
import java.util.Locale

/**
 * The honest "this platform cannot" answers. The desktop host composes these
 * into a real host, and JVM tests use them as-is; none of them throws, none of
 * them pretends a device prompt happened.
 */
class NoopPlatformHost : PlatformHost {

    override fun toast(text: String) = Unit
    override fun openUrl(url: String) = Unit
    override fun notificationsEnabled(): Boolean = false
    override fun openNotificationSettings() = Unit
    override fun requestNotificationPermission() = Unit
    override fun ignoringBatteryOptimizations(): Boolean = false
    override fun openBatterySettings() = Unit
    override fun requestIgnoreBatteryOptimizations() = Unit
    override fun miuiNoRestrictApps(): String? = null
    override fun privateDnsMode(): DnsPrivacyMode = DnsPrivacyMode.UNKNOWN
    override fun openPrivateDnsSettings() = Unit
    override fun openCertificateInstaller() = Unit
    override fun openAppDetails(packageName: String) = Unit
    override fun deviceLanguage(): String = Locale.getDefault().language.lowercase(Locale.ROOT)
    override fun packageName(): String = ""
}

/** No pickers, no documents: every read reports failure, every write declines. */
class NoopFileHost : FileHost {

    override suspend fun openText(): String? = null

    override suspend fun createDocument(suggestedName: String, mime: String): String? = null

    override fun readText(uriText: String): String? = null

    override fun writeText(uriText: String, text: String): Boolean = false

    override fun openWrite(uriText: String): Writer? = null

    override fun displayName(uriText: String): String = ""

    override fun persistRead(uriText: String) = Unit
}

class NoopAppInventory : AppInventory {

    override fun installedApps(): List<InstalledApp> = emptyList()

    override fun icon(packageName: String): androidx.compose.ui.graphics.ImageBitmap? = null
}

class NoopReminders : Reminders {

    override fun syncHttpsReminder(
        language: AppLanguage,
        protectionActive: Boolean,
        caTrusted: Boolean,
    ) = Unit

    override fun notifyFirewall(language: AppLanguage, packageName: String, appName: String) = Unit

    override fun notifySecurity(language: AppLanguage, domain: String, listName: String?) = Unit

    override fun scheduleFilterUpdates(hours: Int) = Unit
}

/** Backed by maps: enough for a test to assert round-trips, gone on restart. */
class InMemoryKeyValueStore : KeyValueStore {

    private val strings = HashMap<String, String>()
    private val booleans = HashMap<String, Boolean>()

    override fun getString(key: String): String? = strings[key]

    override fun putString(key: String, value: String?) {
        if (value == null) strings.remove(key) else strings[key] = value
    }

    override fun getBoolean(key: String, default: Boolean): Boolean = booleans[key] ?: default

    override fun putBoolean(key: String, value: Boolean) {
        booleans[key] = value
    }
}
