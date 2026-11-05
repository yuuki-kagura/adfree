package git.shin.adfree.platform

import android.Manifest
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.OpenableColumns
import android.provider.Settings
import android.util.LruCache
import android.widget.Toast
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.core.content.ContextCompat
import git.shin.adfree.model.AppCategory
import git.shin.adfree.model.AppLanguage
import git.shin.adfree.vpn.HttpsReminder
import git.shin.adfree.vpn.PrivateDns
import git.shin.adfree.work.FilterUpdateScheduler
import git.shin.adfree.work.FirewallNotifier
import git.shin.adfree.work.SecurityNotifier
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.util.Locale

/**
 * The Android answer to every [PlatformHost] call: intents, toasts and the
 * device settings screens the moved UI reaches for.
 */
class AndroidPlatformHost(private val context: Context) : PlatformHost {

    /** Set by MainActivity so the prompt goes through its permission launcher. */
    var onNotificationPermission: (() -> Unit)? = null

    override fun toast(text: String) {
        Toast.makeText(context, text, Toast.LENGTH_SHORT).show()
    }

    override fun openUrl(url: String) {
        runCatching {
            context.startActivity(
                Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
        }
    }

    override fun notificationsEnabled(): Boolean =
        context.getSystemService(NotificationManager::class.java)?.areNotificationsEnabled() == true

    override fun openNotificationSettings() {
        val intent = Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
            .putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        runCatching { context.startActivity(intent) }
    }

    override fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        onNotificationPermission?.invoke() ?: openNotificationSettings()
    }

    override fun ignoringBatteryOptimizations(): Boolean {
        // MIUI keeps its own no-restrict list and isIgnoringBatteryOptimizations
        // reports false even after the user picks "Không hạn chế" there.
        val power = context.getSystemService(PowerManager::class.java)
        if (power?.isIgnoringBatteryOptimizations(context.packageName) == true) return true
        val exempt = runCatching {
            Settings.System.getString(context.contentResolver, MIUI_NO_RESTRICT_APPS)
        }.getOrNull().orEmpty()
        return context.packageName in exempt.split(":")
    }

    override fun openBatterySettings() {
        runCatching {
            context.startActivity(
                Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
        }.onFailure {
            runCatching {
                context.startActivity(
                    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                        .setData(Uri.fromParts("package", context.packageName, null))
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                )
            }
        }
    }

    override fun requestIgnoreBatteryOptimizations() {
        // MIUI routes the request straight to its PowerDetailActivity; the
        // stock dialog needs a package-scoped intent the OEM hides.
        runCatching {
            context.startActivity(
                Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
                    .setData(Uri.parse("package:${context.packageName}"))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
        }.onFailure { openBatterySettings() }
    }

    override fun miuiNoRestrictApps(): String? = runCatching {
        Settings.System.getString(context.contentResolver, MIUI_NO_RESTRICT_APPS)
    }.getOrNull()

    override fun privateDnsMode(): DnsPrivacyMode = when (PrivateDns.mode(context)) {
        PrivateDns.Mode.OFF -> DnsPrivacyMode.OFF
        PrivateDns.Mode.AUTOMATIC -> DnsPrivacyMode.AUTOMATIC
        PrivateDns.Mode.STRICT -> DnsPrivacyMode.STRICT
    }

    override fun openPrivateDnsSettings() {
        PrivateDns.openSettings(context)
    }

    override fun openCertificateInstaller() {
        runCatching {
            context.startActivity(
                Intent(Settings.ACTION_SECURITY_SETTINGS)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
        }
    }

    override fun openAppDetails(packageName: String) {
        runCatching {
            context.startActivity(
                Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                    .setData(Uri.fromParts("package", packageName, null))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
        }
    }

    override fun deviceLanguage(): String {
        val locales = context.resources.configuration.locales
        return if (locales.isEmpty) "" else locales[0].language.lowercase(Locale.ROOT)
    }

    override fun packageName(): String = context.packageName

    private companion object {
        const val MIUI_NO_RESTRICT_APPS = "MILLET_NO_RESTRICT_APP"
    }
}

/**
 * SAF behind [FileHost]: pickers are funnels through launchers MainActivity
 * registers once ([openPicker]/[createPicker]); everything else runs straight
 * on the ContentResolver.
 */
class AndroidFileHost(private val context: Context) : FileHost {

    /** Wired by MainActivity; null until then, so picks report cancellation. */
    var openPicker: (suspend () -> String?)? = null
    var createPicker: (suspend (String) -> String?)? = null

    override suspend fun openText(): String? = openPicker?.invoke()

    override suspend fun createDocument(suggestedName: String, mime: String): String? =
        createPicker?.invoke(suggestedName)

    override fun readText(uriText: String): String? = runCatching {
        context.contentResolver.openInputStream(Uri.parse(uriText))
            ?.use { InputStreamReader(it, Charsets.UTF_8).readText() }
    }.getOrNull()

    override fun writeText(uriText: String, text: String): Boolean = runCatching {
        context.contentResolver.openOutputStream(Uri.parse(uriText))
            ?.use { OutputStreamWriter(it, Charsets.UTF_8).use { writer -> writer.write(text) } }
            ?: error("no output stream")
    }.isSuccess

    override fun openWrite(uriText: String): java.io.Writer? = runCatching {
        context.contentResolver.openOutputStream(Uri.parse(uriText))
            ?.let { OutputStreamWriter(it, Charsets.UTF_8).buffered() }
    }.getOrNull()

    override fun displayName(uriText: String): String = runCatching {
        val uri = Uri.parse(uriText)
        context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) {
                val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (index >= 0) cursor.getString(index) else null
            } else null
        }
    }.getOrNull().orEmpty()

    override fun persistRead(uriText: String) {
        runCatching {
            context.contentResolver.takePersistableUriPermission(
                Uri.parse(uriText),
                Intent.FLAG_GRANT_READ_URI_PERMISSION,
            )
        }
    }
}

/** PackageManager behind [AppInventory]; the desktop host has no app catalogue. */
class AndroidAppInventory(private val context: Context) : AppInventory {

    private val iconCache = LruCache<String, ImageBitmap>(64)

    override fun installedApps(): List<InstalledApp> {
        val pm = context.packageManager
        val installed = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0L))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledApplications(0)
        }
        return installed.map { info ->
            InstalledApp(
                packageName = info.packageName,
                label = pm.getApplicationLabel(info).toString(),
                isSystem = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0 &&
                    (info.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0,
                uid = info.uid,
                category = category(info),
            )
        }
    }

    override fun icon(packageName: String): ImageBitmap? {
        synchronized(iconCache) { iconCache.get(packageName) }?.let { return it }
        val drawable = runCatching {
            context.packageManager.getApplicationIcon(packageName)
        }.getOrNull() ?: return null
        val bitmap = decode(drawable).asImageBitmap()
        synchronized(iconCache) { iconCache.put(packageName, bitmap) }
        return bitmap
    }

    private fun decode(drawable: Drawable): Bitmap {
        (drawable as? BitmapDrawable)?.bitmap?.let { return it }
        val width = drawable.intrinsicWidth.coerceAtLeast(1)
        val height = drawable.intrinsicHeight.coerceAtLeast(1)
        return Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888).also { bitmap ->
            val canvas = Canvas(bitmap)
            drawable.setBounds(0, 0, canvas.width, canvas.height)
            drawable.draw(canvas)
        }
    }

    private fun category(info: ApplicationInfo): String {
        // PackageManager has no browser category; without this list the
        // "Browsers" chip could never match anything.
        if (info.packageName in BROWSER_PACKAGES) return AppCategory.BROWSER
        val pm = context.packageManager
        return try {
            val category = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                pm.getApplicationInfo(info.packageName, 0).category
            } else {
                ApplicationInfo.CATEGORY_UNDEFINED
            }
            when (category) {
                ApplicationInfo.CATEGORY_GAME -> AppCategory.GAME
                ApplicationInfo.CATEGORY_SOCIAL -> AppCategory.SOCIAL
                ApplicationInfo.CATEGORY_VIDEO -> AppCategory.VIDEO
                ApplicationInfo.CATEGORY_AUDIO -> AppCategory.AUDIO
                ApplicationInfo.CATEGORY_NEWS -> AppCategory.NEWS
                ApplicationInfo.CATEGORY_MAPS -> AppCategory.MAPS
                ApplicationInfo.CATEGORY_PRODUCTIVITY -> AppCategory.PRODUCTIVITY
                ApplicationInfo.CATEGORY_IMAGE -> AppCategory.IMAGE
                else -> AppCategory.OTHER
            }
        } catch (_: Exception) {
            AppCategory.OTHER
        }
    }

    private companion object {
        /** Known browser packages; Android exposes no browser category. */
        val BROWSER_PACKAGES = setOf(
            "com.android.chrome",
            "com.chrome.beta",
            "com.chrome.dev",
            "com.chrome.canary",
            "org.chromium.chrome",
            "com.google.android.apps.chrome",
            "org.mozilla.firefox",
            "org.mozilla.firefox_beta",
            "org.mozilla.fennec_fdroid",
            "com.brave.browser",
            "com.sec.android.app.sbrowser",
            "com.opera.browser",
            "com.opera.mini.native",
            "com.microsoft.emmx",
            "com.duckduckgo.mobile.android",
            "com.vivaldi.browser",
            "com.kiwibrowser.browser",
            "io.github.ungoogled_software.ungoogled_chromium",
        )
    }
}

/** The real notifications and WorkManager jobs behind [Reminders]. */
class AndroidReminders(private val context: Context) : Reminders {

    override fun syncHttpsReminder(
        language: AppLanguage,
        protectionActive: Boolean,
        caTrusted: Boolean,
    ) {
        HttpsReminder.sync(context, language, protectionActive, caTrusted)
    }

    override fun notifyFirewall(language: AppLanguage, packageName: String, appName: String) {
        FirewallNotifier.notify(context, language, packageName, appName)
    }

    override fun notifySecurity(language: AppLanguage, domain: String, listName: String?) {
        SecurityNotifier.notify(context, language, domain, listName)
    }

    override fun scheduleFilterUpdates(hours: Int) {
        FilterUpdateScheduler.sync(context, hours)
    }
}

/** SharedPreferences behind [KeyValueStore]. */
class AndroidKeyValueStore(
    prefs: SharedPreferences,
) : KeyValueStore {

    private val store = prefs

    override fun getString(key: String): String? = store.getString(key, null)

    override fun putString(key: String, value: String?) {
        store.edit().putString(key, value).apply()
    }

    override fun getBoolean(key: String, default: Boolean): Boolean =
        store.getBoolean(key, default)

    override fun putBoolean(key: String, value: Boolean) {
        store.edit().putBoolean(key, value).apply()
    }
}
