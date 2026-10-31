package git.shin.adfree.work

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import git.shin.adfree.MainActivity
import git.shin.adfree.R
import git.shin.adfree.model.AppLanguage
import git.shin.adfree.ui.Localization

/**
 * One line when the firewall cuts an app's connection, so a silently blocked
 * app is explainable from the shade. Opening it lands on the Apps tab where
 * the per-app rule can be changed.
 */
object FirewallNotifier {

    private const val CHANNEL_ID = "adfree_firewall"
    private const val NOTIFICATION_BASE_ID = 1003

    fun notify(
        context: Context,
        language: AppLanguage,
        packageName: String,
        appName: String,
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS,
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        val ui = Localization.wrap(context, language)
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                ui.getString(R.string.notification_channel_firewall),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = ui.getString(R.string.notification_channel_firewall_description)
                setShowBadge(false)
            }
            manager.createNotificationChannel(channel)
        }
        val open = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java).apply {
                action = MainActivity.ACTION_OPEN_APPS
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or
                    Intent.FLAG_ACTIVITY_CLEAR_TOP or
                    Intent.FLAG_ACTIVITY_SINGLE_TOP
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setContentTitle(ui.getString(R.string.notification_firewall_title, appName))
            .setContentText(ui.getString(R.string.notification_firewall_text))
            .setSmallIcon(R.drawable.ic_qs_shield)
            .setContentIntent(open)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .build()
        manager.notify(NOTIFICATION_BASE_ID + (packageName.hashCode() and 0xFFFF), notification)
    }
}
