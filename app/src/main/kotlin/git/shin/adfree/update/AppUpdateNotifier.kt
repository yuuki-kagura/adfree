package git.shin.adfree.update

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
 * One low-priority line when a new release is found, on the same updates
 * channel the filter refresh already uses. Tapping it opens the Settings tab,
 * where the version row carries the download and the system installer; the
 * notice itself never downloads anything.
 */
object AppUpdateNotifier {

    private const val CHANNEL_ID = "adfree_updates"

    // 1001 is the ongoing VPN notice, 1002 the start-refused alert, 1003 the
    // certificate reminder and 1004 the filter-refresh line; this gets its own
    // id because a shared one silently replaces the older notification.
    private const val NOTIFICATION_ID = 1005

    fun notify(
        context: Context,
        language: AppLanguage,
        info: UpdateInfo,
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
                ui.getString(R.string.notification_channel_updates),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = ui.getString(R.string.notification_channel_updates_description)
                setShowBadge(false)
            }
            manager.createNotificationChannel(channel)
        }
        val open = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java).apply {
                action = MainActivity.ACTION_OPEN_UPDATE
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or
                    Intent.FLAG_ACTIVITY_CLEAR_TOP or
                    Intent.FLAG_ACTIVITY_SINGLE_TOP
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setContentTitle(ui.getString(R.string.notification_app_update_title, info.version))
            .setContentText(ui.getString(R.string.notification_app_update_text))
            .setStyle(NotificationCompat.BigTextStyle().bigText(info.releaseNotes.take(500)))
            .setSmallIcon(R.drawable.ic_qs_shield)
            .setContentIntent(open)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .build()
        manager.notify(NOTIFICATION_ID, notification)
    }
}
