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
 * One low-priority line after a background refresh. The notification opens the
 * Filters tab, so the result is actionable instead of just informational.
 */
object FilterUpdateNotifier {

    private const val CHANNEL_ID = "adfree_updates"

    // Ids are process-wide, not per channel: 1002 belongs to the start-refused
    // alert on the conflicts channel, so posting the refresh line under it
    // would silently replace that one. 1004 is free; 1005 is the app-update
    // notice in the update package.
    private const val NOTIFICATION_ID = 1004

    fun notify(context: Context, language: AppLanguage, updated: Int) {
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
                action = MainActivity.ACTION_OPEN_FILTERS
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or
                    Intent.FLAG_ACTIVITY_CLEAR_TOP or
                    Intent.FLAG_ACTIVITY_SINGLE_TOP
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setContentTitle(ui.getString(R.string.notification_filter_update_title))
            .setContentText(ui.getString(R.string.notification_filter_update_text, updated))
            .setSmallIcon(R.drawable.ic_qs_shield)
            .setContentIntent(open)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .build()
        manager.notify(NOTIFICATION_ID, notification)
    }
}
