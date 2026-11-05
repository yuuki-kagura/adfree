package git.shin.adfree.work

import git.shin.adfree.l10n.Strings
import git.shin.adfree.l10n.L10n
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

/**
 * One line when a security list refuses a malicious domain, so browsing
 * protection is visible from the shade instead of only in the log.
 *
 * It rides the firewall channel: both are "AdFree stopped something" notices,
 * and a second low-importance channel would only split the user's attention
 * between two shades of the same thing. Tapping opens the log at that domain.
 */
object SecurityNotifier {

    private const val CHANNEL_ID = "adfree_firewall"
    private const val NOTIFICATION_BASE_ID = 2000

    fun notify(
        context: Context,
        language: AppLanguage,
        domain: String,
        listName: String?,
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS,
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                L10n.get(Strings.notification_channel_firewall),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = L10n.get(Strings.notification_channel_firewall_description)
                setShowBadge(false)
            }
            manager.createNotificationChannel(channel)
        }
        val open = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java).apply {
                action = MainActivity.ACTION_OPEN_ACTIVITY
                putExtra(MainActivity.EXTRA_LOG_DOMAIN, domain)
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or
                    Intent.FLAG_ACTIVITY_CLEAR_TOP or
                    Intent.FLAG_ACTIVITY_SINGLE_TOP
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val text = listName?.takeIf { it.isNotBlank() }?.let {
            L10n.format(Strings.notification_security_text_list, it)
        } ?: L10n.get(Strings.notification_security_text)
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setContentTitle(L10n.format(Strings.notification_security_title, domain))
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_qs_shield)
            .setContentIntent(open)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .build()
        manager.notify(NOTIFICATION_BASE_ID + (domain.hashCode() and 0xFFFF), notification)
    }
}
