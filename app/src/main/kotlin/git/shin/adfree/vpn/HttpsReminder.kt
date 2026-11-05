package git.shin.adfree.vpn

import git.shin.adfree.l10n.Strings
import git.shin.adfree.l10n.L10n
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import git.shin.adfree.MainActivity
import git.shin.adfree.R
import git.shin.adfree.model.AppLanguage

/**
 * Reminds the user that HTTPS filtering needs the CA in the trust store.
 *
 * AdGuard keeps this up until the certificate is installed; so does this:
 * [sync] posts while protection is active and the CA is missing, and cancels
 * once the store contains it. It is re-evaluated on app resume, screen-on and
 * every settings change, so installing the certificate clears it without
 * opening the HTTPS section.
 */
object HttpsReminder {
    private const val CHANNEL_ID = "adfree_https_reminder"
    private const val NOTIFICATION_ID = 1003

    fun sync(
        context: Context,
        language: AppLanguage,
        protectionActive: Boolean,
        caTrusted: Boolean,
    ) {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        if (!protectionActive || caTrusted) {
            manager.cancel(NOTIFICATION_ID)
            return
        }
        ensureChannel(context, language)
        val open = PendingIntent.getActivity(
            context,
            10,
            Intent(context, MainActivity::class.java).apply {
                action = MainActivity.ACTION_OPEN_PROTECTION
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or
                    Intent.FLAG_ACTIVITY_CLEAR_TOP or
                    Intent.FLAG_ACTIVITY_SINGLE_TOP
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val text = L10n.get(Strings.https_reminder_text)
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_qs_shield)
            .setContentTitle(L10n.get(Strings.https_reminder_title))
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setContentIntent(open)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_REMINDER)
            .setShowWhen(false)
            .build()
        runCatching { manager.notify(NOTIFICATION_ID, notification) }
    }

    private fun ensureChannel(context: Context, language: AppLanguage) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            L10n.get(Strings.https_reminder_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = L10n.get(Strings.https_reminder_channel_description)
            setShowBadge(false)
        }
        context.getSystemService(NotificationManager::class.java)
            ?.createNotificationChannel(channel)
    }
}
