package git.shin.adfree.work

import android.content.Context
import android.os.PowerManager
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import git.shin.adfree.AdGuardApplication
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Refreshes subscriptions that are older than the configured interval.
 *
 * The Repository already serialises refreshes, so a worker racing a
 * foreground check simply returns without doing anything. A failed download
 * is not retried here: the next periodic run picks it up, and retrying a dead
 * URL in a tight loop would only drain the battery.
 */
class FilterUpdateWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val app = applicationContext as? AdGuardApplication ?: return Result.success()
        // Nothing is checked with the screen off, filters and app release both.
        // WorkManager opens the window even during Doze; the pass is simply
        // skipped here, and the screen-on hook picks the same work up when the
        // user is back with the phone.
        val power = applicationContext.getSystemService(PowerManager::class.java)
        if (power != null && !power.isInteractive) return Result.success()
        val repository = app.container.repository
        val updated = withContext(Dispatchers.IO) {
            runCatching { repository.backgroundUpdateStaleLists() }.getOrDefault(0)
        }
        if (updated > 0) {
            FilterUpdateNotifier.notify(
                applicationContext,
                repository.settings.value.appLanguage,
                updated,
            )
        }
        // The app release check rides this same pass: same schedule, same
        // enable switch, same screen-on rule.
        app.container.appUpdate.autoCheck()
        return Result.success()
    }
}
