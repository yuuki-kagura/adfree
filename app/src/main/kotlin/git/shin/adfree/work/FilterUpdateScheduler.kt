package git.shin.adfree.work

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit

/**
 * Keeps the periodic filter refresh in sync with the user's chosen interval.
 *
 * WorkManager owns the schedule so it survives reboots and app updates; the
 * worker itself only downloads lists that are actually due, so changing the
 * interval never forces an early download.
 */
object FilterUpdateScheduler {

    private const val UNIQUE_WORK = "adfree-filter-auto-update"
    private const val TAG = "filter-auto-update"

    /** The unique work period, or null when background refresh is off. */
    internal fun periodicHours(hours: Int): Long? = hours.takeIf { it > 0 }?.toLong()

    fun sync(context: Context, hours: Int) {
        val workManager = WorkManager.getInstance(context)
        val period = periodicHours(hours)
        if (period == null) {
            workManager.cancelUniqueWork(UNIQUE_WORK)
            return
        }
        val request = PeriodicWorkRequestBuilder<FilterUpdateWorker>(
            period,
            TimeUnit.HOURS,
        )
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .setRequiresBatteryNotLow(true)
                    .build(),
            )
            .setBackoffCriteria(BackoffPolicy.LINEAR, 30, TimeUnit.MINUTES)
            .addTag(TAG)
            .build()
        workManager.enqueueUniquePeriodicWork(
            UNIQUE_WORK,
            ExistingPeriodicWorkPolicy.UPDATE,
            request,
        )
    }
}
