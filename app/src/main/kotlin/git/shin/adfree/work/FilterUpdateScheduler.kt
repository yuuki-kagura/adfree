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

    fun sync(context: Context, hours: Int) {
        val workManager = WorkManager.getInstance(context)
        if (hours <= 0) {
            workManager.cancelUniqueWork(UNIQUE_WORK)
            return
        }
        val request = PeriodicWorkRequestBuilder<FilterUpdateWorker>(
            hours.toLong(),
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
