package git.shin.adfree.update

import android.content.Context
import android.os.PowerManager
import android.util.Log
import git.shin.adfree.AdGuardApplication
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Owns the app-update question for the whole process: the state the Settings
 * row renders, the once-a-day automatic check, and the download.
 *
 * It rides the automatic filter refresh on purpose — same enable switch, same
 * trigger points, and the same rule that nothing is checked while the screen
 * is off. The check stamp is written *before* the request: a releases API
 * that never answers must cost one request a day, not one per screen-on.
 */
class AppUpdateController(
    context: Context,
) : git.shin.adfree.platform.AppUpdate {
    private val appContext = context.applicationContext
    private val prefs = appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val checker = AppUpdateChecker(appContext)

    private val _state = MutableStateFlow<UpdateUiState>(UpdateUiState.Idle)
    override val state: StateFlow<UpdateUiState> = _state.asStateFlow()

    /** How the last manual check ended; the Settings row reports it as a snackbar. */
    private val _outcomes = MutableSharedFlow<UpdateOutcome>(extraBufferCapacity = 4)
    override val outcomes: SharedFlow<UpdateOutcome> = _outcomes.asSharedFlow()

    // A check in flight, so the screen-on hook and a tap on the Settings row
    // cannot race two requests to the same answer.
    private val inFlight = AtomicBoolean(false)

    // The scope outlives any one ViewModel, the same reason the reader app
    // holds its update state app-wide: the automatic check lands on whatever
    // screen is up, and a view-scoped field would drop it on rotation.
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /** The automatic pass: quiet, gated, and never with the screen off. */
    fun autoCheck() {
        if (!automaticRefreshEnabled()) return
        if (isScreenOff()) return
        if (!dueForAutomaticCheck(
                prefs.getLong(KEY_LAST_CHECK, 0L),
                System.currentTimeMillis(),
                AUTOMATIC_CHECK_INTERVAL_MS,
            )
        ) {
            return
        }
        check(automatic = true)
    }

    /** Somebody tapped the row: report the outcome either way. */
    override fun manualCheck() = check(automatic = false)

    private fun check(automatic: Boolean) {
        if (!inFlight.compareAndSet(false, true)) return
        if (automatic) {
            prefs.edit().putLong(KEY_LAST_CHECK, System.currentTimeMillis()).apply()
        } else {
            _state.value = UpdateUiState.Checking
        }
        scope.launch {
            try {
                checker.checkForUpdate().fold(
                    onSuccess = { applyResult(it, automatic) },
                    onFailure = {
                        _state.value = UpdateUiState.Idle
                        if (!automatic) _outcomes.tryEmit(UpdateOutcome.Failed)
                    },
                )
            } finally {
                inFlight.set(false)
            }
        }
    }

    private fun applyResult(
        result: UpdateCheckResult,
        automatic: Boolean,
    ) {
        when (result) {
            is UpdateCheckResult.UpToDate -> {
                _state.value = UpdateUiState.Idle
                if (!automatic) _outcomes.tryEmit(UpdateOutcome.UpToDate)
            }

            is UpdateCheckResult.Available -> {
                _state.value = UpdateUiState.Available(result.info)
                if (!automatic) {
                    _outcomes.tryEmit(UpdateOutcome.Available)
                } else if (prefs.getString(KEY_NOTIFIED, null) != result.info.version) {
                    // One notification per version. The row in Settings still
                    // offers the update after the notice is waved away; this
                    // only stops the shade from repeating it every day.
                    prefs.edit().putString(KEY_NOTIFIED, result.info.version).apply()
                    val language = AdGuardApplication.instance
                        .container.repository.settings.value.appLanguage
                    AppUpdateNotifier.notify(appContext, language, result.info)
                }
            }
        }
    }

    override fun downloadAndInstall(info: UpdateInfo) {
        if (_state.value is UpdateUiState.Downloading) return
        _state.value = UpdateUiState.Downloading(info, 0)
        scope.launch {
            try {
                checker.downloadAndInstall(info) { progress ->
                    _state.value = UpdateUiState.Downloading(info, progress)
                }
                _state.value = UpdateUiState.Idle
                _outcomes.tryEmit(UpdateOutcome.InstallStarted)
            } catch (cancelled: kotlinx.coroutines.CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                Log.w(TAG, "app update download failed", error)
                _state.value = UpdateUiState.Available(info)
                _outcomes.tryEmit(UpdateOutcome.InstallFailed)
            }
        }
    }

    private fun automaticRefreshEnabled(): Boolean =
        AdGuardApplication.instance.container.repository.settings.value
            .filterAutoUpdateHours > 0

    private fun isScreenOff(): Boolean {
        val power = appContext.getSystemService(PowerManager::class.java) ?: return false
        return !power.isInteractive
    }

    private companion object {
        const val PREFS_NAME = "app_update"
        const val KEY_LAST_CHECK = "last_automatic_check"
        const val KEY_NOTIFIED = "notified_version"
        const val TAG = "AppUpdateController"

        /** A release does not appear and change within a day; one ask a day is enough. */
        const val AUTOMATIC_CHECK_INTERVAL_MS = 24L * 60L * 60L * 1000L
    }
}
