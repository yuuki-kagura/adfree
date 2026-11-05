package git.shin.adfree.platform

import git.shin.adfree.update.UpdateOutcome
import git.shin.adfree.update.UpdateUiState
import git.shin.adfree.update.UpdateInfo
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * The OTA updater seam the Settings row renders. Android checks the release
 * feed and installs through the package installer; the desktop host reports
 * versions without installing.
 */
interface AppUpdate {

    val state: StateFlow<UpdateUiState>

    val outcomes: SharedFlow<UpdateOutcome>

    fun manualCheck()

    fun downloadAndInstall(info: UpdateInfo)
}
