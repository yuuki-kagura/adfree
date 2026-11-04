package git.shin.adfree.update

/** Metadata for a signed APK published on the project's GitHub releases page. */
data class UpdateInfo(
    val version: String,
    val releaseNotes: String,
    val downloadUrl: String,
    val assetId: Long,
    val expectedSize: Long,
    val sha256: String,
)

sealed interface UpdateCheckResult {
    data object UpToDate : UpdateCheckResult

    data class Available(
        val info: UpdateInfo,
    ) : UpdateCheckResult
}

sealed interface UpdateUiState {
    data object Idle : UpdateUiState

    data object Checking : UpdateUiState

    data class Available(
        val info: UpdateInfo,
    ) : UpdateUiState

    data class Downloading(
        val info: UpdateInfo,
        val progress: Int,
    ) : UpdateUiState
}

/** How a check or an install ended, for whoever reports it to the user. */
enum class UpdateOutcome {
    UpToDate,
    Available,
    Failed,
    InstallStarted,
    InstallFailed,
}
