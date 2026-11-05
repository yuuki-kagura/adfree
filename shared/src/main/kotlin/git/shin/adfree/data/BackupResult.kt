package git.shin.adfree.data

import git.shin.adfree.ui.UiText

/** Outcome of a SAF backup export/import, for the snackbar. */
data class BackupResult(val ok: Boolean, val message: UiText)
