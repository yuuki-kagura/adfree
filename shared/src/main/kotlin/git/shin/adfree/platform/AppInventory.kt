package git.shin.adfree.platform

import androidx.compose.ui.graphics.ImageBitmap
import git.shin.adfree.model.AppCategory

/** One installed app, already mapped onto the shared [AppCategory] codes. */
data class InstalledApp(
    val packageName: String,
    val label: String,
    val isSystem: Boolean,
    val uid: Int,
    val category: String = AppCategory.OTHER,
)

/**
 * The device's app list and icons. Android reads PackageManager; the desktop
 * host has no app catalogue to offer and returns nothing.
 */
interface AppInventory {

    fun installedApps(): List<InstalledApp>

    /** The launcher icon, null while loading or when unavailable. */
    fun icon(packageName: String): ImageBitmap?
}
