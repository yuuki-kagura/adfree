package git.shin.adfree.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.graphics.ImageBitmap
import git.shin.adfree.platform.LocalAppInventory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * The package's launcher icon, or null while it loads / when the package is
 * gone. Decoding goes through the platform inventory because binder access
 * only exists on Android; the host caches hits so paging a list stays cheap.
 */
@Composable
fun rememberAppIcon(packageName: String?): ImageBitmap? {
    val inventory = LocalAppInventory.current
    val icon by produceState(null as ImageBitmap?, packageName, inventory) {
        if (!packageName.isNullOrBlank() && inventory != null) {
            value = withContext(Dispatchers.IO) { inventory.icon(packageName) }
        }
    }
    return icon
}
