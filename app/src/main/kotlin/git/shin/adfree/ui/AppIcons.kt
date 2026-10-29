package git.shin.adfree.ui

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.util.LruCache
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Launcher icons are binder work plus a bitmap decode; a log page holds
 * hundreds of rows, so they are loaded off the main thread and kept.
 */
private val appIconCache = LruCache<String, ImageBitmap>(64)

private fun peekAppIcon(packageName: String): ImageBitmap? =
    synchronized(appIconCache) { appIconCache.get(packageName) }

private fun decodeAppIcon(context: Context, packageName: String): ImageBitmap? {
    val drawable = runCatching {
        context.packageManager.getApplicationIcon(packageName)
    }.getOrNull() ?: return null
    val bitmap = drawableToBitmap(drawable).asImageBitmap()
    synchronized(appIconCache) { appIconCache.put(packageName, bitmap) }
    return bitmap
}

private fun drawableToBitmap(drawable: Drawable): Bitmap {
    (drawable as? BitmapDrawable)?.bitmap?.let { return it }
    val width = drawable.intrinsicWidth.coerceAtLeast(1)
    val height = drawable.intrinsicHeight.coerceAtLeast(1)
    return Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888).also { bitmap ->
        val canvas = Canvas(bitmap)
        drawable.setBounds(0, 0, canvas.width, canvas.height)
        drawable.draw(canvas)
    }
}

/**
 * The package's launcher icon, or null while it loads / when the package is
 * gone. A cache hit resolves without a composition round-trip.
 */
@Composable
fun rememberAppIcon(packageName: String?): ImageBitmap? {
    val context = LocalContext.current
    val cached = packageName?.let(::peekAppIcon)
    val icon by produceState(cached, packageName) {
        value = cached
        if (cached == null && !packageName.isNullOrBlank()) {
            value = withContext(Dispatchers.IO) { decodeAppIcon(context, packageName) }
        }
    }
    return icon
}
