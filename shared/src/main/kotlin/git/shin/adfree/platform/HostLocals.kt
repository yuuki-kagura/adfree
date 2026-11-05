package git.shin.adfree.platform

import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.staticCompositionLocalOf
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

val LocalPlatformHost = staticCompositionLocalOf<PlatformHost?> { null }

val LocalFileHost = staticCompositionLocalOf<FileHost?> { null }

val LocalAppInventory = staticCompositionLocalOf<AppInventory?> { null }

val LocalReminders = staticCompositionLocalOf<Reminders?> { null }

private val NO_TICK = MutableStateFlow(0L)

/**
 * Incremented by the host on every foreground resume. Screens that used
 * Android's ON_RESUME lifecycle event refresh from this instead.
 */
val LocalResumeTick = staticCompositionLocalOf<StateFlow<Long>> { NO_TICK }

/**
 * The shared stand-in for androidx.activity's back stack. The host installs
 * exactly one real back handler that asks this registry first; screens push
 * handlers while a dialog or sub-route is open.
 */
class BackRegistry {
    private val handlers = mutableListOf<() -> Boolean>()

    @Synchronized
    fun push(handler: () -> Boolean) {
        handlers += handler
    }

    @Synchronized
    fun pop(handler: () -> Boolean) {
        handlers -= handler
    }

    @Synchronized
    fun onBack(): Boolean = handlers.lastOrNull()?.invoke() ?: false
}

private val NO_BACK = BackRegistry()

val LocalBackRegistry = staticCompositionLocalOf { NO_BACK }

/** The multiplatform replacement for `androidx.activity.compose.BackHandler`. */
@Composable
fun BackHandler(enabled: Boolean = true, onBack: () -> Unit) {
    val registry = LocalBackRegistry.current
    val handler = remember(onBack) { { onBack(); true } }
    DisposableEffect(enabled, handler) {
        if (enabled) {
            registry.push(handler)
            onDispose { registry.pop(handler) }
        } else {
            onDispose { }
        }
    }
}
