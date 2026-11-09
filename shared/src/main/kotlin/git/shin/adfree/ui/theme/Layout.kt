package git.shin.adfree.ui.theme

import androidx.compose.runtime.Composable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf

/**
 * The two shapes every screen draws itself in.
 *
 * A phone screen taps one thing at a time, so it stacks: one card per idea,
 * full width, tall rows. A desktop window is read, not tapped: AdGuard for
 * Windows answers with flat rows on one surface, hairline separators, and two
 * columns when the window is wide enough to hold them.
 *
 * Screens read the flag instead of measuring the window themselves, so the
 * same composable keeps its phone behaviour on Android and grows a desktop
 * body on Linux.
 */
enum class UiLayout {
    /** Phone: stacked cards, tall rows, bottom navigation. */
    Compact,

    /** Desktop: flat rows, hairline separators, two columns. */
    Desktop,
}

val LocalUiLayout = staticCompositionLocalOf { UiLayout.Compact }

val uiLayout: UiLayout
    @Composable
    @ReadOnlyComposable
    get() = LocalUiLayout.current

/** True inside a desktop window, false on a phone. */
val isDesktopLayout: Boolean
    @Composable
    @ReadOnlyComposable
    get() = LocalUiLayout.current == UiLayout.Desktop

/**
 * Shared measurements. The desktop numbers are the phone ones minus the
 * fat: AdGuard for Windows keeps 12–14px rows text on 48px rows, so a
 * settings list reads as a list, not as a stack of tiles.
 */
object UiSize {
    /** Horizontal page inset inside the content column. */
    val gutter: Int @Composable @ReadOnlyComposable get() = if (isDesktopLayout) 24 else 16

    /** Vertical gap between two sections. */
    val sectionGap: Int @Composable @ReadOnlyComposable get() = if (isDesktopLayout) 18 else 16

    /** Height a list row may not go under. */
    val rowMinHeight: Int @Composable @ReadOnlyComposable get() = if (isDesktopLayout) 46 else 60

    /** Title of a list row. */
    val rowTitleSp: Float @Composable @ReadOnlyComposable get() = if (isDesktopLayout) 13f else 14f

    /** Second line of a list row, or a page subtitle. */
    val rowSubtitleSp: Float @Composable @ReadOnlyComposable get() = if (isDesktopLayout) 11.5f else 11f

    /** The one big page title. */
    val pageTitleSp: Float @Composable @ReadOnlyComposable get() = if (isDesktopLayout) 21f else 24f

    /** Widest a page column may grow before it is centred. */
    const val CONTENT_MAX_WIDTH = 1120
}
