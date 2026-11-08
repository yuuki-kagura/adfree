package git.shin.adfree.desktop

import java.awt.Color
import java.awt.Font
import java.io.File

/**
 * The colours a KDE menu is drawn with, taken from the user's own theme.
 *
 * The tray menu is ours to paint (see [showTrayMenu]), and a menu in Breeze
 * Dark colours is indistinguishable from a native one while a Swing default is
 * not: the panel, the accent used for the highlighted row, the border and the
 * font all come from `kdeglobals`, with Breeze Dark's values as the fallback.
 */
internal data class MenuTheme(
    val panel: Color,
    val text: Color,
    val disabled: Color,
    val accent: Color,
    val accentText: Color,
    val border: Color,
    val separator: Color,
    val font: Font,
)

internal fun kdeMenuTheme(): MenuTheme {
    val config = readKdeGlobals()
    val windowBg = config.rgb("Colors:Window", "BackgroundNormal") ?: Color(0x20, 0x23, 0x26)
    val windowFg = config.rgb("Colors:Window", "ForegroundNormal") ?: Color(0xFC, 0xFC, 0xFC)
    // Menus sit on the view colour in Breeze, one step above the window.
    val panel = config.rgb("Colors:View", "BackgroundNormal") ?: windowBg.lighten(0.04)
    val accent = config.rgb("Colors:Selection", "BackgroundNormal") ?: Color(0x3D, 0xAE, 0xE9)
    val accentText = config.rgb("Colors:Selection", "ForegroundNormal") ?: Color(0xFC, 0xFC, 0xFC)
    return MenuTheme(
        panel = panel,
        text = windowFg,
        disabled = blend(windowFg, panel, 0.45),
        accent = accent,
        accentText = accentText,
        border = blend(windowFg, panel, 0.14),
        separator = blend(windowFg, panel, 0.20),
        // A menu row has to be readable at arm's length: the desktop font is
        // the starting point, one point up from it is what a tray menu needs
        // on a 1366x768 panel.
        font = (config.font() ?: Font("Noto Sans", Font.PLAIN, 10))
            .deriveFont((config.font()?.size ?: 10) + 1f),
    )
}

private fun blend(from: Color, to: Color, amount: Double): Color = Color(
    (from.red + (to.red - from.red) * amount).toInt().coerceIn(0, 255),
    (from.green + (to.green - from.green) * amount).toInt().coerceIn(0, 255),
    (from.blue + (to.blue - from.blue) * amount).toInt().coerceIn(0, 255),
)

private fun Color.lighten(amount: Double): Color = blend(this, Color.WHITE, amount)

/** `kdeglobals` is an INI file: groups of `Key=Value`, values are plain text. */
internal class KdeGlobals(private val values: Map<String, Map<String, String>>) {
    fun get(group: String, key: String): String? = values[group]?.get(key)

    fun rgb(group: String, key: String): Color? {
        val parts = get(group, key)?.split(',') ?: return null
        if (parts.size < 3) return null
        val channels = parts.take(3).map { it.trim().toIntOrNull() ?: return null }
        return Color(
            channels[0].coerceIn(0, 255),
            channels[1].coerceIn(0, 255),
            channels[2].coerceIn(0, 255),
        )
    }

    /** `font=Noto Sans,10,-1,5,50,0,0,0,0,0`: family, point size, then style. */
    fun font(): Font? {
        val raw = get("General", "font") ?: return null
        val parts = raw.split(',').map { it.trim() }
        val family = parts.firstOrNull()?.takeIf { it.isNotEmpty() } ?: return null
        val size = parts.getOrNull(1)?.toIntOrNull() ?: return null
        val style = when (parts.getOrNull(3)?.toIntOrNull() ?: 0) {
            1 -> Font.BOLD
            3 -> Font.BOLD or Font.ITALIC
            2 -> Font.ITALIC
            else -> Font.PLAIN
        }
        return Font(family, style, size)
    }

    companion object {
        fun read(file: File): KdeGlobals {
            if (!file.isFile) return KdeGlobals(emptyMap())
            val values = mutableMapOf<String, MutableMap<String, String>>()
            var group = "General"
            file.forEachLine { line ->
                val trimmed = line.trim()
                when {
                    trimmed.startsWith("[") && trimmed.endsWith("]") ->
                        group = trimmed.substring(1, trimmed.length - 1)
                    trimmed.isEmpty() || trimmed.startsWith("#") -> Unit
                    else -> {
                        val separator = trimmed.indexOf('=')
                        if (separator > 0) {
                            values.getOrPut(group) { mutableMapOf() }[
                                trimmed.substring(0, separator).trim(),
                            ] = trimmed.substring(separator + 1).trim()
                        }
                    }
                }
            }
            return KdeGlobals(values)
        }
    }
}

private fun readKdeGlobals(): KdeGlobals {
    val config = File(System.getProperty("user.home"), ".config/kdeglobals")
    return KdeGlobals.read(config)
}
