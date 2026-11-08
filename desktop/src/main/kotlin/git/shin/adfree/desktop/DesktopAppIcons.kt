package git.shin.adfree.desktop

import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.toComposeImageBitmap
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import org.jetbrains.skia.Image as SkiaImage

/**
 * The icon of the program behind a log row.
 *
 * A desktop log names the process the kernel names — `chrome`, `firefox`,
 * `konsole` — because that is what a filter rule has to match on. The picture
 * lives somewhere else: in a `.desktop` entry that spells the application's
 * own name, and in an icon theme file that entry points at. Finding one from
 * the other is the whole job here, and it is worth doing: a column of process
 * names is read by reading, while a column of icons is scanned.
 *
 * Everything is best-effort. A process with no desktop entry, an entry whose
 * icon is not installed where this lookup looks, an SVG — all of them end in
 * null, and the row falls back to the name it always showed.
 */
internal class DesktopAppIcons(
    /** Where `.desktop` entries live: the user's own first, then the system's. */
    private val applicationDirs: List<File> = defaultApplicationDirs(),
    /** Where icons live: the theme roots, then the flatpak exports. */
    private val iconRoots: List<File> = defaultIconRoots(),
) {

    /** One entry's worth of what the match needs. */
    private data class DesktopEntry(val id: String, val exec: String?, val icon: String?, val wmClass: String?)

    /** Decoded icons, and the names known to have none, so nothing is looked up twice. */
    private val icons = ConcurrentHashMap<String, ImageBitmap>()
    private val missing = ConcurrentHashMap.newKeySet<String>()
    private val names = ConcurrentHashMap<String, String>()

    /** The icon for `process`, or null when this machine has none to offer. */
    fun icon(process: String): ImageBitmap? {
        val key = normalize(process)
        if (key.isEmpty()) return null
        icons[key]?.let { return it }
        if (key in missing) return null
        val name = iconName(key) ?: run {
            missing.add(key)
            return null
        }
        val file = iconFile(name) ?: run {
            missing.add(key)
            return null
        }
        val decoded = runCatching {
            SkiaImage.makeFromEncoded(file.readBytes()).toComposeImageBitmap()
        }.getOrNull()
        if (decoded == null) {
            missing.add(key)
            return null
        }
        icons[key] = decoded
        return decoded
    }

    /**
     * The icon theme name for a process: the `Icon=` of the entry that best
     * describes it, or the process name itself.
     *
     * The process is what the kernel calls the program and the entry is what
     * its author called it, so the pair is rarely equal: Chrome runs as
     * `chrome` and installs `google-chrome.desktop`. Containment in either
     * direction is what bridges that, scored so an exact name beats a partial
     * one and a longer overlap beats a shorter.
     */
    internal fun iconName(process: String): String? {
        names[process]?.let { return it }
        val key = normalize(process)
        if (key.isEmpty()) return null
        var best: String? = null
        var bestScore = 0
        for (entry in entries()) {
            // An entry with no `Icon=` cannot answer this question, however
            // well its name matches: it would win the score and hand the
            // lookup a null. A launch-only wrapper and the odd Wine leftover
            // are exactly the entries that do this.
            val icon = entry.icon?.takeIf { it.isNotBlank() } ?: continue
            val score = score(key, entry)
            if (score > bestScore) {
                bestScore = score
                best = icon
            }
        }
        // Nothing matched: the process name is what themes call most programs
        // anyway, so it is tried before giving up.
        val resolved = best ?: key
        names[process] = resolved
        return resolved
    }

    /** The file an icon theme name points at, or null when nothing on disk matches. */
    internal fun iconFile(name: String): File? {
        if (name.startsWith("/")) return File(name).takeIf { it.isFile }
        // Sizes from the one a row renders best up to the largest a theme
        // usually carries: a 512px source is a good scale-down and a waste of
        // memory, but a machine that only has that one still gets an icon.
        for (root in iconRoots) {
            for (size in ICON_SIZES) {
                val file = File(File(File(root, "hicolor"), "${size}x$size"), "apps/$name.png")
                if (file.isFile) return file
            }
            val pixmap = File(File(root, "pixmaps"), "$name.png")
            if (pixmap.isFile) return pixmap
            // Other themes are worth a look only where the standard one keeps
            // nothing, which is where a KDE-only application lands.
            val themes = root.listFiles()?.filter { it.isDirectory } ?: continue
            for (theme in themes) {
                for (size in ICON_SIZES) {
                    val file = File(File(File(theme, "${size}x$size"), "apps"), "$name.png")
                    if (file.isFile) return file
                }
            }
        }
        return null
    }

    /** Every entry, parsed once per lookup: a log row asks for one process. */
    private fun entries(): List<DesktopEntry> {
        val found = mutableListOf<DesktopEntry>()
        for (dir in applicationDirs) {
            val files = dir.listFiles { file -> file.isFile && file.name.endsWith(".desktop") } ?: continue
            for (file in files) {
                runCatching { parse(file) }.getOrNull()?.let { found.add(it) }
            }
        }
        return found
    }

    private fun parse(file: File): DesktopEntry {
        var icon: String? = null
        var exec: String? = null
        var wmClass: String? = null
        var inMain = false
        for (line in file.readLines()) {
            val text = line.trim()
            when {
                text.startsWith("[") -> inMain = text == "[Desktop Entry]"
                !inMain || !text.contains('=') -> Unit
                text.startsWith("Icon=") -> if (icon == null) icon = text.removePrefix("Icon=").trim()
                text.startsWith("Exec=") -> if (exec == null) exec = text.removePrefix("Exec=").trim()
                text.startsWith("StartupWMClass=") ->
                    if (wmClass == null) wmClass = text.removePrefix("StartupWMClass=").trim()
            }
        }
        return DesktopEntry(
            id = file.name.removeSuffix(".desktop"),
            exec = exec?.let { executable(it) },
            icon = icon,
            wmClass = wmClass,
        )
    }

    /** The program's own word of an `Exec=` line, without flags or field codes. */
    private fun executable(exec: String): String? =
        exec.split(' ')
            .firstOrNull { it.isNotBlank() && !it.startsWith("%") && !it.startsWith("-") }
            ?.let { it.substringAfterLast('/') }
            ?.takeIf { it.isNotBlank() }

    private fun score(process: String, entry: DesktopEntry): Int {
        val candidates = listOfNotNull(
            entry.id.lowercase(),
            entry.exec?.lowercase(),
            entry.wmClass?.lowercase(),
            entry.icon?.substringAfterLast('/')?.removeSuffix(".png")?.lowercase(),
        )
        var best = 0
        for (candidate in candidates) {
            val score = when {
                candidate == process -> 100
                candidate.startsWith(process) || process.startsWith(candidate) ->
                    60 - kotlin.math.abs(candidate.length - process.length)
                process.length >= 3 && candidate.contains(process) ->
                    40 - (candidate.length - process.length)
                else -> 0
            }
            if (score > best) best = score
        }
        return best
    }

    private fun normalize(process: String): String =
        process.substringAfterLast('/').trim().lowercase().takeIf { it.isNotBlank() && it != "?" } ?: ""

    companion object {
        /** The one the log rows use; the lookups are cached inside it. */
        val shared = DesktopAppIcons()

        /** Sizes in the order a row wants them: crisp at 16–20 dp, then bigger. */
        private val ICON_SIZES = listOf(64, 48, 128, 96, 256, 32, 512, 24, 22, 16)

        private fun xdg(vararg parts: String): File =
            File(System.getenv("XDG_DATA_HOME") ?: File(System.getProperty("user.home"), ".local/share").path, parts.joinToString("/"))

        private fun home(vararg parts: String): File =
            File(System.getProperty("user.home"), parts.joinToString("/"))

        internal fun defaultApplicationDirs(): List<File> = listOf(
            xdg("applications"),
            home(".local/share/applications"),
            File("/usr/local/share/applications"),
            File("/usr/share/applications"),
            File("/var/lib/flatpak/exports/share/applications"),
            xdg("flatpak/exports/share/applications"),
        ).distinctBy { it.path }.filter { it.isDirectory }

        internal fun defaultIconRoots(): List<File> = listOf(
            xdg("icons"),
            home(".local/share/icons"),
            home(".icons"),
            File("/usr/local/share/icons"),
            File("/usr/share/icons"),
            File("/usr/share"),
            File("/var/lib/flatpak/exports/share/icons"),
            xdg("flatpak/exports/share/icons"),
        ).distinctBy { it.path }.filter { it.isDirectory }
    }
}
