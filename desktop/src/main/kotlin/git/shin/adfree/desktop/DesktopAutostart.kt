package git.shin.adfree.desktop

import java.io.File

/**
 * "Start with the system", for a desktop session.
 *
 * A graphical login is the only moment a window has a display to open on, so
 * the entry lives in XDG's autostart directory rather than in a boot-time
 * system unit: the unit that holds `CAP_NET_ADMIN` is started by whatever runs
 * at login, and a session that is not logged in has nothing for it to protect.
 *
 * What it starts depends on how far the machine has been set up. With the
 * protection unit installed, the entry starts the unit — no window, no second
 * instance, and the switch the user left on is a machine that is filtered from
 * the first second of the session. Without it, the entry starts the app, which
 * is what installs the unit the first time somebody asks for full protection.
 */
class DesktopAutostart(
    private val entry: File = defaultEntry(),
) {

    /** Writes or removes the entry, whichever the setting asks for. */
    fun sync(
        enabled: Boolean,
        unitInstalled: Boolean,
        appArgv: List<String>,
        workingDirectory: String? = null,
    ): Result<Unit> = runCatching {
        if (!enabled) {
            entry.delete()
            return@runCatching
        }
        entry.parentFile?.mkdirs()
        entry.writeText(
            if (unitInstalled) {
                render(unitStart)
            } else {
                // The app is started from the session's own directory, which is
                // the home directory; the core is found relative to the working
                // directory, so the entry has to carry the one the app was
                // installed from.
                render(appArgv, workingDirectory)
            },
        )
    }

    fun installed(): Boolean = entry.isFile

    /**
     * The entry's text. `Exec` is the one field with syntax in it: words are
     * separated by spaces, and a word that holds a space, a quote, a backtick or
     * a `$` has to be quoted and escaped — the classpath of a packaged app is
     * one long word with colons, but a path in a home directory is not.
     */
    internal fun render(exec: List<String>, workingDirectory: String? = null): String {
        val commandLine = exec.joinToString(" ") { desktopQuote(it) }
        return buildString {
            appendLine("[Desktop Entry]")
            appendLine("Type=Application")
            appendLine("Name=AdFree")
            appendLine("Comment=Filtering starts with the session")
            appendLine("Exec=$commandLine")
            workingDirectory?.takeIf { it.isNotBlank() }?.let { appendLine("Path=$it") }
            appendLine("Terminal=false")
            appendLine("NoDisplay=true")
            appendLine("X-GNOME-Autostart-enabled=true")
            appendLine("X-KDE-autostart-after=panel")
        }
    }

    private companion object {
        val unitStart = listOf("systemctl", "--no-block", "restart", "adfree-desktop")

        fun defaultEntry(): File = File(
            System.getenv("XDG_CONFIG_HOME")
                ?: File(System.getProperty("user.home"), ".config").absolutePath,
            "autostart/adfree-desktop.desktop",
        )
    }
}

/**
 * One `Exec` word as the desktop-entry spec reads it. Reserved characters are
 * escaped by a backslash, and `%` doubles because it introduces a field code
 * (`%f`, `%U`) even inside quotes.
 */
internal fun desktopQuote(value: String): String {
    val escaped = buildString {
        value.forEach { character ->
            when (character) {
                '\\', '"', '`', '$' -> append('\\').append(character)
                else -> append(character)
            }
        }
    }.replace("%", "%%")
    return if (escaped.any { it.isWhitespace() || it == '\\' || it == '"' }) "\"$escaped\"" else escaped
}
