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
    /**
     * How this machine starts things at logon.
     *
     * XDG on Linux: one file, no privilege, and it may point at the unit. On
     * Windows the app must also start *elevated*, and a `Run` key cannot do
     * that — the token is only granted by the secure desktop's prompt, which
     * means a UAC dialog at every logon. A Scheduled Task with `ONLOGON` and
     * `HIGHEST` starts in the user's session without that prompt, which is why
     * it, and not the registry, is what this writes.
     */
    private val isWindows: Boolean = isWindowsHost(),
    private val run: (List<String>) -> Boolean = ::runQuietly,
) {

    /** Writes or removes the entry, whichever the setting asks for. */
    fun sync(
        enabled: Boolean,
        unitInstalled: Boolean,
        appArgv: List<String>,
        workingDirectory: String? = null,
    ): Result<Unit> = runCatching {
        if (isWindows) {
            if (!enabled) {
                run(schtasksDelete())
                return@runCatching
            }
            val argv = appArgv.ifEmpty { return@runCatching }
            if (!run(schtasksCreate(argv))) {
                error("schtasks refused to create the logon task")
            }
            return@runCatching
        }
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

    fun installed(): Boolean =
        if (isWindows) run(schtasksQuery()) else entry.isFile

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

    /** The task's name in Task Scheduler. Fixed, so `install` replaces itself. */
    internal companion object {
        const val TASK_NAME = "adfree-desktop"

        val unitStart = listOf("systemctl", "--no-block", "restart", "adfree-desktop")

        /**
         * `schtasks /Create` for a logon task that runs with the highest
         * available token. `/F` overwrites, because the app's own path changes
         * when it is updated and an old action would point at nothing.
         */
        internal fun schtasksCreate(appArgv: List<String>): List<String> = listOf(
            "schtasks",
            "/Create",
            "/TN",
            TASK_NAME,
            "/TR",
            windowsCommandLine(appArgv),
            "/SC",
            "ONLOGON",
            "/RL",
            "HIGHEST",
            "/F",
        )

        internal fun schtasksDelete(): List<String> =
            listOf("schtasks", "/Delete", "/TN", TASK_NAME, "/F")

        internal fun schtasksQuery(): List<String> =
            listOf("schtasks", "/Query", "/TN", TASK_NAME)

        fun defaultEntry(): File = File(
            System.getenv("XDG_CONFIG_HOME")
                ?: File(System.getProperty("user.home"), ".config").absolutePath,
            "autostart/adfree-desktop.desktop",
        )
    }
}

/**
 * One command line as Task Scheduler's `/TR` reads it: words joined by spaces,
 * quoted only when they need it, because the value is one argv element of
 * `schtasks` rather than an argv of its own.
 */
internal fun windowsCommandLine(argv: List<String>): String =
    argv.joinToString(" ") { word -> if (word.any { it.isWhitespace() }) "\"$word\"" else word }

/** Runs a command and answers whether it succeeded, with nothing on the console. */
internal fun runQuietly(argv: List<String>): Boolean = runCatching {
    ProcessBuilder(argv).redirectErrorStream(true).start().waitFor() == 0
}.getOrDefault(false)

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
