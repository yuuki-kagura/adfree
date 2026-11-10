package git.shin.adfree.desktop

import com.sun.jna.Library
import com.sun.jna.Native
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit

/**
 * The parts of the user's session an installed unit cannot inherit.
 *
 * The protection unit is written once and started many times, so the values
 * copied into it at install time are the values of the session that installed
 * it. Most of them are stable (`HOME`, `XDG_RUNTIME_DIR`, the session bus), but
 * `XAUTHORITY` is not: every graphical login mints a new `xauth_*` file and
 * deletes the old one. A unit started the morning after therefore hands Java an
 * `XAUTHORITY` path that no longer exists, Xlib refuses the connection, and the
 * first AWT call — the tray icon — throws `AWTError` and takes the whole
 * process down with the redirect rules it had just installed.
 *
 * The unit runs as the same user, so it can ask that user's own systemd manager
 * what the session looks like now. The JVM's environment is updated through
 * libc before AWT is loaded, because Xlib reads `XAUTHORITY` straight from
 * `environ`; Java's `System.getenv` map is a snapshot and cannot be written.
 */
object DesktopSession {

    /** The variables a window needs, in the order a wrong one hurts. */
    private val DISPLAY_KEYS = listOf("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY")

    /**
     * Rewrites the display variables of this process from the live session.
     *
     * A failure is not fatal: the app can still filter without a window, and
     * the fallback below covers the common no-user-manager case.
     */
    fun refreshDisplayEnvironment(
        log: (String) -> Unit = { System.err.println("[desktop] $it") },
    ) {
        if (!System.getProperty("os.name").orEmpty().contains("linux", ignoreCase = true)) return
        val session = userManagerEnvironment()
        val desired = LinkedHashMap<String, String>()
        DISPLAY_KEYS.forEach { key ->
            session[key]?.takeIf { it.isNotBlank() }?.let { desired[key] = it }
        }
        // An X cookie is a path, and a path from the installing session is a
        // path to a file the next login removed.
        val cookie = desired["XAUTHORITY"]
            ?.takeIf { File(it).isFile }
            ?: newestXAuthority(runtimeDirectory())?.absolutePath
        if (cookie != null) desired["XAUTHORITY"] = cookie
        desired.forEach { (key, value) ->
            if (System.getenv(key) == value) return@forEach
            if (setEnvironment(key, value)) log("session: $key <- $value")
        }
    }

    /**
     * The user manager's environment, which is the only place that knows the
     * current login rather than the login the unit was written in.
     *
     * `systemctl --user` needs the runtime directory and the bus address; both
     * are stable and already in the unit. A machine with no user manager (or a
     * unit started before the session) answers nothing and the caller falls
     * back to the filesystem.
     */
    internal fun userManagerEnvironment(): Map<String, String> = runCatching {
        val process = ProcessBuilder("systemctl", "--user", "show-environment")
            .redirectErrorStream(true)
            .start()
        if (!process.waitFor(2, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            return@runCatching emptyMap()
        }
        parseShowEnvironment(process.inputStream.bufferedReader().readText())
    }.getOrDefault(emptyMap())

    /** One `KEY=VALUE` per line, as `systemctl show-environment` prints it. */
    internal fun parseShowEnvironment(text: String): Map<String, String> = buildMap {
        text.lineSequence().forEach { line ->
            val separator = line.indexOf('=')
            if (separator > 0) put(line.substring(0, separator), line.substring(separator + 1))
        }
    }

    /**
     * The newest X cookie in the session's runtime directory.
     *
     * The display manager names it per login (`xauth_XXXXXX`), so "newest" is
     * the only answer that follows a new login; the name itself carries no
     * meaning. Readable only by this user, which is who the unit runs as.
     */
    internal fun newestXAuthority(runtimeDirectory: File?): File? {
        val candidates = runtimeDirectory?.listFiles { file ->
            file.isFile && file.name.startsWith("xauth_")
        } ?: return null
        return candidates.maxByOrNull { it.lastModified() }
    }

    /** `$XDG_RUNTIME_DIR`, or the conventional `/run/user/<uid>`. */
    private fun runtimeDirectory(): File? {
        System.getenv("XDG_RUNTIME_DIR")?.takeIf { it.isNotBlank() }?.let { return File(it) }
        val uid = runCatching {
            (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
        }.getOrNull() ?: return null
        return File("/run/user/$uid")
    }

    /** True when libc took the value; false keeps the old one instead of failing. */
    private fun setEnvironment(key: String, value: String): Boolean =
        runCatching { SessionLibC.INSTANCE.setenv(key, value, 1) == 0 }.getOrDefault(false)

    /**
     * The one libc call this file needs. Kept private so the desktop's other
     * bindings do not grow a general process-environment surface.
     */
    private interface SessionLibC : Library {
        fun setenv(name: String, value: String, overwrite: Int): Int

        companion object {
            val INSTANCE: SessionLibC = Native.load("c", SessionLibC::class.java)
        }
    }
}
