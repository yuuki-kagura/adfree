package git.shin.adfree.desktop

import java.io.File

/**
 * The Windows redirect needs two files from WinDivert, and they must sit in the
 * same directory: the DLL loads its driver from beside itself.
 *
 * They travel inside the application jar, `WinDivert.dll` and `WinDivert64.sys`
 * exactly as the official distribution ships them — unmodified, because the
 * signature on that pair is what lets Windows load the driver without a signing
 * certificate of our own — with the licence and version beside them. This writes
 * them out to a stable directory on first run and tells the core where they are.
 *
 * Nothing here runs off Windows: elsewhere the files are absent, the unpack is a
 * no-op, and the app filters the way it always has.
 */
object WinDivertFiles {

    private const val RESOURCE_DIR = "/windivert"

    /** The two files, largest-last is fine: the DLL finds the driver by name. */
    private val BINARIES = listOf("x64/WinDivert.dll", "x64/WinDivert64.sys")

    /** Shipped with the binaries because their licence requires it. */
    private val NOTICES = listOf("LICENSE.txt", "VERSION", "README.txt")

    /**
     * Writes the pair into `dir` when it is not already there and returns the
     * directory, or `null` on a platform that has no WinDivert.
     *
     * Cached by length so an updated app replaces the files, and written through
     * a temporary name so a half-written DLL cannot be loaded by the next start.
     */
    fun unpack(dir: File = defaultDir()): File? {
        if (!isWindowsHost()) return null
        val target = File(dir, "x64")
        target.mkdirs()
        val wanted = BINARIES + NOTICES
        for (name in wanted) {
            val bytes = read(name) ?: return null
            val file = File(target, name.substringAfterLast('/'))
            if (file.length() != bytes.size.toLong()) {
                val temp = File(target, "${file.name}.tmp")
                temp.writeBytes(bytes)
                temp.renameTo(file)
            }
        }
        return target
    }

    /** Unpacks, then points the core at the result. Returns the directory used. */
    fun install(dir: File = defaultDir()): File? {
        val target = unpack(dir) ?: return null
        runCatching { git.shin.adfree.core.coreSetWindivertDir(target.absolutePath) }
        return target
    }

    private fun read(name: String): ByteArray? = runCatching {
        object {}.javaClass.getResourceAsStream("$RESOURCE_DIR/$name")?.use { it.readBytes() }
    }.getOrNull()

    private fun defaultDir(): File = File(
        System.getenv("XDG_DATA_HOME") ?: File(System.getProperty("user.home"), ".local/share").path,
        "adfree/windivert",
    )
}
