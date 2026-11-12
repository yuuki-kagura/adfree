package git.shin.adfree.desktop

import java.io.File

/**
 * The core's file name on this platform: `cargo` writes a Unix shared object and
 * a Windows DLL, and everything that looks the library up has to agree with it.
 */
internal val coreLibraryName: String
    get() = if (isWindowsHost()) "adfree_core.dll" else "libadfree_core.so"

/** Where `cargo build --release` leaves the core, without the file name. */
private const val CORE_TARGET_DIR = "rust/target/release"

/**
 * Locates the host build of the Rust core. `ADFREE_CORE_LIB` wins; otherwise
 * the usual `cargo build --release` output under the repo is searched relative
 * to the working directory (repo root or `:desktop`/`desktop`).
 */
internal fun findCoreLibrary(): File? {
    System.getenv("ADFREE_CORE_LIB")?.let { return File(it).takeIf(File::exists) }
    val dir = File(System.getProperty("user.dir"))
    val name = coreLibraryName
    val candidates = listOfNotNull(
        File("$CORE_TARGET_DIR/$name"),
        File("../$CORE_TARGET_DIR/$name"),
        File(dir, "$CORE_TARGET_DIR/$name"),
        dir.parentFile?.let { File(it, "$CORE_TARGET_DIR/$name") },
        // A packaged app has no repository beside it. The launcher knows where
        // it lives, and the library was shipped next to the jars — that is the
        // only path an installed deb or rpm has.
        packagedLibrary(),
        // A distribution that packages the core separately puts it here; the
        // app is not the only thing allowed to know where the library is.
        File("/usr/lib/adfree/$name"),
        // An installed deb or rpm has no repository beside it and no separate
        // library to point at: the core travels inside the application jar and
        // is written out where it can be loaded from.
        unpackedLibrary(),
    )
    return candidates.firstOrNull(File::exists)
}

/**
 * Writes the core that ships inside the application jar out to a stable path and
 * returns it. The `XDG_CACHE_HOME` name is kept on Windows too, where
 * `System.getProperty("user.home")` supplies the base: one cache layout is
 * easier to explain than two. Cached by size, so a package that brings a new core replaces the
 * old one and an unchanged one costs a `length()`.
 */
internal fun unpackedLibrary(): File? {
    // Read through a class of this jar: `Any::class.java` is a bootstrap class,
    // and its resource lookups do not see the application classpath.
    val name = coreLibraryName
    val stream = object {}.javaClass.getResourceAsStream("/$name") ?: return null
    val bytes = stream.use { it.readBytes() }
    val cache = File(
        System.getenv("XDG_CACHE_HOME") ?: File(System.getProperty("user.home"), ".cache").path,
        "adfree/lib",
    )
    cache.mkdirs()
    val target = File(cache, name)
    if (target.length() != bytes.size.toLong()) {
        val temp = File(cache, "$name.tmp")
        temp.writeBytes(bytes)
        temp.setExecutable(true)
        // Rename rather than write in place: a half-written library is a load
        // failure the next process inherits, and two windows starting at once
        // must not see one another's partial file.
        temp.renameTo(target)
        target.setExecutable(true)
    }
    return target.takeIf(File::isFile)
}

/**
 * The core beside a packaged app image: `jpackage` sets `jpackage.app-path` to
 * the launcher in `bin/`, and the app resources land in `lib/app/resources/`.
 */
private fun packagedLibrary(): File? {
    val launcher = System.getProperty("jpackage.app-path")?.let(::File) ?: return null
    val image = launcher.parentFile?.parentFile ?: return null
    return File(image, "lib/app/resources/${coreLibraryName}")
}
