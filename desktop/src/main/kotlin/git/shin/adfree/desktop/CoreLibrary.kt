package git.shin.adfree.desktop

import java.io.File

/**
 * Locates the host build of the Rust core. `ADFREE_CORE_LIB` wins; otherwise
 * the usual `cargo build --release` output under the repo is searched relative
 * to the working directory (repo root or `:desktop`/`desktop`).
 */
internal fun findCoreLibrary(): File? {
    System.getenv("ADFREE_CORE_LIB")?.let { return File(it).takeIf(File::exists) }
    val dir = File(System.getProperty("user.dir"))
    val candidates = listOfNotNull(
        File("rust/target/release/libadfree_core.so"),
        File("../rust/target/release/libadfree_core.so"),
        File(dir, "rust/target/release/libadfree_core.so"),
        dir.parentFile?.let { File(it, "rust/target/release/libadfree_core.so") },
    )
    return candidates.firstOrNull(File::exists)
}
