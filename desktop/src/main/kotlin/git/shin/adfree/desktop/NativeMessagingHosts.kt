package git.shin.adfree.desktop

import java.io.File

/**
 * Puts `adfree-native-host` in front of every browser that can talk to it.
 *
 * Chrome's native messaging is not a service: a browser finds a host by
 * reading a small JSON manifest out of its own profile directory and starting
 * whatever `path` names. So "the extension can drive AdFree" means three
 * things on disk — the host binary, one manifest per browser, and the
 * extension that asks for it — and only the middle one is generated here.
 *
 * The manifest is written per browser because each one owns a different
 * profile root. A browser that is not installed is skipped rather than
 * created: an empty `BraveSoftware/` directory is how a user ends up
 * wondering why their crashed-profile dialog appeared.
 *
 * The extension itself is not ours to install. It is AdGuard's, published on
 * the Chrome Web Store, and the manifest only says *who may call this host*:
 * `allowed_origins` names that extension's id and nothing else.
 */
internal object NativeMessagingHosts {

    /** The host name the extension asks Chrome to start. */
    const val HOST_NAME: String = "com.adguard.browser_extension_host.nm"

    /** AdGuard Browser Assistant, as published on the Chrome Web Store. */
    const val EXTENSION_ID: String = "fbohpolgemkbfphodcfgnpjcmedcjhpn"

    /**
     * Profile roots, relative to `$XDG_CONFIG_HOME`. Plain Chromium forks keep
     * the same layout; a browser that is not there is skipped.
     */
    private val BROWSER_ROOTS = listOf(
        "google-chrome",
        "google-chrome-beta",
        "google-chrome-unstable",
        "chromium",
        "BraveSoftware/Brave-Browser",
        "microsoft-edge",
        "microsoft-edge-beta",
        "vivaldi",
        "opera",
        "yandex-browser",
    )

    /**
     * Locates the host binary the same way the core library is located:
     * `ADFREE_NATIVE_HOST` wins, then the `cargo build --release` output under
     * the repo, read relative to the working directory.
     */
    fun findHostBinary(): File? {
        System.getenv("ADFREE_NATIVE_HOST")?.let { return File(it).takeIf(File::exists) }
        val dir = File(System.getProperty("user.dir"))
        val candidates = listOfNotNull(
            File("rust/target/release/adfree-native-host"),
            File("../rust/target/release/adfree-native-host"),
            File(dir, "rust/target/release/adfree-native-host"),
            dir.parentFile?.let { File(it, "rust/target/release/adfree-native-host") },
        )
        return candidates.firstOrNull(File::exists)
    }

    fun configHome(): File =
        File(System.getenv("XDG_CONFIG_HOME") ?: File(System.getProperty("user.home"), ".config").path)

    fun manifestFor(root: File): File = File(root, "NativeMessagingHosts/$HOST_NAME.json")

    /** Browser profile roots that exist on this machine right now. */
    fun installedBrowsers(configHome: File = configHome()): List<File> =
        BROWSER_ROOTS.map { File(configHome, it) }.filter { it.isDirectory }

    /**
     * Writes the manifest into every browser found.
     *
     * Returns the directories written, so the caller can say *which* browsers
     * now work instead of "done": the extension also has to be installed in
     * that browser, and a user who has two of them needs to know which half is
     * finished.
     */
    fun install(host: File, configHome: File = configHome()): List<File> {
        val written = mutableListOf<File>()
        for (root in installedBrowsers(configHome)) {
            val target = manifestFor(root)
            target.parentFile?.mkdirs()
            val manifest = """
                {
                  "name": "$HOST_NAME",
                  "description": "AdFree filtering engine for AdGuard's browser extension",
                  "path": "${host.canonicalFile.absolutePath}",
                  "type": "stdio",
                  "allowed_origins": ["chrome-extension://$EXTENSION_ID/"]
                }
            """.trimIndent() + "\n"
            runCatching { target.writeText(manifest) }.onSuccess { written.add(target) }
        }
        return written
    }

    /** True when any browser already has a manifest that names an existing host. */
    fun installedAndUsable(configHome: File = configHome()): Boolean =
        installedBrowsers(configHome).any { root ->
        val manifest = manifestFor(root)
        if (!manifest.isFile) return@any false
        val path = Regex("\"path\"\\s*:\\s*\"([^\"]+)\"").find(manifest.readText())
            ?.groupValues?.getOrNull(1)
            ?: return@any false
        File(path).canExecute()
    }
}
