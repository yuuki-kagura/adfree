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
 *
 * Linux and Windows disagree about the *third* thing, and it is the one that
 * decides whether a browser ever reads the manifest. On Linux the manifest
 * lives in the browser's own profile directory. On Windows there is no such
 * lookup: the browser asks the registry under `HKCU\Software\<vendor>\
 * NativeMessagingHosts\<name>` for the path of a manifest, which may live
 * anywhere the user can read. Both halves are here because the rest of the
 * app does not care which one applies.
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
        val names = listOf("adfree-native-host", "adfree-native-host.exe")
        val candidates = names.flatMap { name ->
            listOfNotNull(
                File("rust/target/release/$name"),
                File("../rust/target/release/$name"),
                File(dir, "rust/target/release/$name"),
                dir.parentFile?.let { File(it, "rust/target/release/$name") },
                // A packaged install ships the host beside the app image.
                File(dir, "app/resources/$name"),
                dir.parentFile?.let { File(it, "app/resources/$name") },
            )
        }
        return candidates.firstOrNull(File::exists)
    }

    /**
     * Where each browser looks for a host manifest in the registry, relative to
     * `HKEY_CURRENT_USER\Software`. A browser that is not installed has no key
     * there, so the list doubles as the "is it installed" test.
     */
    private val WINDOWS_BROWSERS = listOf(
        "Google\\Chrome",
        "Chromium",
        "BraveSoftware\\Brave-Browser",
        "Microsoft\\Edge",
        "Vivaldi",
        "Opera Software\\Opera Stable",
        "Yandex\\YandexBrowser",
    )

    /** `HKCU\Software\<vendor>\NativeMessagingHosts\<name>`. */
    fun windowsKey(vendor: String): String =
        "HKCU\\Software\\$vendor\\NativeMessagingHosts\\$HOST_NAME"

    /** Runs one `reg` command and reports whether it exited cleanly. */
    private fun reg(args: List<String>): Boolean = runCatching {
        val process = ProcessBuilder(listOf("reg") + args)
            .redirectErrorStream(true)
            .start()
        // The output is only interesting when it fails, and nothing here waits on
        // a dialog: `reg` is a console tool and prints and exits.
        process.inputStream.readBytes()
        process.waitFor() == 0
    }.getOrDefault(false)

    /** The value `reg query` printed for a key, or null when the key is absent. */
    private fun regValue(key: String): String? = runCatching {
        val process = ProcessBuilder("reg", "query", key, "/ve")
            .redirectErrorStream(true)
            .start()
        val text = process.inputStream.readBytes().toString(Charsets.UTF_8)
        if (process.waitFor() != 0) return@runCatching null
        // `    (Default)    REG_SZ    C:\...\x.json`
        text.lineSequence()
            .firstOrNull { it.contains("REG_SZ") }
            ?.substringAfter("REG_SZ")
            ?.trim()
    }.getOrNull()

    /** Where the manifest is kept on Windows: the app's own data directory. */
    fun windowsManifest(dataDir: File): File =
        File(dataDir, "native-messaging/$HOST_NAME.json")

    /**
     * The app's data directory — where the Windows manifest lives, because the
     * Linux half has a profile directory per browser and Windows needs one file
     * somewhere only this user can read.
     */
    fun dataDir(): File = File(
        System.getenv("XDG_DATA_HOME") ?: File(System.getProperty("user.home"), ".local/share").path,
        "adfree",
    )

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
    fun install(
        host: File,
        configHome: File = configHome(),
        dataDir: File = dataDir(),
    ): List<File> {
        if (isWindowsHost()) return installWindows(host, dataDir)
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

    /**
     * Windows: one manifest in the app's data directory, a registry value per
     * browser pointing at it.
     *
     * `HKCU`, not `HKLM`: the app runs elevated, but the extension belongs to the
     * user, and a machine-wide key would advertise AdFree to every account on a
     * shared machine — including ones that never installed it.
     */
    private fun installWindows(host: File, dataDir: File): List<File> {
        val manifest = windowsManifest(dataDir)
        manifest.parentFile?.mkdirs()
        val body = """
            {
              "name": "$HOST_NAME",
              "description": "AdFree filtering engine for AdGuard's browser extension",
              "path": "${host.canonicalFile.absolutePath}",
              "type": "stdio",
              "allowed_origins": ["chrome-extension://$EXTENSION_ID/"]
            }
        """.trimIndent() + "\n"
        if (runCatching { manifest.writeText(body) }.isFailure) return emptyList()
        // Every vendor key is written, not only the ones that exist: a browser
        // that is installed later picks the host up without the app being told,
        // and a key for an absent browser costs one registry value.
        val registered = WINDOWS_BROWSERS.count { vendor ->
            reg(listOf("add", windowsKey(vendor), "/ve", "/t", "REG_SZ", "/d", manifest.absolutePath, "/f"))
        }
        return if (registered > 0) listOf(manifest) else emptyList()
    }

    /** True when any browser already has a manifest that names an existing host. */
    fun installedAndUsable(configHome: File = configHome()): Boolean {
        if (isWindowsHost()) {
            return WINDOWS_BROWSERS.any { vendor ->
                val path = regValue(windowsKey(vendor)) ?: return@any false
                File(path).isFile
            }
        }
        return installedBrowsers(configHome).any { root ->
        val manifest = manifestFor(root)
        if (!manifest.isFile) return@any false
        val path = Regex("\"path\"\\s*:\\s*\"([^\"]+)\"").find(manifest.readText())
            ?.groupValues?.getOrNull(1)
            ?: return@any false
        File(path).canExecute()
        }
    }
}
