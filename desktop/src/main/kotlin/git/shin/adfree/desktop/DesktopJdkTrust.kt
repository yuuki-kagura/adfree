package git.shin.adfree.desktop

import java.io.File
import java.nio.file.Files

/**
 * The JDK's own trust keystore, per installed JVM.
 *
 * A Java application never reads the distro bundle: it reads
 * `<jdk>/lib/security/cacerts`, and it will keep rejecting the filtering CA
 * until the certificate is in that file — which is why a Java tool behind the
 * proxy reports a TLS failure while `curl` on the same machine is happy. The
 * file is root-owned, so this runs inside [CaInstall]'s elevated process.
 *
 * The default keystore password is `changeit` and the file ships world-readable
 * with it, so importing changes no secret; the alias is removed before the
 * import so a re-run replaces the certificate instead of reporting a duplicate.
 */
object DesktopJdkTrust {

    private const val ALIAS = "adfree-ca"
    private const val STORE_PASS = "changeit"
    private const val CACERTS = "lib/security/cacerts"

    /** One keystore and what happened: null detail means the import landed. */
    data class Result(val keystore: File, val detail: String?)

    /**
     * Every keystore this machine has: the running JVM's own, then the distro's
     * JVM directories under `/usr/lib/jvm`. Deduplicated by real path, because
     * `java.home` is often a symlink into one of them.
     *
     * A keystore that is a symlink into `/etc/ssl` or `/etc/pki` is skipped on
     * purpose: those distros *generate* the Java keystore from the system
     * anchor directory on every `update-ca-trust`, so the certificate is
     * already there — a hand-written entry would either be erased by the next
     * regeneration or land in a file owned by the ca-certificates package. Only
     * a JDK's own bundled store, a regular file nobody regenerates, needs the
     * write.
     */
    fun keystores(
        javaHome: String? = System.getProperty("java.home"),
        jvmRoot: File = File("/usr/lib/jvm"),
    ): List<File> {
        val candidates = buildList {
            javaHome?.let { File(it, CACERTS) }?.let { add(it) }
            jvmRoot.listFiles().orEmpty().sortedBy { it.name }.forEach { jvm ->
                add(File(jvm, CACERTS))
            }
        }
        return candidates
            .filter { it.isFile && !Files.isSymbolicLink(it.toPath()) }
            .distinctBy { runCatching { it.canonicalPath }.getOrDefault(it.absolutePath) }
    }

    /**
     * Imports [pem] into every keystore. Runs as root from [CaInstall]; a
     * keystore that refuses (a read-only image, a custom password) is reported
     * and the others still get the certificate.
     */
    fun install(
        pem: File,
        keystores: List<File> = keystores(),
        runner: (List<String>) -> Pair<Int, String> = ::run,
    ): List<Result> {
        if (!pem.isFile) return keystores.map { Result(it, "no certificate at ${pem.path}") }
        return keystores.map { keystore ->
            val keytool = keytoolFor(keystore)
            val base = listOf(keytool, "-keystore", keystore.absolutePath, "-storepass", STORE_PASS)
            // A re-run must replace the entry: `-importcert` refuses an alias
            // that is taken, so the old one is dropped first, failure ignored.
            runner(base + listOf("-delete", "-alias", ALIAS))
            val (code, output) = runner(
                base + listOf(
                    "-importcert", "-noprompt", "-trustcacerts",
                    "-alias", ALIAS,
                    "-file", pem.absolutePath,
                ),
            )
            Result(keystore, if (code == 0) null else output.trim())
        }
    }

    /** The `keytool` beside the keystore's own JVM, or the one on `PATH`. */
    private fun keytoolFor(keystore: File): String {
        // <jdk>/lib/security/cacerts -> <jdk>/bin/keytool
        val jdk = keystore.parentFile?.parentFile?.parentFile
        val local = jdk?.let { File(it, "bin/keytool") }
        return if (local != null && local.canExecute()) local.absolutePath else "keytool"
    }

    private fun run(argv: List<String>): Pair<Int, String> = runCatching {
        val process = ProcessBuilder(argv)
            // `keytool` is non-interactive with `-noprompt`, but a keystore it
            // cannot open still asks for a password on stdin; answer with EOF.
            .redirectInput(ProcessBuilder.Redirect.from(File("/dev/null")))
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        process.waitFor() to output
    }.getOrDefault(-1 to "cannot run ${argv.firstOrNull() ?: "the command"}")
}
