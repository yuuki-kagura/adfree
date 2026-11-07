package git.shin.adfree.desktop

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The stores here are found on disk and written through `certutil`, so the
 * tests stand in for both: a fake home directory names the databases, and a
 * fake runner records the commands instead of touching a real NSS store.
 */
class DesktopTrustStoresTest {

    private fun home(vararg relative: String): File {
        val root = File.createTempFile("adfree-trust", "").let { it.delete(); it.mkdirs(); it }
        relative.forEach { path ->
            val file = File(root, path)
            if (path.endsWith("/")) file.mkdirs() else {
                file.parentFile.mkdirs()
                file.writeText("")
            }
        }
        return root
    }

    private class Recorder {
        val commands = mutableListOf<List<String>>()
        /** Exit code per command, matched by the flag that names the action. */
        var answers: (List<String>) -> Int = { 0 }
        fun runner(): (List<String>) -> Pair<Int, String> = { argv ->
            commands += argv
            answers(argv) to ""
        }
    }

    /**
     * Chromium and every other NSS application share `~/.pki/nssdb`, and that
     * database is created on the browser's first run — not when AdFree installs
     * its certificate. The directory must therefore be created here, or a
     * Chromium started after the install would begin life without the CA in a
     * store it will go on reading.
     */
    @Test
    fun theSharedDatabaseIsCreatedEvenBeforeABrowserHasRun() {
        val stores = DesktopTrustStores(home = home())
        assertEquals(
            listOf(File(System.getProperty("user.home"), ".pki/nssdb").name),
            stores.databases().map { it.name },
        )
        assertEquals("one database", 1, stores.databases().size)
    }

    /** One database per Firefox profile, and only where Firefox already made one. */
    @Test
    fun firefoxProfilesAreFoundOnlyWhereTheyHaveADatabase() {
        val root = home(
            ".mozilla/firefox/abc.default-release/cert9.db",
            ".mozilla/firefox/xyz.dev/cert9.db",
            ".mozilla/firefox/empty.profile/",
        )
        val found = DesktopTrustStores(home = root).databases().map { it.name }
        assertEquals(listOf("nssdb", "abc.default-release", "xyz.dev"), found)
    }

    /**
     * The install sequence per database: make it readable (create it when it is
     * not), drop a stale nickname, then add the certificate as a trusted CA.
     * Dropping first is what makes a re-run after an app update replace the
     * certificate instead of failing on the duplicate alias.
     */
    @Test
    fun installingDropsTheOldEntryThenAddsATrustedCa() {
        val recorder = Recorder()
        // `-L` reports the empty database as unreadable: the install path must
        // then create it before adding anything.
        recorder.answers = { argv ->
            if (argv.contains("-L") && !argv.contains("-n")) 1 else 0
        }
        val pem = File.createTempFile("adfree-ca", ".pem").apply { writeText("PEM") }
        val stores = DesktopTrustStores(home = home(), runner = recorder.runner())
        val result = stores.install(pem)
        assertEquals(1, result.size)
        assertTrue("the database took the certificate", result.single().ok)

        val actions = recorder.commands.map { argv ->
            argv.drop(1).first { it in setOf("-N", "-D", "-A", "-L", "-L") || it == "-n" }
        }
        assertTrue("the database is created first", recorder.commands.any { "-N" in it })
        val add = recorder.commands.single { "-A" in it }
        assertEquals("trusted CA", "C,,", add[add.indexOf("-t") + 1])
        assertEquals(DesktopTrustStores.NICKNAME, add[add.indexOf("-n") + 1])
        assertEquals(pem.absolutePath, add[add.indexOf("-i") + 1])
        // The old nickname is dropped before the new one is added, and the
        // read-back that proves the import landed is the last command.
        assertTrue(
            "the delete comes before the add",
            recorder.commands.indexOfFirst { "-D" in it } < recorder.commands.indexOf(add),
        )
        assertTrue("the add is proven by a read-back", recorder.commands.last().contains("-L"))
        assertTrue(actions.isNotEmpty())
    }

    /** A database that reports success but does not list the certificate is a failure. */
    @Test
    fun anAddThatDoesNotReadBackIsReportedAsSuch() {
        val recorder = Recorder()
        recorder.answers = { argv ->
            when {
                argv.contains("-A") -> 0
                // The read-back is the one query with a nickname after -L.
                argv.contains("-L") && argv.contains("-n") -> 1
                else -> 0
            }
        }
        val pem = File.createTempFile("adfree-ca", ".pem").apply { writeText("PEM") }
        val stores = DesktopTrustStores(home = home(), runner = recorder.runner())
        val result = stores.install(pem).single()
        assertFalse(result.ok)
        assertTrue(result.detail, "does not read back" in result.detail)
    }

    /** No `certutil` on the machine is a skipped store, not a crashed install. */
    @Test
    fun aMissingCertutilIsReportedPerDatabase() {
        val pem = File.createTempFile("adfree-ca", ".pem").apply { writeText("PEM") }
        val stores = DesktopTrustStores(
            home = home(".pki/nssdb/"),
            runner = { -1 to "cannot run certutil" },
        )
        val result = stores.install(pem).single()
        assertFalse(result.ok)
        assertTrue(result.detail.isNotBlank())
    }

    /**
     * The JDK keystore is per JVM and lives under the JVM's own directory: the
     * alias must be dropped first for the same re-run reason, and the file
     * passed must be this certificate.
     */
    @Test
    fun everyJdkKeystoreGetsTheCertificate() {
        val jvmRoot = home("jdk-a/lib/security/cacerts", "jdk-b/lib/security/cacerts", "jdk-empty/")
        val found = DesktopJdkTrust.keystores(javaHome = null, jvmRoot = jvmRoot)
        assertEquals(listOf("jdk-a", "jdk-b"), found.map { it.parentFile.parentFile.parentFile.name })

        val recorder = Recorder()
        val pem = File.createTempFile("adfree-ca", ".pem").apply { writeText("PEM") }
        val results = DesktopJdkTrust.install(pem, found, recorder.runner())
        assertEquals(2, results.size)
        assertTrue(results.all { it.detail == null })
        assertEquals("delete then import per keystore", 4, recorder.commands.size)
        val import = recorder.commands.first { "-importcert" in it }
        assertEquals("adfree-ca", import[import.indexOf("-alias") + 1])
        assertEquals(pem.absolutePath, import[import.indexOf("-file") + 1])
        assertTrue("non-interactive", "-noprompt" in import)
    }

    /**
     * A distro that generates the Java keystore from its anchor directory (Arch
     * symlinks `/usr/lib/jvm/<jdk>/lib/security/cacerts` into `/etc/ssl`, Debian
     * ships it the same way) already has the certificate, because the anchor
     * install ran before this. Writing it by hand would be undone at the next
     * `update-ca-trust`, so those are skipped.
     */
    @Test
    fun aGeneratedJavaKeystoreIsLeftToTheDistro() {
        val root = home("jdk-a/lib/security/cacerts", "jdk-b/lib/security/")
        val generated = File(System.getProperty("java.io.tmpdir"), "adfree-generated-cacerts")
        generated.writeText("")
        java.nio.file.Files.createSymbolicLink(
            File(root, "jdk-b/lib/security/cacerts").toPath(),
            generated.toPath(),
        )
        val found = DesktopJdkTrust.keystores(javaHome = null, jvmRoot = root)
        assertEquals(listOf("jdk-a"), found.map { it.parentFile.parentFile.parentFile.name })
        generated.delete()
    }

    /** A keystore that refuses is reported, and the other keystores still get it. */
    @Test
    fun aRefusingKeystoreDoesNotStopTheOthers() {
        val jvmRoot = home("jdk-a/lib/security/cacerts", "jdk-b/lib/security/cacerts")
        val found = DesktopJdkTrust.keystores(javaHome = null, jvmRoot = jvmRoot)
        val pem = File.createTempFile("adfree-ca", ".pem").apply { writeText("PEM") }
        val results = DesktopJdkTrust.install(pem, found) { argv ->
            if ("jdk-a" in argv.joinToString(" ") && "-importcert" in argv) 1 to "read-only" else 0 to ""
        }
        assertEquals(2, results.size)
        assertEquals("read-only", results.first { it.keystore.path.contains("jdk-a") }.detail)
        assertEquals(null, results.first { it.keystore.path.contains("jdk-b") }.detail)
    }
}
