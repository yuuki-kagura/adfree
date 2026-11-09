package git.shin.adfree.desktop

import java.io.File
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The manifest is the only thing that makes Chrome start AdFree, so the tests
 * are about what a browser reads, not about the writer: the host name it must
 * answer to, the id allowed to call it, and a path that is executable.
 */
class NativeMessagingHostsTest {

    private val root: File = File(System.getProperty("java.io.tmpdir"), "adfree-nm-test-${System.nanoTime()}")
    private val host: File = File(root, "adfree-native-host").apply {
        parentFile.mkdirs()
        writeText("#!/bin/sh\n")
        setExecutable(true)
    }
    private val configHome: File = File(root, "config")

    @After
    fun clean() {
        root.deleteRecursively()
    }

    private fun browser(name: String = "google-chrome"): File = File(configHome, name).apply { mkdirs() }

    @Test
    fun `writes the manifest where chrome looks`() {
        browser()
        val written = NativeMessagingHosts.install(host, configHome)

        assertEquals(1, written.size)
        val manifest = File(configHome, "google-chrome/NativeMessagingHosts/${NativeMessagingHosts.HOST_NAME}.json")
        assertTrue(manifest.isFile)
        val text = manifest.readText()
        assertTrue(text.contains("\"path\": \"${host.absolutePath}\""))
        assertTrue(text.contains("chrome-extension://${NativeMessagingHosts.EXTENSION_ID}/"))
    }

    @Test
    fun `installs into every browser present and none that is not`() {
        browser("google-chrome")
        browser("BraveSoftware/Brave-Browser")
        NativeMessagingHosts.install(host, configHome)

        assertTrue(File(configHome, "google-chrome/NativeMessagingHosts").isDirectory)
        assertTrue(File(configHome, "BraveSoftware/Brave-Browser/NativeMessagingHosts").isDirectory)
        // A browser that is not installed must not have a directory invented
        // for it: that is how a user ends up with a profile they never created.
        assertFalse(File(configHome, "vivaldi").exists())
    }

    @Test
    fun `installed means the manifest names a host that can run`() {
        browser()
        assertFalse(NativeMessagingHosts.installedAndUsable(configHome))

        NativeMessagingHosts.install(host, configHome)
        assertTrue(NativeMessagingHosts.installedAndUsable(configHome))

        // A manifest pointing at a binary that is gone is not installed: the
        // browser would start nothing and the extension would report the app
        // as stopped, which is worse than saying it is not connected.
        host.delete()
        assertFalse(NativeMessagingHosts.installedAndUsable(configHome))
    }

    @Test
    fun `a stale manifest is reported as installed until the path is checked`() {
        browser()
        val manifest = File(configHome, "google-chrome/NativeMessagingHosts/${NativeMessagingHosts.HOST_NAME}.json")
        manifest.parentFile.mkdirs()
        manifest.writeText("""{"name":"x","path":"/nonexistent/host","type":"stdio"}""")

        assertFalse(NativeMessagingHosts.installedAndUsable(configHome))
    }
}
