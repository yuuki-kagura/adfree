package git.shin.adfree.desktop

import git.shin.adfree.desktop.AssistantBridge.Companion.readFrame
import git.shin.adfree.desktop.AssistantBridge.Companion.writeFrame
import java.io.File
import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The wire format is Chrome's, not ours: a little-endian length prefix. Getting
 * the byte order wrong does not fail loudly — it produces a nonsensical length,
 * the reader drops the connection, and the extension reports the app as
 * stopped. These tests pin the bytes down.
 */
class AssistantBridgeFramingTest {

    private val dir: File = File(System.getProperty("java.io.tmpdir"), "adfree-bridge-${System.nanoTime()}")
    private val server: ServerSocketChannel = ServerSocketChannel.open(StandardProtocolFamily.UNIX).apply {
        dir.mkdirs()
        bind(UnixDomainSocketAddress.of(File(dir, "t.sock").toPath()))
    }
    private val client: SocketChannel =
        SocketChannel.open(UnixDomainSocketAddress.of(File(dir, "t.sock").toPath()))
    private val accepted: SocketChannel = server.accept()

    @After
    fun clean() {
        client.close()
        accepted.close()
        server.close()
        dir.deleteRecursively()
    }

    @Test
    fun `a frame survives the round trip`() {
        val payload = """{"id":"1","type":"init"}""".toByteArray()
        writeFrame(client, payload)
        assertArrayEquals(payload, readFrame(accepted))
    }

    @Test
    fun `the length is little endian on the wire`() {
        writeFrame(client, ByteArray(0x0102))

        val header = ByteBuffer.allocate(4)
        while (header.hasRemaining()) accepted.read(header)
        header.flip()
        // 0x0102 little-endian: 02 01 00 00 — reading it big-endian, which is
        // ByteBuffer's default, is what a careless implementation does.
        val bigEndian = header.int
        assertEquals(0x0102, Integer.reverseBytes(bigEndian))
        assertTrue(bigEndian != 0x0102)
    }

    @Test
    fun `a closed peer reads as no frame rather than a hang`() {
        client.close()
        assertNull(readFrame(accepted))
    }
}
