package git.shin.adfree.desktop

import org.freedesktop.dbus.annotations.DBusInterfaceName
import org.freedesktop.dbus.connections.impl.DBusConnection
import org.freedesktop.dbus.connections.impl.DBusConnectionBuilder
import org.freedesktop.dbus.interfaces.DBusInterface
import org.freedesktop.dbus.types.UInt32
import org.freedesktop.dbus.types.Variant
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * The status icon is only a fix if the session bus actually answers its menu
 * calls: the marshalling here (`a(iiay)` icon, `(u(ia{sv}av))` layout) is the
 * part that fails silently, and KDE then draws nothing at all.
 *
 * Both tests skip when the session has no StatusNotifier host — the same case
 * that leaves the AWT tray in charge.
 */
class TraySniTest {

    /** The item's own interface, for the click the tray sends. */
    @DBusInterfaceName("org.kde.StatusNotifierItem")
    interface Item : DBusInterface {
        fun ContextMenu(x: Int, y: Int)
    }

    private var tray: TraySni? = null
    private var connection: DBusConnection? = null

    @Before
    fun startTray() {
        tray = TraySni.start()
    }

    @After
    fun stopTray() {
        tray?.close()
        connection?.close()
    }

    @Test
    fun theIconIsRegisteredWithTheSessionWatcher() {
        val started = tray
        assumeTrue("no StatusNotifier host in this session", started != null)
        assertTrue(
            "the icon should be one registered item: ${registeredItems()}",
            registeredItems().any { it.startsWith(started!!.service) },
        )
    }

    @Test
    fun pausingYellowsTheIconAndTellsTheTray() {
        val started = tray
        assumeTrue("no StatusNotifier host in this session", started != null)
        val conn = connect()
        val props = conn.getRemoteObject(
            started!!.service,
            "/StatusNotifierItem",
            org.freedesktop.dbus.interfaces.Properties::class.java,
        )
        started.setPaused(true)
        val paused = props.GetAll("org.kde.StatusNotifierItem")
        // Active even while paused: the tray host hides Passive items, which
        // would take the icon off the panel instead of greying it.
        assertEquals("Active", paused["Status"]?.value)
        assertEquals("AdFree (paused)", paused["Title"]?.value)
        started.setPaused(false)
        val running = props.GetAll("org.kde.StatusNotifierItem")
        assertEquals("Active", running["Status"]?.value)
        assertEquals("AdFree", running["Title"]?.value)
        // The icon itself changes, or a paused tray looks exactly like a
        // filtering one. A struct on the wire is an array of its fields:
        // `(iiay)` is width, height, pixels.
        assertFalse(
            "the paused icon should differ from the running one",
            greeting(running).contentEquals(greeting(paused)),
        )
        // AdGuard's "off" yellow, on the mark only: the dark pixels the crop
        // keeps around it must stay dark, or the tray shows a yellow square.
        val runningPixels = greeting(running)
        val pausedPixels = greeting(paused)
        var red = 0L
        var green = 0L
        var blue = 0L
        var painted = 0
        for (index in pausedPixels.indices step 4) {
            if ((pausedPixels[index].toInt() and 0xFF) < 128) continue
            val luminance = (
                299 * (runningPixels[index + 1].toInt() and 0xFF) +
                    587 * (runningPixels[index + 2].toInt() and 0xFF) +
                    114 * (runningPixels[index + 3].toInt() and 0xFF)
                ) / 1000
            if (luminance < 60) {
                assertTrue(
                    "the icon's own dark pixels must not be tinted",
                    pausedPixels.copyOfRange(index, index + 4)
                        .contentEquals(runningPixels.copyOfRange(index, index + 4)),
                )
                continue
            }
            red += pausedPixels[index + 1].toInt() and 0xFF
            green += pausedPixels[index + 2].toInt() and 0xFF
            blue += pausedPixels[index + 3].toInt() and 0xFF
            painted++
        }
        assertTrue("the mark has to have pixels", painted > 0)
        assertTrue("yellow, not grey: r=$red g=$green b=$blue", red > green && green > blue)
    }

    private fun greeting(props: Map<String, Variant<*>>): ByteArray {
        // `a(iiay)`: a list of structs, each one an array of its fields in
        // order, so the pixels are the third field.
        val pixmaps = elements(props["IconPixmap"]!!.value)
        val pixels = elements(pixmaps.first())[2]
        return when (pixels) {
            is ByteArray -> pixels
            is List<*> -> pixels.map { (it as Number).toByte() }.toByteArray()
            else -> error("expected pixels, got ${pixels?.javaClass}")
        }
    }

    private fun elements(value: Any?): List<*> = when (value) {
        is List<*> -> value
        is Array<*> -> value.toList()
        else -> error("expected a struct, got ${value?.javaClass}")
    }

    @Test
    fun pausingAnnouncesItselfOnTheBus() {
        val started = tray
        assumeTrue("no StatusNotifier host in this session", started != null)
        val listener = connect()
        val seen = java.util.concurrent.LinkedBlockingQueue<String>()
        listener.addSigHandler(TraySni.StatusNotifierItem.NewTitle::class.java) { signal ->
            seen.offer(signal.title)
        }
        listener.addSigHandler(TraySni.StatusNotifierItem.NewIcon::class.java) { _ ->
            seen.offer("icon")
        }
        started!!.setPaused(true)
        val deadline = System.currentTimeMillis() + 3000
        val received = mutableListOf<String>()
        while (System.currentTimeMillis() < deadline && received.size < 2) {
            seen.poll(200, java.util.concurrent.TimeUnit.MILLISECONDS)?.let { received += it }
        }
        assertTrue(
            "the host has to be told, or the icon never repaints: $received",
            received.any { it.contains("paused") },
        )
        assertTrue("the icon itself is repainted too: $received", received.contains("icon"))
    }

    @Test
    fun theMenuIsOursToDrawAndTheClickCarriesTheCursor() {
        val started = tray
        assumeTrue("no StatusNotifier host in this session", started != null)
        val asRegistrant = started!!.service
        val conn = connect()
        val props = conn.getRemoteObject(
            asRegistrant,
            "/StatusNotifierItem",
            org.freedesktop.dbus.interfaces.Properties::class.java,
        )
        // `GetAll`, like the tray host uses: a single `Get` goes through the
        // framework's property table, which only knows annotated properties.
        val all = props.GetAll("org.kde.StatusNotifierItem")
        val menu = all["Menu"]?.value.toString()
        assertEquals(
            "KDE must be told to hand us the click, not to build the menu itself",
            "/NO_DBUSMENU",
            menu,
        )
        val item = conn.getRemoteObject(asRegistrant, "/StatusNotifierItem", Item::class.java)
        item.ContextMenu(120, 40)
        val request = started!!.requests.tryReceive().getOrNull()
        assertEquals("a right click asks for a menu at the cursor", TrayRequest.Menu(120, 40), request)
    }

    private fun connect(): DBusConnection =
        connection ?: DBusConnectionBuilder.forSessionBus().build().also { connection = it }

    /**
     * What the watcher has accepted, which is the only proof the shell will
     * show the icon.
     */
    private fun registeredItems(): List<String> {
        val props = connect().getRemoteObject(
            "org.kde.StatusNotifierWatcher",
            "/StatusNotifierWatcher",
            org.freedesktop.dbus.interfaces.Properties::class.java,
        )
        return props.Get<List<String>>("org.kde.StatusNotifierWatcher", "RegisteredStatusNotifierItems")
    }
}
