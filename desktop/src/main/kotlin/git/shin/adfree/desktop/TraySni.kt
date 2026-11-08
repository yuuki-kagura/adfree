package git.shin.adfree.desktop

import git.shin.adfree.l10n.L10n
import git.shin.adfree.l10n.Strings
import java.awt.RenderingHints
import java.awt.image.BufferedImage
import javax.imageio.ImageIO
import kotlinx.coroutines.channels.Channel
import org.freedesktop.dbus.Struct
import org.freedesktop.dbus.annotations.DBusInterfaceName
import org.freedesktop.dbus.annotations.Position
import org.freedesktop.dbus.connections.impl.DBusConnection
import org.freedesktop.dbus.connections.impl.DBusConnectionBuilder
import org.freedesktop.dbus.interfaces.DBusInterface
import org.freedesktop.dbus.messages.DBusSignal
import org.freedesktop.dbus.types.UInt32
import org.freedesktop.dbus.types.Variant

/**
 * The status icon, on the protocol KDE actually listens to.
 *
 * AWT's tray (`SystemTray`, and therefore Compose's `Tray`) is XEmbed. On a
 * Wayland session the icon is drawn by KDE's `xembedsniproxy`, which paints the
 * bitmap and then delivers no clicks back to us: left click, right click and
 * the popup menu are all unreachable, and no change to the menu definition can
 * fix that because the events never arrive.
 *
 * The native path is StatusNotifierItem over the session bus: icon, clicks and
 * notifications are D-Bus properties and calls. [start] returns null when the
 * session has no StatusNotifier host (plain X11 without a tray owner), which
 * leaves the AWT path in charge there.
 */
class TraySni private constructor(
    private val connection: DBusConnection,
    private val item: Item,
) {
    /** The bus name the icon was registered under, for tests and logs. */
    val service: String get() = connection.uniqueName

    /** Clicks arrive on D-Bus threads; the app drains this on its own. */
    val requests = Channel<TrayRequest>(Channel.CONFLATED)

    fun setPaused(paused: Boolean) {
        if (item.paused == paused) return
        item.paused = paused
        // The tray host painted the icon once, at registration: without these
        // signals the icon keeps saying "filtering" after the app stopped.
        runCatching {
            connection.sendMessage(
                StatusNotifierItem.NewTitle(ITEM_PATH, if (paused) "AdFree (paused)" else "AdFree"),
            )
            connection.sendMessage(
                StatusNotifierItem.NewIcon(ITEM_PATH),
            )
        }.onFailure { e ->
            // The icon saying the wrong thing is worth a line in the log.
            System.err.println("[desktop] tray: could not announce the new state: $e")
        }
    }

    /** A desktop notification, for the sessions where the tray has no bubble. */
    fun notify(summary: String, body: String) {
        runCatching {
            connection
                .getRemoteObject(
                    "org.freedesktop.Notifications",
                    "/org/freedesktop/Notifications",
                    Notifications::class.java,
                )
                .Notify("AdFree", UInt32(0), "", summary, body, emptyList(), emptyMap(), -1)
        }
    }

    fun close() {
        runCatching { connection.close() }
    }

    companion object {
        /** Plasma's marker for "there is no DBusMenu here". */
        private const val NO_DBUSMENU = "/NO_DBUSMENU"

        /** The object path the icon's properties, methods and signals live at. */
        private const val ITEM_PATH = "/StatusNotifierItem"

        /**
         * Registers the icon. Null when this session has no StatusNotifier
         * host, so the caller can fall back to the AWT tray.
         */
        fun start(): TraySni? = try {
            val pixmaps = loadPixmaps()
            if (pixmaps.isEmpty()) {
                System.err.println("[desktop] tray: the app icon could not be read")
                null
            } else {
                val connection = connectSession()
                val item = Item(pixmaps)
                connection.exportObject(item)
                // The tray host resolves anything we export against the name we
                // were registered by, and every native item registers its
                // *unique* name (`:1.42`); a well-known one leaves Plasma
                // unable to find the icon's other objects.
                connection
                    .getRemoteObject(
                        "org.kde.StatusNotifierWatcher",
                        "/StatusNotifierWatcher",
                        StatusNotifierWatcher::class.java,
                    )
                    .RegisterStatusNotifierItem(connection.uniqueName)
                TraySni(connection, item).also { tray ->
                    item.onRequest = { tray.requests.trySend(it) }
                    println("[desktop] tray: StatusNotifierItem registered as ${connection.uniqueName}")
                }
            }
        } catch (e: Throwable) {
            // No StatusNotifier host (plain X11, no session bus): the AWT tray
            // is what those sessions get, so this is a fallback, not a fault.
            System.err.println("[desktop] tray: falling back to the AWT tray: ${e.message}")
            null
        }

        /**
         * A systemd `--system` unit (the escalated instance) does not inherit
         * the session bus address, so fall back to the socket the login session
         * always leaves behind.
         */
        private fun connectSession(): DBusConnection = runCatching {
            DBusConnectionBuilder.forSessionBus().build()
        }.getOrElse {
            val runtime = System.getenv("XDG_RUNTIME_DIR") ?: "/run/user/${userId()}"
            DBusConnectionBuilder.forAddress("unix:path=$runtime/bus").build()
        }

        private fun userId(): String = runCatching {
            java.nio.file.Files.getAttribute(java.nio.file.Path.of("/proc/self"), "unix:uid").toString()
        }.getOrElse { "1000" }

        /** ARGB32, largest first, as the icon spec asks. */
        private fun loadPixmaps(): List<IconPixmap> = runCatching {
            val png = TraySni::class.java.getResourceAsStream("/icon/adfree.png")
                ?: return@runCatching emptyList()
            val source = png.use { ImageIO.read(it) } ?: return@runCatching emptyList()
            val glyph = cropToGlyph(source)
            // One pixmap per size a tray may ask for: a host that finds no
            // match draws the nearest smaller one, which is what made the icon
            // look smaller than its neighbours.
            listOf(128, 96, 64, 48, 32, 24, 22, 16).map { pixmap(glyph, it) }
        }.getOrElse { emptyList() }

        /**
         * The app icon is a glyph on a wide dark badge; at 22 px the badge is
         * most of what a tray shows, and the shape inside it shrinks to a dot.
         * The tray gets the glyph alone: cropped to what is actually drawn, so
         * there is no padding to eat the space.
         */
        private fun cropToGlyph(source: BufferedImage): BufferedImage {
            var left = source.width
            var top = source.height
            var right = 0
            var bottom = 0
            for (y in 0 until source.height) {
                for (x in 0 until source.width) {
                    val argb = source.getRGB(x, y)
                    val alpha = (argb ushr 24) and 0xFF
                    if (alpha < 8) continue
                    val red = (argb ushr 16) and 0xFF
                    val green = (argb ushr 8) and 0xFF
                    val blue = argb and 0xFF
                    // The badge is near-black (luminance ~13); everything
                    // brighter is the mark.
                    if ((299 * red + 587 * green + 114 * blue) / 1000 < 60) continue
                    if (x < left) left = x
                    if (y < top) top = y
                    if (x > right) right = x
                    if (y > bottom) bottom = y
                }
            }
            if (right <= left || bottom <= top) return source
            return source.getSubimage(left, top, right - left + 1, bottom - top + 1)
        }

        /**
         * The same shape in AdGuard's "off" yellow, painted on the glyph's own
         * shading: the tray says at a glance whether filtering is on, and the
         * icon stays the mark rather than a yellow tile.
         */
        fun paused(pixmaps: List<IconPixmap>): List<IconPixmap> = pixmaps.map { pixmap ->
            val bytes = pixmap.data.copyOf()
            var brightest = 1
            for (index in bytes.indices step 4) {
                val luminance = luminance(bytes, index)
                if (luminance > brightest) brightest = luminance
            }
            for (index in bytes.indices step 4) {
                if ((bytes[index].toInt() and 0xFF) == 0) continue
                // Only the mark is repainted: the few dark pixels the crop keeps
                // around it are the icon's own badge, and tinting those put a
                // faint yellow square back behind the shape.
                if (luminance(bytes, index) < 60) continue
                // Keep the glyph's shading, or the yellow flattens the mark
                // into a blob at 22 px.
                val shade = 35 + 65 * luminance(bytes, index) / brightest
                bytes[index + 1] = (255 * shade / 100).coerceIn(0, 255).toByte()
                bytes[index + 2] = (197 * shade / 100).coerceIn(0, 255).toByte()
                bytes[index + 3] = (61 * shade / 100).coerceIn(0, 255).toByte()
            }
            IconPixmap(pixmap.width, pixmap.height, bytes)
        }

        private fun luminance(bytes: ByteArray, index: Int): Int {
            val red = bytes[index + 1].toInt() and 0xFF
            val green = bytes[index + 2].toInt() and 0xFF
            val blue = bytes[index + 3].toInt() and 0xFF
            return (299 * red + 587 * green + 114 * blue) / 1000
        }

        /**
         * Aspect is kept: a tray slot is square, and stretching the mark to fill
         * it would widen a shield into an egg.
         */
        private fun pixmap(source: BufferedImage, size: Int): IconPixmap {
            val scale = minOf(size.toDouble() / source.width, size.toDouble() / source.height)
            val width = (source.width * scale).toInt().coerceAtLeast(1)
            val height = (source.height * scale).toInt().coerceAtLeast(1)
            val scaled = BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB)
            scaled.createGraphics().apply {
                setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR)
                drawImage(source, (size - width) / 2, (size - height) / 2, width, height, null)
                dispose()
            }
            val bytes = ByteArray(size * size * 4)
            var i = 0
            for (y in 0 until size) {
                for (x in 0 until size) {
                    val argb = scaled.getRGB(x, y)
                    bytes[i++] = (argb ushr 24).toByte()
                    bytes[i++] = (argb ushr 16).toByte()
                    bytes[i++] = (argb ushr 8).toByte()
                    bytes[i++] = argb.toByte()
                }
            }
            return IconPixmap(size, size, bytes)
        }
    }

    /** `(iiay)`: one square of ARGB32 pixels in network byte order. */
    class IconPixmap(
        @field:Position(0) val width: Int,
        @field:Position(1) val height: Int,
        @field:Position(2) val data: ByteArray,
    ) : Struct()

    @DBusInterfaceName("org.kde.StatusNotifierItem")
    interface StatusNotifierItem : DBusInterface {
        fun Activate(x: Int, y: Int)

        fun SecondaryActivate(x: Int, y: Int)

        fun ContextMenu(x: Int, y: Int)

        fun Scroll(delta: Int, orientation: String)

        /**
         * Signals are what make the host repaint; a property alone is not
         * enough. The name and the interface come from the class: dbus-java
         * reads them off a signal nested in the interface it belongs to.
         *
         * Every constructor takes the object path first, because that is the
         * argument dbus-java drops when it derives the body signature. Without
         * it the body carries no signature at all and the bus daemon throws the
         * signal away without a word.
         */
        class NewTitle(path: String, val title: String) : DBusSignal(ENDIANESS, path, title)

        /**
         * Plasma repaints the icon on this signal and then re-reads the
         * properties, so it carries no payload. (The spec also names
         * `NewIconPixmap`; this host does not listen for it.)
         */
        class NewIcon(path: String) : DBusSignal(ENDIANESS, path)

        companion object {
            private const val ENDIANESS: Byte = 0
        }
    }

    @DBusInterfaceName("org.kde.StatusNotifierWatcher")
    interface StatusNotifierWatcher : DBusInterface {
        fun RegisterStatusNotifierItem(service: String)
    }

    @DBusInterfaceName("org.freedesktop.DBus.Properties")
    interface Properties : DBusInterface {
        fun Get(interfaceName: String, propertyName: String): Variant<*>

        fun GetAll(interfaceName: String): Map<String, Variant<*>>

        fun Set(interfaceName: String, propertyName: String, value: Variant<*>)
    }

    @DBusInterfaceName("org.freedesktop.Notifications")
    interface Notifications : DBusInterface {
        @Suppress("LongParameterList")
        fun Notify(
            appName: String,
            replacesId: UInt32,
            appIcon: String,
            summary: String,
            body: String,
            actions: List<String>,
            hints: Map<String, Variant<*>>,
            expireTimeout: Int,
        ): UInt32
    }

    private class Item(
        val pixmaps: List<IconPixmap>,
        val pausedPixmaps: List<IconPixmap> = paused(pixmaps),
    ) : StatusNotifierItem, Properties {
        @Volatile
        var paused = false

        @Volatile
        var onRequest: (TrayRequest) -> Unit = {}

        override fun isRemote() = false

        override fun getObjectPath() = ITEM_PATH

        override fun Activate(x: Int, y: Int) = onRequest(TrayRequest.Command(TrayCommand.OPEN))

        override fun SecondaryActivate(x: Int, y: Int) = onRequest(TrayRequest.Command(TrayCommand.OPEN))

        /**
         * The menu is ours to draw, not KDE's: `/NO_DBUSMENU` is Plasma's own
         * escape hatch (it logs "DBusMenu disabled for this application" and
         * falls back to this call), and it is the only path where the click
         * carries the cursor position. KDE's DBusMenu importer builds the menu
         * from a layout we can serve, but on this desktop it renders nothing at
         * all for a non-Qt item, which is what the old AWT tray looked like too.
         */
        override fun ContextMenu(x: Int, y: Int): Unit {
            println("[desktop] tray: menu requested at $x,$y")
            onRequest(TrayRequest.Menu(x, y))
        }

        override fun Scroll(delta: Int, orientation: String) = Unit

        override fun GetAll(interfaceName: String): Map<String, Variant<*>> = mapOf(
            "Category" to Variant("ApplicationStatus", "s"),
            "Id" to Variant("adfree", "s"),
            "Title" to Variant(if (paused) "AdFree (paused)" else "AdFree", "s"),
            // Always Active: the tray host *hides* a Passive item, so pausing
            // that way makes the icon vanish instead of greying out.
            "Status" to Variant("Active", "s"),
            "WindowId" to Variant(UInt32(0), "u"),
            "IconName" to Variant("", "s"),
            "IconPixmap" to Variant(if (paused) pausedPixmaps else pixmaps, "a(iiay)"),
            "OverlayIconName" to Variant("", "s"),
            "OverlayIconPixmap" to Variant(emptyList<IconPixmap>(), "a(iiay)"),
            "AttentionIconName" to Variant("", "s"),
            "AttentionIconPixmap" to Variant(emptyList<IconPixmap>(), "a(iiay)"),
            "AttentionMovieName" to Variant("", "s"),
            "ItemIsMenu" to Variant(false, "b"),
            "Menu" to Variant(org.freedesktop.dbus.ObjectPath("adfree", NO_DBUSMENU), "o"),
        )

        override fun Get(interfaceName: String, propertyName: String): Variant<*> =
            GetAll(interfaceName)[propertyName] ?: Variant("", "s")

        override fun Set(interfaceName: String, propertyName: String, value: Variant<*>) = Unit
    }
}

/** Everything the tray asks the app to do, in the order it asks. */
sealed interface TrayRequest {
    /** A menu item was chosen. */
    data class Command(val command: TrayCommand) : TrayRequest

    /** The icon was right-clicked at this screen position. */
    data class Menu(val x: Int, val y: Int) : TrayRequest
}

/** What a click on the tray icon asks for. */
enum class TrayCommand { OPEN, LOG, PAUSE_30S, PAUSE_1H, RESUME, EXIT }

/** The labels and enabled state of the tray menu, shared by both trays. */
internal fun trayMenuEntries(paused: Boolean): List<TrayEntry> = listOf(
    TrayEntry(TrayCommand.OPEN, L10n.get(Strings.tray_open)),
    TrayEntry(TrayCommand.LOG, "Filtering log"),
    TrayEntry.separator(),
    TrayEntry(TrayCommand.PAUSE_30S, L10n.get(Strings.tray_pause_30s), enabled = !paused),
    TrayEntry(TrayCommand.PAUSE_1H, L10n.get(Strings.tray_pause_1h), enabled = !paused),
    TrayEntry(TrayCommand.RESUME, L10n.get(Strings.tray_resume), enabled = paused),
    TrayEntry.separator(),
    TrayEntry(TrayCommand.EXIT, L10n.get(Strings.tray_exit)),
)

/** One row of the tray menu; a separator carries no command. */
internal data class TrayEntry(
    val command: TrayCommand?,
    val label: String,
    val enabled: Boolean = true,
) {
    companion object {
        fun separator() = TrayEntry(null, "", false)
    }
}
