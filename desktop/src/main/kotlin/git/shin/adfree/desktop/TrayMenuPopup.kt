package git.shin.adfree.desktop

import java.awt.BasicStroke
import java.awt.Color
import java.awt.Dimension
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.Insets
import java.awt.Point
import java.awt.Rectangle
import java.awt.RenderingHints
import java.awt.Shape
import java.awt.event.KeyEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.awt.event.WindowAdapter
import java.awt.event.WindowEvent
import java.awt.geom.RoundRectangle2D
import javax.swing.AbstractAction
import javax.swing.JComponent
import javax.swing.JWindow
import javax.swing.KeyStroke
import javax.swing.SwingUtilities
import javax.swing.border.EmptyBorder

/**
 * The tray menu, drawn by us.
 *
 * KDE hands a StatusNotifierItem's right click to its DBusMenu importer, which
 * opens an empty popup for a non-Qt item on this desktop. Plasma's documented
 * escape hatch is to ask the app to draw the menu itself
 * (`Menu = /NO_DBUSMENU` then `ContextMenu(x, y)`), so this is that menu:
 * a window of its own at the click position, painted in the colours of the
 * user's theme so it reads as part of the desktop.
 *
 * It is a plain window rather than a `JPopupMenu` because a Swing popup is
 * override-redirect: the window manager never focuses it, so it never gets the
 * focus-out that would close it when the click lands somewhere else, and the
 * menu stayed on screen until an entry was chosen.
 */
internal fun showTrayMenu(
    x: Int,
    y: Int,
    paused: Boolean,
    onCommand: (TrayCommand) -> Unit,
) {
    SwingUtilities.invokeLater {
        try {
            // One menu at a time: a second right click replaces the first
            // instead of leaving a window nobody owns.
            closeTrayMenu()
            val theme = kdeMenuTheme()
            val window = JWindow()
            var catcher: JWindow? = null
            val close = {
                window.dispose()
                catcher?.dispose()
                catcher = null
                openTrayMenu = null
            }
            val panel = MenuPanel(theme, trayMenuEntries(paused)) { command ->
                close()
                onCommand(command)
            }
            window.contentPane.add(panel)
            window.isAlwaysOnTop = true
            window.pack()
            place(window, panel.preferredSize, x, y)
            window.shape = panel.roundShape()
            // The click that dismisses a menu goes to whatever is under it, so
            // the dismissal is caught by a clear full-screen layer: the window
            // manager never focuses our menu (focus stealing prevention), so
            // waiting for a focus-out would leave the menu on screen forever.
            // The layer has to stay above the ordinary windows to see those
            // clicks at all, which is why it is cut open where the menu is.
            val dismisser = clickCatcher(window.bounds, close)
            catcher = dismisser
            dismisser.isVisible = true
            window.addWindowFocusListener(
                object : WindowAdapter() {
                    override fun windowLostFocus(e: WindowEvent) = close()
                },
            )
            window.rootPane
                .getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "close")
            window.rootPane.actionMap.put("close", object : AbstractAction() {
                override fun actionPerformed(e: java.awt.event.ActionEvent) = close()
            })
            window.isVisible = true
            window.toFront()
            window.requestFocus()
            openTrayMenu = close
        } catch (e: Throwable) {
            System.err.println("[desktop] tray: the menu could not be shown: $e")
        }
    }
}

/** The open menu's own "make it go away", if there is one. */
@Volatile
private var openTrayMenu: (() -> Unit)? = null

/** Closes the menu that is on screen, if any. Safe to call from any thread. */
internal fun closeTrayMenu() {
    val open = openTrayMenu ?: return
    openTrayMenu = null
    if (SwingUtilities.isEventDispatchThread()) {
        open()
    } else {
        SwingUtilities.invokeLater(open)
    }
}

/**
 * A transparent, unfocusable full-screen window that turns any click anywhere
 * into "close the menu", with a hole where the menu is: the window manager puts
 * it above the menu whatever the mapping order, and a click on a row has to
 * reach the row rather than the layer.
 */
private fun clickCatcher(hole: Rectangle, onDismiss: () -> Unit): JWindow {
    val catcher = JWindow()
    val screen = java.awt.GraphicsEnvironment
        .getLocalGraphicsEnvironment()
        .getDefaultScreenDevice()
        .defaultConfiguration
        .bounds
    catcher.setBounds(screen)
    // Clicks land on the shape, not on the window's rectangle: cutting the menu
    // out of it is what lets a row be clicked.
    val whole = java.awt.geom.Area(Rectangle(screen))
    whole.subtract(
        java.awt.geom.Area(
            Rectangle(hole.x - screen.x, hole.y - screen.y, hole.width, hole.height),
        ),
    )
    runCatching { catcher.shape = whole }
    catcher.isAlwaysOnTop = true
    catcher.focusableWindowState = false
    catcher.background = Color(0, 0, 0, 0)
    // A fully transparent X window can be treated as click-through; one that is
    // invisible but present always receives the click.
    runCatching { catcher.opacity = 0.01f }
    catcher.addMouseListener(
        object : MouseAdapter() {
            override fun mousePressed(e: MouseEvent) = onDismiss()
        },
    )
    return catcher
}

/**
 * Opens above the cursor when the screen has no room below, the way a panel
 * menu behaves, and stays inside the screen either way.
 */
private fun place(window: JWindow, size: Dimension, x: Int, y: Int) {
    val screen = java.awt.GraphicsEnvironment
        .getLocalGraphicsEnvironment()
        .getDefaultScreenDevice()
        .defaultConfiguration
        .bounds
    var left = x
    var top = y
    if (left + size.width > screen.x + screen.width) left = screen.x + screen.width - size.width
    if (top + size.height > screen.y + screen.height) top -= size.height
    window.setLocation(left.coerceAtLeast(screen.x), top.coerceAtLeast(screen.y))
}

private class MenuPanel(
    private val theme: MenuTheme,
    entries: List<TrayEntry>,
    private val onChoose: (TrayCommand) -> Unit,
) : JComponent() {
    private val padding = 6
    private val radius = 10
    private val rows = buildRows(entries)
    private var hovered = -1

    init {
        font = theme.font
        border = EmptyBorder(padding, padding, padding, padding)
        isOpaque = false
        val metrics = getFontMetrics(theme.font)
        val labelWidth = rows.maxOf { if (it.entry.command == null) 0 else metrics.stringWidth(it.entry.label) }
        val width = labelWidth + 2 * (padding + 16) + 8
        preferredSize = Dimension(width, rows.sumOf { it.height } + 2 * padding)
        addMouseListener(
            object : MouseAdapter() {
                override fun mouseReleased(e: MouseEvent) = choose(rowAt(e.point))
            },
        )
        addMouseMotionListener(
            object : MouseAdapter() {
                override fun mouseMoved(e: MouseEvent) = hover(rowAt(e.point))

                override fun mouseDragged(e: MouseEvent) = hover(rowAt(e.point))
            },
        )
        addMouseListener(
            object : MouseAdapter() {
                override fun mouseExited(e: MouseEvent) = hover(-1)
            },
        )
    }

    fun roundShape(): Shape = RoundRectangle2D.Float(
        0f,
        0f,
        width.toFloat(),
        height.toFloat(),
        radius.toFloat(),
        radius.toFloat(),
    )

    override fun paintComponent(g: Graphics) {
        val g2 = g.create() as Graphics2D
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON)
            g2.color = theme.panel
            g2.fillRect(0, 0, width, height)
            for ((index, row) in rows.withIndex()) {
                paintRow(g2, row, index == hovered)
            }
            g2.color = theme.border
            g2.stroke = BasicStroke(1f)
            g2.drawRoundRect(0, 0, width - 1, height - 1, radius, radius)
        } finally {
            g2.dispose()
        }
    }

    private fun paintRow(g2: Graphics2D, row: Row, hovered: Boolean) {
        val entry = row.entry
        if (entry.command == null) {
            val y = row.top + row.height / 2
            g2.color = theme.separator
            g2.stroke = BasicStroke(1f)
            g2.drawLine(padding + 6, y, width - padding - 6, y)
            return
        }
        val selected = hovered && entry.enabled
        if (selected) {
            g2.color = theme.accent
            g2.fillRoundRect(
                padding - 2,
                row.top,
                width - 2 * padding + 4,
                row.height,
                radius - 2,
                radius - 2,
            )
        }
        g2.font = theme.font
        g2.color = when {
            selected -> theme.accentText
            entry.enabled -> theme.text
            else -> theme.disabled
        }
        val metrics = g2.fontMetrics
        val baseline = row.top + (row.height + metrics.ascent - metrics.descent) / 2
        g2.drawString(entry.label, padding + 12, baseline)
    }

    private fun rowAt(point: Point): Int {
        val local = Point(point.x, point.y)
        return rows.indexOfFirst { local.y >= it.top && local.y < it.top + it.height }
    }

    private fun hover(index: Int) {
        val candidate = rows.getOrNull(index)?.takeIf { it.entry.command != null && it.entry.enabled }
        val next = if (candidate == null) -1 else index
        if (next != hovered) {
            hovered = next
            cursor = java.awt.Cursor.getPredefinedCursor(
                if (next >= 0) java.awt.Cursor.HAND_CURSOR else java.awt.Cursor.DEFAULT_CURSOR,
            )
            repaint()
        }
    }

    private fun choose(index: Int) {
        val row = rows.getOrNull(index) ?: return
        val command = row.entry.command ?: return
        if (!row.entry.enabled) return
        onChoose(command)
    }

    private data class Row(val entry: TrayEntry, val top: Int, val height: Int)

    private fun buildRows(entries: List<TrayEntry>): List<Row> {
        val metrics = getFontMetrics(theme.font)
        val rowHeight = metrics.height + 12
        val separatorHeight = 9
        var top = padding
        return entries.map { entry ->
            val height = if (entry.command == null) separatorHeight else rowHeight
            Row(entry, top, height).also { top += height }
        }
    }

    override fun getInsets(): Insets = Insets(padding, padding, padding, padding)

    /** Only the panel itself is hit-testable; the window adds nothing. */
    override fun contains(x: Int, y: Int): Boolean = Rectangle(0, 0, width, height).contains(x, y)
}

/** The palette a menu is drawn with, without needing a display. */
internal fun menuThemeForTest(): MenuTheme = kdeMenuTheme()
