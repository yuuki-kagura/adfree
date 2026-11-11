package git.shin.adfree.model

import java.util.Locale

/**
 * A count written the way a card or a chip can hold it.
 *
 * "136455" is a number nobody reads at a glance and it pushes the label it sits
 * in until the label wraps; "136K" is the same fact in the space it was given.
 * The dot is deliberate and locale-independent: these are counters, not money,
 * and a figure that changes shape with the system language reads as a different
 * number in a screenshot.
 */
object CountFormat {

    /** `999`, `1.2K`, `136K`, `1.2M`, `3.4B`. */
    fun compact(value: Long): String {
        val n = value.coerceAtLeast(0L)
        if (n < 1_000L) return n.toString()
        val steps = arrayOf(
            1_000L to "K",
            1_000_000L to "M",
            1_000_000_000L to "B",
            1_000_000_000_000L to "T",
        )
        var index = 0
        while (index + 1 < steps.size && n >= steps[index + 1].first) index++
        var text = render(n.toDouble() / steps[index].first)
        // 999_999 rounds to "1000K": promote the unit rather than print four
        // digits in a slot sized for three.
        if ((text.toDoubleOrNull() ?: 0.0) >= 999.95 && index + 1 < steps.size) {
            index += 1
            text = render(n.toDouble() / steps[index].first)
        }
        return text + steps[index].second
    }

    /** `3.5 GB`, `12 MB`, `512 KB` — traffic, in the unit a reader thinks in. */
    fun data(bytes: Long): String {
        val n = bytes.coerceAtLeast(0L)
        return when {
            n >= 1L shl 30 -> render(n.toDouble() / (1L shl 30).toDouble()) + " GB"
            n >= 1L shl 20 -> render(n.toDouble() / (1L shl 20).toDouble()) + " MB"
            n >= 1L shl 10 -> render(n.toDouble() / (1L shl 10).toDouble()) + " KB"
            else -> "$n B"
        }
    }

    /** One decimal below a hundred, none above it: `1.2K`, `136K`. */
    private fun render(scaled: Double): String =
        if (scaled >= 99.95) {
            String.format(Locale.ROOT, "%.0f", scaled)
        } else {
            String.format(Locale.ROOT, "%.1f", scaled).trimEnd('0').trimEnd('.')
        }
}
