package git.shin.adfree.l10n

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import git.shin.adfree.model.AppLanguage
import java.io.InputStream
import javax.xml.parsers.DocumentBuilderFactory
import org.w3c.dom.Element

/**
 * The app's string tables, read from the classpath so Android and the desktop
 * host resolve the same keys. [language] is snapshot state: composables that
 * call [Strings]-keyed lookups recompose the moment the user switches the app
 * language, exactly like Android's resource pipeline did.
 */
object L10n {

    /** The in-app language setting; SYSTEM follows [systemLanguage]. */
    var language: AppLanguage by mutableStateOf(AppLanguage.SYSTEM)

    /** The device locale tag ("en", "vi", …), set once by the host. */
    var systemLanguage: String = "en"

    private val default: Map<String, String> = load("l10n/strings-default.xml")

    private val vietnamese: Map<String, String> = load("l10n/strings-vi.xml")

    /** The locale tag the tables are being read in right now. */
    fun locale(): String = when (language) {
        AppLanguage.SYSTEM -> systemLanguage
        AppLanguage.ENGLISH -> "en"
        AppLanguage.VIETNAMESE -> "vi"
    }

    fun get(key: String): String = get(key, locale())

    /** The key's value in an explicit locale, for notifications and services. */
    fun get(key: String, locale: String): String {
        val table = if (locale.startsWith("vi")) vietnamese else default
        return table[key] ?: default[key] ?: key
    }

    /** Fills `%1$s`/`%1$d` positions in the key's value. */
    fun format(key: String, vararg args: Any): String = fill(get(key, locale()), args)

    /** [format] against an explicit locale. */
    fun format(key: String, locale: String, args: Array<out Any>): String =
        fill(get(key, locale), args)

    /**
     * Resolves `%N$s`/`%N$d`/`%N$.1f`/`%%` positionally, like Android's
     * getString. `%1$.1f` is a real format, not literal text: the template
     * scan below only understands the conversion letter, so a precision spec
     * used to leak into the UI as "+%1$.1f%".
     */
    internal fun fill(template: String, args: Array<out Any>): String {
        if (args.isEmpty() && !template.contains("%%")) return template
        if (args.isNotEmpty()) {
            try {
                return java.lang.String.format(java.util.Locale.ROOT, template, *args)
            } catch (_: java.util.IllegalFormatException) {
                // Fall through: a hand-written template may mix a stray '%'
                // with valid positions; the scanner below is forgiving.
            }
        }
        val out = StringBuilder(template.length)
        var i = 0
        while (i < template.length) {
            val c = template[i]
            if (c == '%' && i + 1 < template.length) {
                if (template[i + 1] == '%') {
                    out.append('%')
                    i += 2
                    continue
                }
                var j = i + 1
                val digits = StringBuilder()
                while (j < template.length && template[j].isDigit()) {
                    digits.append(template[j])
                    j++
                }
                if (digits.isNotEmpty() && j < template.length && template[j] == '$') {
                    val conv = if (j + 1 < template.length) template[j + 1] else 's'
                    if (conv in "sdfx") {
                        val value = args.getOrNull(digits.toString().toInt() - 1)
                        out.append(rendered(value, conv))
                        i = j + 2
                        continue
                    }
                }
            }
            out.append(c)
            i++
        }
        return out.toString()
    }

    private fun rendered(value: Any?, conv: Char): String = when {
        value == null -> ""
        conv == 'd' -> (value as? Number)?.toLong()?.toString() ?: value.toString()
        else -> value.toString()
    }

    private fun load(path: String): Map<String, String> {
        val stream: InputStream = L10n::class.java.classLoader.getResourceAsStream(path)
            ?: error("missing string table $path on the classpath")
        return stream.use(::parse)
    }

    private fun parse(stream: InputStream): Map<String, String> {
        val factory = DocumentBuilderFactory.newInstance()
        factory.setNamespaceAware(false)
        val document = factory.newDocumentBuilder().parse(stream)
        val table = LinkedHashMap<String, String>()
        val nodes = document.getElementsByTagName("string")
        for (index in 0 until nodes.length) {
            val element = nodes.item(index) as? Element ?: continue
            val name = element.getAttribute("name")
            if (name.isNotEmpty()) table[name] = unescape(element.textContent.normalizeSpaces())
        }
        return table
    }

    private fun String.normalizeSpaces(): String = replace(Regex("\\s+"), " ").trim()

    /** Undoes Android's resource escapes: `\'`, `\"`, `\n`, `\t`, `\\`, `\@`, `\?`. */
    internal fun unescape(raw: String): String {
        if (!raw.contains('\\')) return raw
        val out = StringBuilder(raw.length)
        var i = 0
        while (i < raw.length) {
            val c = raw[i]
            if (c == '\\' && i + 1 < raw.length) {
                when (val next = raw[i + 1]) {
                    'n' -> out.append('\n')
                    't' -> out.append('\t')
                    'r' -> out.append('\r')
                    '\\', '\'', '"', '@', '?' -> out.append(next)
                    else -> out.append(c).append(next)
                }
                i += 2
            } else {
                out.append(c)
                i++
            }
        }
        return out.toString()
    }
}
