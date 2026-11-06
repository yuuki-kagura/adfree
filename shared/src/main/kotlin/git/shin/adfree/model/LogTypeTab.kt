package git.shin.adfree.model

import git.shin.adfree.l10n.L10n
import git.shin.adfree.l10n.Strings

/**
 * The log's request-type tabs — AdGuard for Windows puts these across the top
 * of its filtering log, and every row belongs to exactly one of them.
 *
 * The strings in [types] are the names the core writes
 * (`rust/src/events.rs::req_type::name`), which is the single place a resource
 * is folded onto a tab: a `subdocument` and a `document` arrive already
 * merged, as do `xmlhttprequest` and `xhr`. Nothing here re-derives that.
 */
enum class LogTypeTab(val key: String, val labelKey: String, val types: Set<String>) {
    ALL("all", Strings.log_tab_all, emptySet()),
    HTML("html", Strings.log_tab_html, setOf("document")),
    CSS("css", Strings.log_tab_css, setOf("stylesheet")),
    JS("js", Strings.log_tab_js, setOf("script")),
    AJAX("ajax", Strings.log_tab_ajax, setOf("xhr")),
    IMAGE("image", Strings.log_tab_image, setOf("image")),
    MEDIA("media", Strings.log_tab_media, setOf("media")),
    DNS("dns", Strings.log_tab_dns, setOf("dns")),
    CONNECTION("connection", Strings.log_tab_connection, setOf("connection")),

    /**
     * Everything with no tab of its own: fonts and websockets, the `other` the
     * core falls back to, and rows written before a request ever had a type —
     * which is not the same as having no type, and is why they are not dropped.
     */
    OTHER("other", Strings.log_tab_other, setOf("font", "websocket", "other")),
    ;

    /** Whether a row of type [type] belongs to this tab. */
    fun matches(type: String?): Boolean = when (this) {
        ALL -> true
        OTHER -> type.isNullOrBlank() || !claimed.contains(type)
        else -> types.contains(type)
    }

    companion object {
        /** The types some named tab already takes, so `Other` can take the rest. */
        private val claimed: Set<String> = entries
            .filter { it != ALL && it != OTHER }
            .flatMap { it.types }
            .toSet()

        fun of(key: String): LogTypeTab = entries.firstOrNull { it.key == key } ?: ALL

        /** Every tab in display order, with `All` first. */
        val ordered: List<LogTypeTab> = entries.toList()
    }
}

/**
 * What the Type column shows: the kind of resource the request was, in the
 * app's language. An unknown name is reported as `Other` rather than the raw
 * core string, because the column is read next to the tabs that group it.
 */
fun requestTypeLabel(type: String?): String = when (type?.lowercase()) {
    null, "", "other" -> L10n.get(Strings.req_type_other)
    "document" -> L10n.get(Strings.req_type_document)
    "stylesheet" -> L10n.get(Strings.req_type_stylesheet)
    "script" -> L10n.get(Strings.req_type_script)
    "xhr" -> L10n.get(Strings.req_type_xhr)
    "image" -> L10n.get(Strings.req_type_image)
    "font" -> L10n.get(Strings.req_type_font)
    "media" -> L10n.get(Strings.req_type_media)
    "websocket" -> L10n.get(Strings.req_type_websocket)
    "dns" -> L10n.get(Strings.req_type_dns)
    "connection" -> L10n.get(Strings.req_type_connection)
    else -> L10n.get(Strings.req_type_other)
}
