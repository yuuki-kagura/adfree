package git.shin.adfree.ui

import git.shin.adfree.l10n.L10n

/**
 * Wording resolved against [L10n]'s current language at render time.
 *
 * ViewModels and the repository hold [UiText] instead of formatted strings, so
 * switching the app language re-renders messages without touching state:
 * composables that call [asString] read the language snapshot and recompose.
 */
sealed interface UiText {

    fun resolve(): String

    fun asString(): String = resolve()

    /** A key into the string tables. */
    data class Resource(val key: String) : UiText {
        override fun resolve(): String = L10n.get(key)
    }

    /** A template key with positional arguments (names, counts, domains). */
    data class Formatted(val key: String, val args: List<Any>) : UiText {
        constructor(key: String, vararg args: Any) : this(key, args.toList())

        override fun resolve(): String = L10n.format(key, *args.toTypedArray())
    }

    data class Raw(val value: String) : UiText {
        override fun resolve(): String = value
    }
}
