package git.shin.adfree.ui

import android.content.Context
import androidx.annotation.PluralsRes
import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource

/**
 * Wording that is resolved against the current locale at render time.
 *
 * The ViewModel and repository hold [UiText] instead of formatted strings so
 * switching the app language re-renders messages without touching state.
 */
sealed interface UiText {

    fun resolve(context: Context): String

    @Composable
    @ReadOnlyComposable
    fun asString(): String

    data class Resource(@StringRes val id: Int) : UiText {
        override fun resolve(context: Context): String = context.getString(id)

        @Composable
        @ReadOnlyComposable
        override fun asString(): String = stringResource(id)
    }

    /** A template resource with positional arguments (names, counts, domains). */
    data class Formatted(@StringRes val id: Int, val args: List<Any>) : UiText {
        constructor(@StringRes id: Int, vararg args: Any) : this(id, args.toList())

        override fun resolve(context: Context): String = context.getString(id, *args.toTypedArray())

        @Composable
        @ReadOnlyComposable
        override fun asString(): String = stringResource(id, *args.toTypedArray())
    }

    data class Plural(@PluralsRes val id: Int, val count: Int) : UiText {
        override fun resolve(context: Context): String =
            context.resources.getQuantityString(id, count, count)

        @Composable
        @ReadOnlyComposable
        override fun asString(): String = pluralStringResource(id, count, count)
    }

    data class Raw(val value: String) : UiText {
        override fun resolve(context: Context): String = value

        @Composable
        @ReadOnlyComposable
        override fun asString(): String = value
    }
}
