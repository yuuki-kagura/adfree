package git.shin.adfree.ui

import android.content.Context
import android.content.res.Configuration
import android.os.LocaleList
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import git.shin.adfree.model.AppLanguage
import java.util.Locale

/** Per-app locale plumbing backed by AppCompat's persisted locale list. */
object Localization {

    fun locale(language: AppLanguage): Locale? = when (language) {
        AppLanguage.SYSTEM -> null
        AppLanguage.ENGLISH -> Locale.ENGLISH
        AppLanguage.VIETNAMESE -> Locale.forLanguageTag("vi")
    }

    fun apply(language: AppLanguage) {
        val locales = locale(language)
            ?.let { LocaleListCompat.forLanguageTags(it.toLanguageTag()) }
            ?: LocaleListCompat.getEmptyLocaleList()
        if (AppCompatDelegate.getApplicationLocales() != locales) {
            AppCompatDelegate.setApplicationLocales(locales)
        }
    }

    /**
     * A context whose resources follow the chosen language. Services and
     * notifications outlive the Activity, so they resolve wording themselves
     * instead of inheriting the Activity's configuration.
     */
    fun wrap(base: Context, language: AppLanguage): Context {
        val locale = locale(language) ?: return base
        val configuration = Configuration(base.resources.configuration)
        configuration.setLocales(LocaleList(locale))
        return base.createConfigurationContext(configuration)
    }
}
