package git.shin.adfree

import android.app.Application
import git.shin.adfree.di.AdGuardAppContainer
import git.shin.adfree.l10n.L10n
import git.shin.adfree.ui.Localization
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import java.util.Locale

class AdGuardApplication : Application() {

    lateinit var container: AdGuardAppContainer
        private set

    private val l10nScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    override fun onCreate() {
        super.onCreate()
        instance = this
        container = AdGuardAppContainer(this)
        // The shared string tables follow the device locale until the user
        // picks a language in the app; the collector below keeps them in step.
        L10n.systemLanguage = resources.configuration.locales
            .takeIf { !it.isEmpty }?.get(0)?.language?.lowercase(Locale.ROOT) ?: "en"
        L10n.language = container.repository.settings.value.appLanguage
        l10nScope.launch {
            container.repository.settings
                .map { it.appLanguage }
                .distinctUntilChanged()
                .collect { L10n.language = it }
        }
        // Load the persisted CA (or mint the first one) before anything is
        // relayed: HTTPS filtering is armed by the configuration, and without
        // a CA the engine cannot terminate TLS - it would relay port 443
        // unfiltered instead of filtering it.
        container.coreEngine.ensureCa()
        // Rust owns the persisted state: hydrate the flows from it, then
        // rebuild the engine from the same records. Hydration also starts the
        // asynchronous filter/script file refresh.
        container.repository.hydrateState()
        container.applyConfig()
        // Rust owns the language choice; mirror it into AppCompat's per-app
        // locales before the first Activity attaches.
        Localization.apply(container.repository.settings.value.appLanguage)
    }

    companion object {
        lateinit var instance: AdGuardApplication
            private set
    }
}
