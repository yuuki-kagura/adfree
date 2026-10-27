package git.shin.adfree

import android.app.Application
import git.shin.adfree.di.AdGuardAppContainer
import git.shin.adfree.ui.Localization

class AdGuardApplication : Application() {

    lateinit var container: AdGuardAppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        instance = this
        container = AdGuardAppContainer(this)
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
