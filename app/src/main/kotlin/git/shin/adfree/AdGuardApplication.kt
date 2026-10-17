package git.shin.adfree

import android.app.Application
import git.shin.adfree.di.AdGuardAppContainer

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
        // Load the filter/script state from disk and sync the configuration to
        // the core.
        container.repository.loadFilterState()
        container.repository.loadScriptsState()
        // The switches the user left on come back before the engine is told
        // what to do: HTTPS filtering and bypass blocking depend on them.
        container.repository.loadSettings()
        container.syncConfigToEngine()
    }

    companion object {
        lateinit var instance: AdGuardApplication
            private set
    }
}
