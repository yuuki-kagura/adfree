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
        container.syncConfigToEngine()
    }

    companion object {
        lateinit var instance: AdGuardApplication
            private set
    }
}
