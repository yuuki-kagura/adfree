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
        // // Load built-in lists and sync the configuration to the core.
        container.repository.loadBuiltInFilterLists()
        container.syncConfigToEngine()
    }

    companion object {
        lateinit var instance: AdGuardApplication
            private set
    }
}
