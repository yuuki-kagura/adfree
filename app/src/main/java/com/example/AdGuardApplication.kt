package com.example

import android.app.Application
import com.example.di.AdGuardAppContainer

class AdGuardApplication : Application() {

    lateinit var container: AdGuardAppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        instance = this
        container = AdGuardAppContainer(this)
    }

    companion object {
        lateinit var instance: AdGuardApplication
            private set
    }
}
