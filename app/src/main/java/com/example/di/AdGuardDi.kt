package com.example.di

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.example.ai.GeminiSecurityLabService
import com.example.data.AdGuardRepository
import com.example.engine.FilterEngine
import com.example.ui.AdGuardViewModel
import com.example.vpn.VpnController

/**
 * Dependency Injection container mimicking Hilt/Dagger structure.
 * Provides clean Singleton scopes, constructor injection, and ViewModelProvider.Factory.
 */
class AdGuardAppContainer(private val context: Context) {

    // Singleton: Low-level Packet & Rule Filter Engine
    val filterEngine: FilterEngine by lazy {
        FilterEngine()
    }

    // Singleton: Android VpnService controller & packet inspector
    val vpnController: VpnController by lazy {
        VpnController(context, filterEngine)
    }

    // Singleton: Central AdGuard data repository
    val repository: AdGuardRepository by lazy {
        AdGuardRepository(filterEngine, vpnController)
    }

    // Singleton: Gemini AI Security & Science Lab
    val geminiSecurityLab: GeminiSecurityLabService by lazy {
        GeminiSecurityLabService()
    }

    // ViewModel Factory
    fun provideViewModelFactory(): ViewModelProvider.Factory {
        return object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                if (modelClass.isAssignableFrom(AdGuardViewModel::class.java)) {
                    return AdGuardViewModel(repository, geminiSecurityLab, vpnController) as T
                }
                throw IllegalArgumentException("Unknown ViewModel class: ${modelClass.name}")
            }
        }
    }
}
