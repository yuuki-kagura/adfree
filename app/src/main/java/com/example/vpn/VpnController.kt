package com.example.vpn

import android.content.Context
import android.content.Intent
import android.net.VpnService
import com.example.engine.FilterEngine
import com.example.model.FilterStatus
import com.example.model.NetworkRequestLog
import com.example.model.ProtocolType
import com.example.model.RequestCategory
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.UUID
import java.util.concurrent.ConcurrentLinkedQueue
import kotlin.random.Random

/**
 * Controller managing VPN lifecycle, packet telemetry batching, and energy optimization.
 * Features:
 * - Telemetry Batching: Groups incoming logs and flushes every 1000ms to reduce CPU wakeups and prevent constant Compose recomposition.
 * - Screen-Off suspension: Halts log dispatching when device screen is turned off.
 * - UI Test Simulation Toggle: Configurable mode for fake test traffic vs 100% real TUN packet inspection.
 */
class VpnController(
    private val context: Context,
    private val filterEngine: FilterEngine
) {
    private val coroutineScope = CoroutineScope(Dispatchers.Default)
    private var trafficSimulationJob: Job? = null
    private var batchFlushJob: Job? = null

    private val _isVpnActive = MutableStateFlow(true)
    val isVpnActive: StateFlow<Boolean> = _isVpnActive.asStateFlow()

    // Simulation toggle requested by user for testing UI
    private val _isSimulationMode = MutableStateFlow(false)
    val isSimulationMode: StateFlow<Boolean> = _isSimulationMode.asStateFlow()

    private val _isScreenOff = MutableStateFlow(false)
    val isScreenOff: StateFlow<Boolean> = _isScreenOff.asStateFlow()

    // Batching buffer for energy-saving telemetry
    private val packetBatchQueue = ConcurrentLinkedQueue<NetworkRequestLog>()

    // Callback delivering batched logs to Repository
    var onBatchPacketProcessed: ((List<NetworkRequestLog>) -> Unit)? = null

    private val simulatedRequests = listOf(
        SimulatedRequest("googleads.g.doubleclick.net", "142.250.185.194", "Chrome", "com.android.chrome", ProtocolType.DOH),
        SimulatedRequest("api.github.com", "140.82.121.6", "GitHub Mobile", "com.github.android", ProtocolType.HTTPS),
        SimulatedRequest("graph.facebook.com", "157.240.241.1", "Instagram", "com.instagram.android", ProtocolType.HTTPS),
        SimulatedRequest("pixel.facebook.com", "157.240.241.2", "Shopee", "com.shopee.vn", ProtocolType.HTTPS),
        SimulatedRequest("adservice.google.com", "142.250.185.195", "Google Play", "com.android.vending", ProtocolType.DOH),
        SimulatedRequest("telemetry.sdk.appsflyer.com", "52.28.188.42", "TikTok", "com.zhiliaoapp.musically", ProtocolType.HTTPS),
        SimulatedRequest("audio-ak-spotify-com.akamaized.net", "23.210.155.33", "Spotify", "com.spotify.music", ProtocolType.HTTPS),
        SimulatedRequest("pagead2.googlesyndication.com", "142.250.185.196", "News Reader", "com.google.android.apps.magazines", ProtocolType.DOH),
        SimulatedRequest("spclient.wg.spotify.com", "35.186.224.25", "Spotify", "com.spotify.music", ProtocolType.HTTPS),
        SimulatedRequest("vortex.data.microsoft.com", "40.77.226.250", "Edge Browser", "com.microsoft.emmx", ProtocolType.HTTPS),
        SimulatedRequest("crashlytics.com", "142.250.185.200", "Zalo", "com.zing.zalo", ProtocolType.HTTPS),
        SimulatedRequest("dns.quad9.net", "9.9.9.9", "System DNS", "android", ProtocolType.DOH),
        SimulatedRequest("tracking.tiktok.com", "161.117.156.40", "TikTok", "com.zhiliaoapp.musically", ProtocolType.HTTPS),
        SimulatedRequest("api.weather.com", "23.212.254.120", "Weather", "com.google.android.apps.weather", ProtocolType.HTTPS),
        SimulatedRequest("applovin.com", "104.18.2.140", "Mobile Game", "com.fingersoft.hillclimb", ProtocolType.HTTPS)
    )

    data class SimulatedRequest(
        val domain: String,
        val ip: String,
        val appName: String,
        val appPackage: String,
        val protocol: ProtocolType
    )

    init {
        startBatchFlushLoop()
    }

    /**
     * Enqueues real packet intercepted from TUN device.
     */
    fun onRawPacketIntercepted(log: NetworkRequestLog) {
        if (_isScreenOff.value) return // Don't queue when screen is off to conserve CPU
        packetBatchQueue.add(log)
    }

    /**
     * Energy-saving periodic batch flush.
     * Batches multiple packet entries into a single UI update every 1000ms.
     */
    private fun startBatchFlushLoop() {
        batchFlushJob?.cancel()
        batchFlushJob = coroutineScope.launch {
            while (isActive) {
                delay(1000)
                if (!_isScreenOff.value && packetBatchQueue.isNotEmpty()) {
                    val batch = mutableListOf<NetworkRequestLog>()
                    while (batch.size < 25) {
                        val item = packetBatchQueue.poll() ?: break
                        batch.add(item)
                    }
                    if (batch.isNotEmpty()) {
                        onBatchPacketProcessed?.invoke(batch)
                    }
                }
            }
        }
    }

    fun setSimulationMode(enabled: Boolean) {
        _isSimulationMode.value = enabled
        if (enabled && _isVpnActive.value) {
            startTrafficSimulation()
        } else {
            stopTrafficSimulation()
        }
    }

    fun setScreenOffState(isOff: Boolean) {
        _isScreenOff.value = isOff
        if (isOff) {
            stopTrafficSimulation()
            packetBatchQueue.clear() // Drop queue to allow immediate CPU deep sleep
        } else {
            if (_isSimulationMode.value && _isVpnActive.value) {
                startTrafficSimulation()
            }
        }
    }

    fun startVpnService() {
        _isVpnActive.value = true
        if (_isSimulationMode.value) {
            startTrafficSimulation()
        }
        try {
            val intent = Intent(context, AdGuardVpnService::class.java).apply {
                action = AdGuardVpnService.ACTION_START_VPN
            }
            context.startService(intent)
        } catch (_: Exception) { }
    }

    fun stopVpnService() {
        _isVpnActive.value = false
        stopTrafficSimulation()
        try {
            val intent = Intent(context, AdGuardVpnService::class.java).apply {
                action = AdGuardVpnService.ACTION_STOP_VPN
            }
            context.startService(intent)
        } catch (_: Exception) { }
    }

    fun onVpnStarted() {
        _isVpnActive.value = true
        if (_isSimulationMode.value) {
            startTrafficSimulation()
        }
    }

    fun onVpnStopped() {
        _isVpnActive.value = false
        stopTrafficSimulation()
    }

    private fun startTrafficSimulation() {
        if (trafficSimulationJob?.isActive == true) return

        trafficSimulationJob = coroutineScope.launch {
            while (isActive) {
                if (_isVpnActive.value && _isSimulationMode.value && !_isScreenOff.value) {
                    delay(Random.nextLong(1500, 3000))

                    val sample = simulatedRequests[Random.nextInt(simulatedRequests.size)]
                    val decision = filterEngine.evaluateDomain(sample.domain)

                    val savedBytes = if (decision.status == FilterStatus.BLOCKED) {
                        Random.nextLong(24_000, 180_000)
                    } else 0L

                    val log = NetworkRequestLog(
                        id = UUID.randomUUID().toString(),
                        domain = sample.domain,
                        ipAddress = sample.ip,
                        appName = sample.appName,
                        appPackage = sample.appPackage,
                        timestampMs = System.currentTimeMillis(),
                        protocol = sample.protocol,
                        status = decision.status,
                        category = decision.category,
                        matchedRule = decision.matchedRule,
                        filterListName = decision.filterSourceName,
                        latencyMicros = decision.latencyMicros,
                        dataSavedBytes = savedBytes
                    )

                    packetBatchQueue.add(log)
                } else {
                    delay(1000)
                }
            }
        }
    }

    private fun stopTrafficSimulation() {
        trafficSimulationJob?.cancel()
        trafficSimulationJob = null
    }

    fun prepareVpnIntent(): Intent? {
        return VpnService.prepare(context)
    }
}
