package com.example.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.example.AdGuardApplication
import com.example.engine.RawPacketFilter
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer

/**
 * Real Android VpnService implementation.
 * - Establishes TUN virtual interface.
 * - Spawns zero-allocation packet reader loop to inspect live system packets.
 * - Synthesizes instantaneous DNS NXDOMAIN replies for blocked ads/trackers.
 * - Monitors screen power state (ACTION_SCREEN_OFF) to throttle telemetry and maximize battery life.
 */
class AdGuardVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false
    private var packetLoopJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO)

    // Battery saver: Track screen on/off state to suspend UI telemetry when screen is off
    private val screenReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                Intent.ACTION_SCREEN_OFF -> {
                    AdGuardApplication.instance.container.vpnController.setScreenOffState(true)
                }
                Intent.ACTION_SCREEN_ON -> {
                    AdGuardApplication.instance.container.vpnController.setScreenOffState(false)
                }
            }
        }
    }

    companion object {
        const val ACTION_START_VPN = "com.example.adguard.START_VPN"
        const val ACTION_STOP_VPN = "com.example.adguard.STOP_VPN"
        private const val NOTIFICATION_CHANNEL_ID = "adguard_vpn_status"
        private const val NOTIFICATION_ID = 1001
        private const val TAG = "AdGuardVpnService"
    }

    override fun onCreate() {
        super.onCreate()
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_SCREEN_ON)
        }
        registerReceiver(screenReceiver, filter)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action ?: ACTION_START_VPN
        if (action == ACTION_STOP_VPN) {
            stopVpn()
            return START_NOT_STICKY
        }

        startVpn()
        return START_STICKY
    }

    private fun startVpn() {
        if (isRunning) return

        try {
            createNotificationChannel()
            startForeground(NOTIFICATION_ID, buildStatusNotification())

            val builder = Builder()
                .setSession("AdGuard Ultra High-Speed Filter")
                .addAddress("10.0.0.2", 32)
                .addDnsServer("94.140.14.14") // Default AdGuard DNS
                .addRoute("0.0.0.0", 0)
                .setMtu(1500)
                .setBlocking(false)

            vpnInterface = builder.establish()
            isRunning = true
            Log.d(TAG, "AdGuard VPN TUN Interface successfully established.")

            // Start Real Raw Packet Loop
            startRawPacketLoop()

            AdGuardApplication.instance.container.vpnController.onVpnStarted()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to establish VPN interface: ${e.message}", e)
            isRunning = false
        }
    }

    /**
     * High-speed non-blocking packet reader loop.
     * Uses direct memory buffer to process incoming IP packets from TUN device.
     */
    private fun startRawPacketLoop() {
        val descriptor = vpnInterface?.fileDescriptor ?: return
        val filterEngine = AdGuardApplication.instance.container.filterEngine
        val vpnController = AdGuardApplication.instance.container.vpnController

        packetLoopJob = scope.launch {
            val inStream = FileInputStream(descriptor)
            val outStream = FileOutputStream(descriptor)
            val directBuffer = ByteBuffer.allocateDirect(16384)
            val rawArray = ByteArray(16384)

            try {
                while (isActive && isRunning) {
                    val length = inStream.read(rawArray)
                    if (length > 0) {
                        directBuffer.clear()
                        directBuffer.put(rawArray, 0, length)
                        directBuffer.flip()

                        val result = RawPacketFilter.processPacket(directBuffer, length, filterEngine)
                        if (result != null) {
                            if (result.syntheticReply != null) {
                                // Write back instantaneous NXDOMAIN reply
                                outStream.write(result.syntheticReply)
                            }
                            vpnController.onRawPacketIntercepted(result.log)
                        }
                    }
                }
            } catch (e: Exception) {
                if (isRunning) {
                    Log.d(TAG, "Packet loop closed: ${e.message}")
                }
            }
        }
    }

    private fun stopVpn() {
        isRunning = false
        packetLoopJob?.cancel()
        packetLoopJob = null

        try {
            vpnInterface?.close()
            vpnInterface = null
        } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN interface: ${e.message}")
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        AdGuardApplication.instance.container.vpnController.onVpnStopped()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "AdGuard Protection Status",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows live protection status of the ad blocker"
                setShowBadge(false)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(channel)
        }
    }

    private fun buildStatusNotification(): Notification {
        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("AdGuard Ultra is Active")
            .setContentText("Network filter and battery saver running at maximum performance")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    override fun onDestroy() {
        try {
            unregisterReceiver(screenReceiver)
        } catch (_: Exception) {}
        stopVpn()
        super.onDestroy()
    }
}
