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

/**
 * A real VpnService: build the TUN, `protect()` the DNS sockets, hand the fd
 * to the Rust core.
 *
 * Big differences from the previous version:
 * * no busy-looping `read()` on the fd — Rust `poll()`s before it reads;
 * * per-app routing via `addDisallowedApplication` instead of a fake firewall;
 * * screen-off is reported to Rust so it stops writing logs (saves battery);
 * * no simulated packets.
 */
class AdGuardVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private val container by lazy { AdGuardApplication.instance.container }
    private var isRunning = false

    private val screenReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                Intent.ACTION_SCREEN_OFF -> onScreenOff()
                Intent.ACTION_SCREEN_ON -> onScreenOn()
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        registerReceiver(
            screenReceiver,
            IntentFilter().apply {
                addAction(Intent.ACTION_SCREEN_OFF)
                addAction(Intent.ACTION_SCREEN_ON)
            },
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP_VPN) {
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
            promoteToForeground(NOTIFICATION_ID, buildStatusNotification())
            establishTunnel()
        } catch (e: Exception) {
            Log.e(TAG, "establish failed: ${e.message}", e)
            isRunning = false
        }
    }

    /**
     * Build the tunnel. QUIC/DoT blocking happens in the core; Android only
     * hands out a route and a DNS server.
     */
    private fun establishTunnel() {
        val settings = container.repository.settings.value
        val dns = container.repository.dnsProviders
            .value
            .firstOrNull { it.id == settings.selectedDnsProviderId }
            ?: return

        val builder = Builder()
            .setSession("AdFree Protection")
            .addAddress(TUN_ADDRESS, TUN_PREFIX)
            .addDnsServer(dns.address.substringBefore('/'))
            .addRoute(ROUTE_IPV4, ROUTE_PREFIX)
            .addRoute("2000::", 3)
            .setMtu(1500)
            .setBlocking(true)

        // Không route chính app này qua tunnel: tránh DNS loop.
        runCatching { builder.addDisallowedApplication(packageName) }
            .onFailure { Log.w(TAG, "cannot exclude own package", it) }

        // Exclude the apps that must not be filtered (from the real firewall).
        container.repository.excludedPackages()
            .take(MAX_EXCLUDED_PACKAGES)
            .forEach { packageName ->
                runCatching { builder.addDisallowedApplication(packageName) }
                    .onFailure { Log.w(TAG, "cannot exclude $packageName", it) }
            }

        val descriptor = builder.establish() ?: run {
            Log.e(TAG, "establish() returned null — quyền VPN chưa được cấp")
            isRunning = false
            return
        }
        val fd = descriptor.fd
        vpnInterface = descriptor
        isRunning = true

        // 1. create protect()ed DNS forwarding sockets BEFORE handing the TUN to the
        // core; 2. all the heavy lifting then runs natively.
        container.coreEngine.prepareUpstreamSockets(this)
        // Spare descriptors the TLS relay connects towards the real server.
        container.coreEngine.preparePeerSockets(this)
        container.coreEngine.start(fd)
        container.vpnController.onVpnStarted()
        Log.i(TAG, "TUN up (fd=$fd), dns=${dns.address}")
    }

    private fun stopVpn() {
        isRunning = false
        container.coreEngine.stop()
        container.vpnController.onVpnStopped()
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.w(TAG, "close TUN failed", e)
        }
        vpnInterface = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    /** Android 14+ requires an explicit foreground service type. */
    /** Android 14+ requires an explicit foreground service type. */
    private fun promoteToForeground(id: Int, notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                id,
                notification,
                android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(id, notification)
        }
    }

    override fun onRevoke() {
        Log.i(TAG, "VPN revoked by user/system")
        container.repository.toggleProtection(false)
        stopVpn()
        super.onRevoke()
    }

    override fun onDestroy() {
        runCatching { unregisterReceiver(screenReceiver) }
        stopVpn()
        super.onDestroy()
    }

    private fun onScreenOff() {
        // Rust stops writing logs and drops the uid table: no needless wakeups.
        container.coreEngine.setScreenOff(true)
        container.coreEngine.markScreenOff()
    }

    private fun onScreenOn() {
        container.coreEngine.setScreenOff(false)
        container.coreEngine.markScreenOn()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "Trạng thái bảo vệ AdFree",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "Chỉ báo AdFree đang lọc lưu lượng mạng"
                setShowBadge(false)
            }
            getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)
        }
    }

    private fun buildStatusNotification(): Notification =
        NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("AdFree đang bảo vệ")
            .setContentText("Lọc quảng cáo & tracker mức DNS")
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()

    companion object {
        const val ACTION_START_VPN = "com.adfree.START_VPN"
        const val ACTION_STOP_VPN = "com.adfree.STOP_VPN"
        private const val TAG = "AdGuardVpnService"
        private const val NOTIFICATION_CHANNEL_ID = "adfree_status"
        private const val NOTIFICATION_ID = 1001
        private const val TUN_ADDRESS = "10.111.42.1"
        private const val TUN_PREFIX = 32
        private const val ROUTE_IPV4 = "0.0.0.0"
        private const val ROUTE_PREFIX = 0
        private const val MAX_EXCLUDED_PACKAGES = 64
    }
}
