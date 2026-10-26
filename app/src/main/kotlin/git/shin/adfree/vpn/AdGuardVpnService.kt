package git.shin.adfree.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.database.ContentObserver
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import git.shin.adfree.AdGuardApplication
import git.shin.adfree.BuildConfig
import git.shin.adfree.core.CoreEngine
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.io.File
import java.util.concurrent.ConcurrentHashMap

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

    /** Tunnel setup is binder-heavy, so it runs here rather than on the main
     *  thread: dozens of `protect()` and `addDisallowedApplication` calls are
     *  seconds of work and would earn the process an ANR. */
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @Volatile
    private var vpnInterface: ParcelFileDescriptor? = null
    private val container by lazy { AdGuardApplication.instance.container }
    @Volatile
    private var isRunning = false

    /** Guards the tunnel build itself, not just the running state. */
    private val establishing = java.util.concurrent.atomic.AtomicBoolean(false)

    private val screenReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                Intent.ACTION_SCREEN_OFF -> onScreenOff()
                Intent.ACTION_SCREEN_ON -> onScreenOn()
            }
        }
    }

    /**
     * Apps come and go while the tunnel runs, and their uids are reused: the
     * core's uid -> package table has to follow, or `$app=` rules would keep
     * naming the app that used to own a uid.
     */
    private val packageReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (!isRunning) return
            // The callback runs on the main thread and enumerating every
            // installed app does not belong there.
            serviceScope.launch(Dispatchers.IO) {
                container.coreEngine.pushUidApps(this@AdGuardVpnService)
            }
        }
    }

    /**
     * The TUN hides which physical network carries a flow, so the per-app
     * Wi-Fi/cellular switches need the transports below the VPN. While the
     * tunnel is the default network, `activeNetwork` is the VPN itself and its
     * capabilities do not name the underlying transport; the request below
     * asks for every validated non-VPN network instead.
     */
    private val activeTransports = ConcurrentHashMap<Network, NetworkCapabilities>()
    private val connectivity by lazy { getSystemService(ConnectivityManager::class.java) }
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            activeTransports[network] = caps
            pushNetworkType()
            // Private DNS can be switched on while the tunnel is up; the
            // effective DoT policy is part of the core config.
            container.syncConfigToEngine()
        }

        override fun onLost(network: Network) {
            activeTransports.remove(network)
            pushNetworkType()
            container.syncConfigToEngine()
        }
    }

    private fun pushNetworkType() {
        val caps = activeTransports.values
        val kind = when {
            caps.any { it.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) } ->
                CoreEngine.NETWORK_WIFI
            caps.any { it.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) } ->
                CoreEngine.NETWORK_CELLULAR
            caps.isEmpty() -> CoreEngine.NETWORK_UNKNOWN
            else -> CoreEngine.NETWORK_OTHER
        }
        container.coreEngine.setNetworkType(kind)
    }

    /**
     * Private DNS can be switched on while the tunnel runs, and the DoT reset
     * has to follow before the system resolver retries: strict mode has no
     * fallback, so a config that still resets 853 leaves the device without
     * resolution until the user happens to open the app again.
     */
    private val privateDnsObserver = object : ContentObserver(Handler(Looper.getMainLooper())) {
        override fun onChange(selfChange: Boolean) {
            container.syncConfigToEngine()
        }
    }

    override fun onCreate() {
        super.onCreate()
        runCatching {
            contentResolver.registerContentObserver(PrivateDns.modeUri, false, privateDnsObserver)
        }.onFailure { Log.w(TAG, "private DNS observer registration failed", it) }
        registerReceiver(
            screenReceiver,
            IntentFilter().apply {
                addAction(Intent.ACTION_SCREEN_OFF)
                addAction(Intent.ACTION_SCREEN_ON)
            },
        )
        registerReceiver(
            packageReceiver,
            IntentFilter().apply {
                addAction(Intent.ACTION_PACKAGE_ADDED)
                addAction(Intent.ACTION_PACKAGE_REMOVED)
                addAction(Intent.ACTION_PACKAGE_REPLACED)
                addDataScheme("package")
            },
        )
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        runCatching {
            connectivity?.registerNetworkCallback(request, networkCallback)
        }.onFailure { Log.w(TAG, "network callback registration failed", it) }
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
        // `isRunning` only turns true once `establish()` returns, so two starts
        // in quick succession (the launcher plus an explicit ACTION_START_VPN)
        // would both get past it and race: two `establish()` calls, and two
        // runs of `prepareUpstreamSockets` mutating the same socket lists. One
        // of them then dies mid-iteration and the tunnel is left half-built.
        if (!establishing.compareAndSet(false, true)) return
        try {
            createNotificationChannel()
            promoteToForeground(NOTIFICATION_ID, buildStatusNotification())
        } catch (e: Exception) {
            Log.e(TAG, "notification failed: ${e.message}", e)
            isRunning = false
            establishing.set(false)
            return
        }
        // Everything below is binder work — `establish()`, one
        // `addDisallowedApplication` per excluded app, and two `protect()` calls
        // per socket. That is seconds of work on a busy device, so running it
        // on the main thread earns the process an ANR. The notification is
        // already up, so nothing else has to happen here.
        serviceScope.launch(Dispatchers.IO) {
            try {
                establishTunnel()
            } catch (e: Exception) {
                Log.e(TAG, "establish failed: ${e.message}", e)
                isRunning = false
            } finally {
                establishing.set(false)
            }
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

        // adbd runs as the `shell` user. Without this the tunnel swallows its
        // traffic to the host and every tool loses the device the moment the
        // VPN goes up — which makes the whole thing impossible to debug.
        // Debug builds can flip this: dropping a marker file in the app's
        // files directory (`adb shell run-as git.shin.adfree touch
        // files/capture-shell`) routes the shell through the tunnel too, which
        // is how UDP relays are exercised with `nc` from adb.
        val captureShell = BuildConfig.DEBUG && File(filesDir, CAPTURE_SHELL_MARKER).exists()
        if (!captureShell) {
            runCatching { builder.addDisallowedApplication(SHELL_PACKAGE) }
                .onFailure { Log.w(TAG, "cannot exclude the shell package", it) }
        }

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
        // The core opens one peer socket per relayed connection and asks us to
        // protect() each one on the fly; without this the relays would send
        // their own traffic back into the tunnel.
        container.coreEngine.setSocketProtector(object : git.shin.adfree.core.SocketProtector {
            override fun protect(fd: Int): Boolean =
                runCatching { this@AdGuardVpnService.protect(fd) }.getOrDefault(false)
        })
        // The `$app=` rules need the uid -> package table, and this is the
        // moment that matters: pushed before the first packet, every flow the
        // tunnel sees is already attributed.
        container.coreEngine.pushUidApps(this)
        // ... and the other half of the pair: which uid owns a connection.
        // The framework answers that for the flows this tunnel carries, which
        // is the only source Android leaves to apps.
        container.coreEngine.setConnectionUidLookup(this)
        // The per-app network switches read this classification; set it before
        // the first packet so a blocked app never slips through on startup.
        pushNetworkType()
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

    override fun onDestroy() {
        serviceScope.cancel()
        runCatching { contentResolver.unregisterContentObserver(privateDnsObserver) }
        runCatching { unregisterReceiver(screenReceiver) }
        runCatching { unregisterReceiver(packageReceiver) }
        runCatching { connectivity?.unregisterNetworkCallback(networkCallback) }
        activeTransports.clear()
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        Log.i(TAG, "VPN revoked by user/system")
        container.repository.toggleProtection(false)
        stopVpn()
        super.onRevoke()
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
        /** adbd's package: kept out of the tunnel so tooling survives. */
        private const val SHELL_PACKAGE = "com.android.shell"

        /** See [onStartCommand]: presence means "capture the shell too". */
        private const val CAPTURE_SHELL_MARKER = "capture-shell"
        private const val NOTIFICATION_CHANNEL_ID = "adfree_status"
        private const val NOTIFICATION_ID = 1001
        private const val TUN_ADDRESS = "10.111.42.1"
        private const val TUN_PREFIX = 32
        private const val ROUTE_IPV4 = "0.0.0.0"
        private const val ROUTE_PREFIX = 0
        private const val MAX_EXCLUDED_PACKAGES = 64
    }
}
