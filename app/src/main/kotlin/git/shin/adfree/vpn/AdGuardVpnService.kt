package git.shin.adfree.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
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
import git.shin.adfree.AssistantActivity
import git.shin.adfree.BuildConfig
import git.shin.adfree.MainActivity
import git.shin.adfree.R
import git.shin.adfree.core.CoreEngine
import git.shin.adfree.ui.Localization
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import java.io.File
import java.net.Inet6Address
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

    /** The pending retry of a tunnel that failed to come up. */
    private var retryJob: Job? = null

    /** Whether the ongoing notification currently owns the foreground slot. */
    @Volatile
    private var foregroundActive = false

    /** Last numbers drawn into the notification; the ticker compares against them. */
    @Volatile
    private var lastNotifiedBlocked = -1L
    @Volatile
    private var lastNotifiedSavedMb = -1L

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
            container.applyConfig()
        }

        override fun onLost(network: Network) {
            activeTransports.remove(network)
            pushNetworkType()
            container.applyConfig()
        }
    }

    private fun pushNetworkType() {
        val caps = activeTransports.values
        val cellular = caps.firstOrNull {
            it.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
        }
        val kind = when {
            caps.any { it.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) } ->
                CoreEngine.NETWORK_WIFI
            cellular != null -> CoreEngine.NETWORK_CELLULAR
            caps.isEmpty() -> CoreEngine.NETWORK_UNKNOWN
            else -> CoreEngine.NETWORK_OTHER
        }
        container.coreEngine.setNetworkType(kind)
        // Older platforms do not report the capability; treating that as "not
        // roaming" matches the pre-roaming behaviour.
        val roaming = cellular != null &&
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            !cellular.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING)
        container.coreEngine.setRoaming(roaming)
    }

    /**
     * Private DNS can be switched on while the tunnel runs, and the DoT reset
     * has to follow before the system resolver retries: strict mode has no
     * fallback, so a config that still resets 853 leaves the device without
     * resolution until the user happens to open the app again.
     */
    private val privateDnsObserver = object : ContentObserver(Handler(Looper.getMainLooper())) {
        override fun onChange(selfChange: Boolean) {
            container.applyConfig()
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
        // The service outlives the Activity: follow language and HTTPS changes
        // so the channel and the filtering line never describe an older config.
        serviceScope.launch {
            container.repository.settings
                .map { it.appLanguage to it.isHttpsFilteringEnabled }
                .distinctUntilChanged()
                .drop(1)
                .collect {
                    if (isRunning) {
                        createNotificationChannel()
                        promoteToForeground(NOTIFICATION_ID, buildStatusNotification())
                    }
                }
        }
        // AdGuard keeps the blocked/data counters live in the shade. The UI
        // poller parks while the app is hidden, so the service ticks its own
        // cheap native read and only redraws when a number actually moved.
        serviceScope.launch {
            while (true) {
                delay(NOTIFICATION_STATS_INTERVAL_MS)
                if (!isRunning || container.coreEngine.isProtectionPaused()) continue
                val (blocked, savedMb) = notificationStats()
                if (blocked != lastNotifiedBlocked || savedMb != lastNotifiedSavedMb) {
                    promoteToForeground(NOTIFICATION_ID, buildStatusNotification())
                }
            }
        }
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
        when (intent?.action) {
            ACTION_STOP_VPN -> {
                // A restart keeps the persisted switch on and must not leave a
                // "disabled" reminder behind; turning protection off must.
                stopVpn(showDisabledReminder = !container.repository.settings.value.isProtectionActive)
                return START_NOT_STICKY
            }
            ACTION_PAUSE_VPN -> {
                // Pause is transient: the tunnel and the persisted protection
                // switch stay as they are, only the filtering gates close.
                setPaused(true)
                return START_STICKY
            }
            ACTION_RESUME_VPN -> {
                setPaused(false)
                return START_STICKY
            }
            ACTION_DISABLE_PROTECTION -> {
                // The notification's disable button: the user is done, so the
                // remembered state has to say so.
                container.repository.toggleProtection(false)
                stopVpn(showDisabledReminder = true)
                return START_NOT_STICKY
            }
            ACTION_REFRESH_NOTIFICATION -> {
                // Re-post only. This action must never start a tunnel: it is
                // sent from the UI after a permission grant.
                if (isRunning) promoteToForeground(NOTIFICATION_ID, buildStatusNotification())
                return START_STICKY
            }
        }
        startVpn()
        return START_STICKY
    }

    /**
     * [attempt] counts the retries of one start, so the backoff grows and the
     * giving-up point is reachable. A start the user asked for begins at zero.
     */
    private fun startVpn(attempt: Int = 0) {
        if (isRunning) return
        // A fresh tunnel always starts filtering: pause is a runtime state of
        // one session, never a persisted preference.
        container.coreEngine.setProtectionPaused(false)
        // `isRunning` only turns true once `establish()` returns, so two starts
        // in quick succession (the launcher plus an explicit ACTION_START_VPN)
        // would both get past it and race: two `establish()` calls, and two
        // runs of `prepareUpstreamSockets` mutating the same socket lists. One
        // of them then dies mid-iteration and the tunnel is left half-built.
        if (!establishing.compareAndSet(false, true)) return
        try {
            createNotificationChannel()
            createAlertChannel()
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
            val established = try {
                establishTunnel()
            } catch (e: Exception) {
                Log.e(TAG, "establish failed: ${e.message}", e)
                false
            }
            establishing.set(false)
            if (!established) {
                teardownTunnel()
                scheduleTunnelRetry(attempt)
            }
        }
    }

    /**
     * Build the tunnel. QUIC/DoT blocking happens in the core; Android only
     * hands out a route and a DNS server. False means no tunnel exists, which
     * [startVpn] answers with a retry.
     */
    private fun establishTunnel(): Boolean {
        // The core resolves the persisted provider (falling back with a
        // warning instead of leaving the device without a tunnel).
        val tunnelDns = container.coreEngine.resolverSnapshot().tunnelDns
            .ifBlank { "94.140.14.14" }

        val builder = Builder()
            .setSession(localizedContext().getString(R.string.vpn_session_name))
            .addAddress(TUN_ADDRESS, TUN_PREFIX)
            .addDnsServer(tunnelDns)
            .addRoute(ROUTE_IPV4, ROUTE_PREFIX)
        if (underlyingHasIpv6()) {
            // Global IPv6 is live upstream: carry it through the tunnel so v6
            // traffic is filtered like everything else.
            builder.addRoute(ROUTE_IPV6, IPV6_PREFIX)
        }
        // With no IPv6 address/route/DNS, the framework installs
        // `::/0 unreachable` itself (Vpn.java), which is exactly AdGuard's
        // behaviour: clients fail the IPv6 attempt instantly instead of
        // reaching the tunnel and dying after a relay retry.
        builder.setMtu(1500)
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
            Log.e(TAG, "establish() returned null — VPN permission was not granted")
            return false
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
        // Protection is up, so the missing-certificate reminder is due.
        container.repository.syncHttpsReminder()
        Log.i(TAG, "TUN up (fd=$fd), dns=$tunnelDns")
        return true
    }

    /**
     * Take a tunnel apart that never came up, without ending the service: the
     * retry below is the reason it is still alive. A descriptor left open under
     * a flag that says nothing is running is the worst outcome — the system
     * keeps routing every flow into a TUN nobody reads, so the device loses
     * connectivity while the app claims protection is off.
     */
    private fun teardownTunnel() {
        isRunning = false
        container.coreEngine.stop()
        if (vpnInterface == null) return
        container.vpnController.onVpnStopped()
        runCatching { vpnInterface?.close() }.onFailure { Log.w(TAG, "close TUN failed", it) }
        vpnInterface = null
    }

    /**
     * Retry a tunnel the user never switched off. `establish()` failing is
     * usually transient — a binder call racing a network change, a descriptor
     * the framework refused once — and Android leaves the session authorized,
     * so a second attempt needs no dialog and asks permission from nobody.
     * Where consent really has gone, retrying would mean asking behind the
     * user's back: that case stops here and says so in the shade.
     */
    private fun scheduleTunnelRetry(attempt: Int) {
        if (!container.coreEngine.wantsStart) return
        // Named as the system's always-on VPN, this tunnel has a rebuilder
        // already: the platform restarts it, and a second one here would only
        // race it and announce a loss the user never sees.
        if (isSystemKeepingVpn()) return
        val needsConsent = VpnService.prepare(this) != null
        if (needsConsent || attempt >= MAX_TUNNEL_RETRIES) {
            // The switch promised protection and neither of us can deliver it.
            container.repository.toggleProtection(false)
            stopVpn()
            postDroppedAlert(needsConsent = needsConsent)
            return
        }
        retryJob?.cancel()
        retryJob = serviceScope.launch {
            delay(RETRY_BASE_MS * (1L shl attempt))
            if (container.coreEngine.wantsStart && !isRunning && !establishing.get()) {
                startVpn(attempt + 1)
            }
        }
        Log.i(TAG, "tunnel retry $attempt scheduled")
    }

    /** Whether system Settings named this VPN always-on, so it is rebuilt there. */
    private fun isSystemKeepingVpn(): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            runCatching { isAlwaysOn() }.getOrDefault(false)

    /**
     * Whether the physical network under the tunnel has a global IPv6
     * address. The tunnel is built before `establish()`, so `activeNetwork`
     * is still the carrier network here.
     */
    private fun underlyingHasIpv6(): Boolean {
        val cm = connectivity ?: return false
        val props = runCatching { cm.getLinkProperties(cm.activeNetwork) }.getOrNull()
            ?: return false
        return props.linkAddresses.any { link ->
            val ip = link.address
            ip is Inet6Address && !ip.isLinkLocalAddress && !ip.isLoopbackAddress &&
                !ip.isSiteLocalAddress && !ip.isMulticastAddress
        }
    }

    /**
     * [showDisabledReminder] posts the tap-to-enable notification after the
     * tunnel is gone. Only a user-initiated disable does that: a restart is
     * about to bring the tunnel back, and a revoke/destroy has no user intent
     * behind it.
     */
    private fun stopVpn(showDisabledReminder: Boolean = false) {
        // A stop the user asked for is the end of any retry in flight.
        retryJob?.cancel()
        retryJob = null
        isRunning = false
        container.repository.syncHttpsReminder()
        container.coreEngine.stop()
        container.vpnController.onVpnStopped()
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.w(TAG, "close TUN failed", e)
        }
        vpnInterface = null
        // `onDestroy` stops the service again after `stopSelf()`. Calling
        // stopForeground twice would cancel the reminder posted below, because
        // Android ties the removal to the notification id.
        if (foregroundActive) {
            foregroundActive = false
            stopForeground(STOP_FOREGROUND_REMOVE)
        }
        if (showDisabledReminder) postDisabledReminder()
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
        foregroundActive = true
    }

    override fun onDestroy() {
        // Read before stopVpn() clears it: whether the tunnel was up and the
        // switch still expected it is what tells a kill apart from a stop.
        val dropped = shouldReportDroppedProtection(
            wasRunning = isRunning,
            protectionExpected = container.repository.settings.value.isProtectionActive,
            systemKeepsVpn = isSystemKeepingVpn(),
        )
        serviceScope.cancel()
        runCatching { contentResolver.unregisterContentObserver(privateDnsObserver) }
        runCatching { unregisterReceiver(screenReceiver) }
        runCatching { unregisterReceiver(packageReceiver) }
        runCatching { connectivity?.unregisterNetworkCallback(networkCallback) }
        activeTransports.clear()
        stopVpn()
        if (dropped) postDroppedAlert()
        super.onDestroy()
    }

    override fun onRevoke() {
        Log.i(TAG, "VPN revoked by user/system")
        // The switch still says the tunnel should be up: it is this call that
        // says otherwise, so the expectation has to be read before it.
        val dropped = shouldReportDroppedProtection(
            wasRunning = isRunning,
            protectionExpected = container.repository.settings.value.isProtectionActive,
            systemKeepsVpn = isSystemKeepingVpn(),
        )
        container.repository.toggleProtection(false)
        stopVpn()
        if (dropped) postDroppedAlert()
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
        // The user may be returning from the certificate installer.
        container.repository.syncHttpsReminder()
    }

    /**
     * A service outlives the Activity, so it has to resolve its own wording
     * instead of inheriting the Activity's per-app locale.
     */
    private fun localizedContext(): Context =
        Localization.wrap(this, container.repository.settings.value.appLanguage)

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ui = localizedContext()
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                ui.getString(R.string.vpn_channel_name),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = ui.getString(R.string.vpn_channel_description)
                setShowBadge(false)
            }
            getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)
        }
    }

    /**
     * The channel a lost tunnel is announced on. The ongoing status notification
     * redraws itself every ten seconds, so its channel has to stay silent; an
     * alert the user needs to hear is therefore a second channel, at default
     * importance, which is also what AdGuard's own protection channel uses.
     */
    private fun createAlertChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val ui = localizedContext()
        val channel = NotificationChannel(
            ALERT_CHANNEL_ID,
            ui.getString(R.string.vpn_alert_channel_name),
            NotificationManager.IMPORTANCE_DEFAULT,
        ).apply {
            description = ui.getString(R.string.vpn_alert_channel_description)
        }
        getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)
    }

    /** The counters AdGuard puts in the shade: blocked requests and saved data. */
    private fun notificationStats(): Pair<Long, Long> {
        val snapshot = container.coreEngine.stats()
        val blocked = snapshot.dnsBlocked + snapshot.tcpReset + snapshot.quicDropped +
            snapshot.quicBlocked + snapshot.udpDropped
        return blocked to snapshot.bytesSaved / (1024L * 1024L)
    }

    private fun buildStatusNotification(): Notification {
        val ui = localizedContext()
        val paused = container.coreEngine.isProtectionPaused()
        val (blocked, savedMb) = if (paused) 0L to 0L else notificationStats()
        if (!paused) {
            lastNotifiedBlocked = blocked
            lastNotifiedSavedMb = savedMb
        }
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or
                    Intent.FLAG_ACTIVITY_CLEAR_TOP or
                    Intent.FLAG_ACTIVITY_SINGLE_TOP
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val toggle = PendingIntent.getService(
            this,
            1,
            Intent(this, AdGuardVpnService::class.java).apply {
                action = vpnToggleAction(paused)
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val disable = PendingIntent.getService(
            this,
            2,
            Intent(this, AdGuardVpnService::class.java).apply {
                action = ACTION_DISABLE_PROTECTION
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val assistant = PendingIntent.getActivity(
            this,
            4,
            Intent(this, AssistantActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val builder = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_qs_shield)
            .setContentIntent(open)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
        if (paused) {
            builder
                .setContentTitle(ui.getString(R.string.vpn_notification_paused_title))
                .setContentText(ui.getString(R.string.vpn_notification_paused_text))
                .addAction(
                    R.drawable.ic_qs_shield,
                    ui.getString(R.string.vpn_notification_resume),
                    toggle,
                )
        } else {
            val blockedLine = ui.getString(R.string.vpn_notification_blocked, blocked)
            builder
                .setContentTitle(ui.getString(R.string.vpn_notification_title))
                .setContentText(blockedLine)
                .setStyle(
                    NotificationCompat.BigTextStyle().bigText(
                        blockedLine + "\n" +
                            ui.getString(R.string.vpn_notification_saved, savedMb),
                    ),
                )
                .addAction(
                    R.drawable.ic_qs_shield,
                    ui.getString(R.string.vpn_notification_disable),
                    disable,
                )
        }
        builder.addAction(
            R.drawable.ic_qs_shield,
            ui.getString(R.string.vpn_notification_assistant),
            assistant,
        )
        return builder.build()
    }

    /**
     * The state AdGuard leaves behind when protection is disabled: a normal
     * ongoing notification that re-opens the consent/enable flow on tap. It
     * uses the same id the foreground service had, so re-enabling replaces it
     * instead of stacking a second shade entry.
     */
    private fun postDisabledReminder() {
        val ui = localizedContext()
        createNotificationChannel()
        val open = PendingIntent.getActivity(
            this,
            3,
            Intent(this, MainActivity::class.java).apply {
                action = MainActivity.ACTION_ENABLE_PROTECTION
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or
                    Intent.FLAG_ACTIVITY_CLEAR_TOP or
                    Intent.FLAG_ACTIVITY_SINGLE_TOP
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notification = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle(ui.getString(R.string.vpn_notification_disabled_title))
            .setContentText(ui.getString(R.string.vpn_notification_disabled_text))
            .setSmallIcon(R.drawable.ic_qs_shield)
            .setContentIntent(open)
            .setOngoing(true)
            .setSilent(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
        getSystemService(NotificationManager::class.java)?.notify(NOTIFICATION_ID, notification)
    }

    /**
     * One alert for a tunnel the user never stopped.
     *
     * [needsConsent] says which kind of loss this was. Android will not let the
     * service put the session back without a fresh consent dialog, so that case
     * taps into the enable flow rather than retrying behind the user's back.
     * When consent survived but `establish()` kept refusing, the retries are
     * what ran out — the tap then simply asks for another start. A separate id
     * from the ongoing notification, so the shade still shows it after
     * `stopForeground` took the tunnel's notification away.
     */
    private fun postDroppedAlert(needsConsent: Boolean = true) {
        val ui = localizedContext()
        createAlertChannel()
        val open = PendingIntent.getActivity(
            this,
            4,
            Intent(this, MainActivity::class.java).apply {
                action = MainActivity.ACTION_ENABLE_PROTECTION
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or
                    Intent.FLAG_ACTIVITY_CLEAR_TOP or
                    Intent.FLAG_ACTIVITY_SINGLE_TOP
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notification = NotificationCompat.Builder(this, ALERT_CHANNEL_ID)
            .setContentTitle(
                ui.getString(
                    if (needsConsent) R.string.vpn_notification_dropped_title
                    else R.string.vpn_notification_failed_title,
                ),
            )
            .setContentText(
                ui.getString(
                    if (needsConsent) R.string.vpn_notification_dropped_text
                    else R.string.vpn_notification_failed_text,
                ),
            )
            .setSmallIcon(R.drawable.ic_qs_shield)
            .setContentIntent(open)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setCategory(Notification.CATEGORY_ERROR)
            .build()
        getSystemService(NotificationManager::class.java)?.notify(DROPPED_ALERT_ID, notification)
    }

    /** Applies the transient pause and redraws the foreground notification. */
    private fun setPaused(paused: Boolean) {
        container.coreEngine.setProtectionPaused(paused)
        if (isRunning || establishing.get()) {
            promoteToForeground(NOTIFICATION_ID, buildStatusNotification())
        }
        container.vpnController.onPauseChanged()
    }

    companion object {
        const val ACTION_START_VPN = VpnActions.START
        const val ACTION_STOP_VPN = VpnActions.STOP
        const val ACTION_PAUSE_VPN = VpnActions.PAUSE
        const val ACTION_RESUME_VPN = VpnActions.RESUME
        const val ACTION_DISABLE_PROTECTION = VpnActions.DISABLE
        const val ACTION_REFRESH_NOTIFICATION = VpnActions.REFRESH_NOTIFICATION
        private const val TAG = "AdGuardVpnService"
        /** adbd's package: kept out of the tunnel so tooling survives. */
        private const val SHELL_PACKAGE = "com.android.shell"

        /** See [onStartCommand]: presence means "capture the shell too". */
        private const val CAPTURE_SHELL_MARKER = "capture-shell"
        const val NOTIFICATION_CHANNEL_ID = "adfree_status"

        /** Loud enough to notice: the channel a lost tunnel is announced on. */
        const val ALERT_CHANNEL_ID = "adfree_protection"
        private const val NOTIFICATION_ID = 1001

        /**
         * The dropped-tunnel alert. Ids are app-global, not per channel, and the
         * two hash-based notifiers occupy 1003..66538 and 2000..67536, so this
         * sits above both rather than replacing one of their rows.
         */
        private const val DROPPED_ALERT_ID = 70_000
        /** Stats change slowly enough that ten seconds is imperceptible. */
        private const val NOTIFICATION_STATS_INTERVAL_MS = 10_000L

        /**
         * Three tries, one second then two then four: long enough for a racing
         * binder call or a network switch to settle, short enough that the user
         * never waits a minute for the shade to say what happened.
         */
        private const val MAX_TUNNEL_RETRIES = 3
        private const val RETRY_BASE_MS = 1_000L
        private const val TUN_ADDRESS = "10.111.42.1"
        private const val TUN_PREFIX = 32
        private const val ROUTE_IPV4 = "0.0.0.0"
        private const val ROUTE_PREFIX = 0

        /** Global unicast only; link-local and ULA stay on the physical link. */
        private const val ROUTE_IPV6 = "2000::"
        private const val IPV6_PREFIX = 3
        private const val MAX_EXCLUDED_PACKAGES = 64
    }
}
