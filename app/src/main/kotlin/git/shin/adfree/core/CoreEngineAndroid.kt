package git.shin.adfree.core

import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.provider.MediaStore
import android.net.VpnService
import android.os.Build
import android.os.Environment
import android.os.ParcelFileDescriptor
import android.provider.Settings
import android.util.Log
import git.shin.adfree.AdGuardApplication
import java.io.File
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * The Android half of [CoreEngine]: everything that needs a `VpnService`, a
 * `PackageManager` or the media store. The shared engine stays platform-free
 * and the engine call sites read the same on both hosts.
 */

/** UDP sockets used to forward DNS, `VpnService.protect()`ed so they do not loop. */
private val upstreamSockets = mutableListOf<java.net.DatagramSocket>()
private val holderPipes = mutableListOf<ParcelFileDescriptor>()
private const val SOCKET_COUNT = 4

/**
 * Create the UDP sockets the core forwards DNS with.
 *
 * The critical part: every socket must be `VpnService.protect()`ed, otherwise
 * packets towards the resolver re-enter our own TUN and DNS dies entirely.
 */
@Synchronized
fun CoreEngine.prepareUpstreamSockets(vpnService: VpnService) {
    closeUpstreamSockets()
    repeat(SOCKET_COUNT) {
        runCatching { java.net.DatagramSocket().apply { reuseAddress = true } }
            .onSuccess { upstreamSockets += it }
    }
    val fds = upstreamSockets.mapNotNull { socket -> protectAndKeep(vpnService, socket) }
    Log.i("AdFreeCore", "upstream DNS sockets protected: ${fds.size}/$SOCKET_COUNT")
    git.shin.adfree.core.coreProtectSockets(fds)
}

/**
 * `protect()`s a socket and hands its descriptor to the Rust core.
 *
 * The descriptor is handed over as-is and the `ParcelFileDescriptor` that
 * wraps it is kept alive for as long as the engine runs. That is deliberate:
 * on Android 12 and newer a dup()ed descriptor belongs to the descriptor
 * object that created it, so `dup()` + `close()` looks fine but the kernel
 * then answers `sendto()` with EBADF and nothing resolves. Keeping the
 * owner alive (and never closing it before `stopAndRelease()`) is what
 * actually works.
 */
private fun protectAndKeep(vpnService: VpnService, socket: java.net.DatagramSocket): Int? = runCatching {
    vpnService.protect(socket)
    val pfd = ParcelFileDescriptor.fromDatagramSocket(socket)
    holderPipes += pfd
    pfd.fd
}.getOrNull()

/**
 * Stops the engine and releases every descriptor handed to it — the pair the
 * VPN service calls on every teardown path.
 */
@Synchronized
fun CoreEngine.stopAndRelease() {
    stop()
    closeUpstreamSockets()
}

@Synchronized
private fun closeUpstreamSockets() {
    holderPipes.forEach { runCatching { it.close() } }
    holderPipes.clear()
    upstreamSockets.forEach { runCatching { it.close() } }
    upstreamSockets.clear()
}

/**
 * Builds the uid -> packages table from the platform's app list and pushes it
 * to the core, which matches `$app=` network rules against it.
 *
 * The core cannot read other apps' uid on Android 10+, so the platform has to
 * tell it: one row per uid, every package sharing it included. Cheap enough to
 * redo whenever an app is installed, removed or replaced.
 */
fun CoreEngine.pushUidApps(context: Context) {
    val pm = context.packageManager
    val installed = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0L))
    } else {
        @Suppress("DEPRECATION")
        pm.getInstalledApplications(0)
    }
    val byUid = LinkedHashMap<Int, MutableList<String>>()
    for (info in installed) {
        byUid.getOrPut(info.uid) { mutableListOf() } += info.packageName
    }
    setUidApps(byUid.map { (uid, packages) ->
        git.shin.adfree.core.UidApps(uid = uid.toUInt(), packages = packages)
    })
}

/**
 * Installs the callback the core uses to name the app that owns one TCP
 * connection, which is what `$app=` rules are matched against.
 *
 * `pushUidApps` above answers "which packages have this uid"; this answers
 * "whose uid is this connection". The kernel table the desktop core reads
 * (`/proc/net/tcp`) has been closed to apps since Android 10, but a
 * VpnService may ask the framework about the connections its own tunnel
 * carries — which is exactly the traffic being filtered.
 */
fun CoreEngine.setConnectionUidLookup(context: Context) {
    // Below Android 10 the kernel table the core reads is still open to
    // apps, and it costs no binder round-trip per flow; from Android 10 on
    // `/proc` is closed, so the framework is the only answer.
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return
    runCatching {
        git.shin.adfree.core.coreSetUidLookup(FrameworkUidLookup(context.applicationContext))
    }.onFailure { Log.w("AdFreeCore", "setUidLookup failed", it) }
}

/**
 * Opens the Settings screen that leads to the CA installer.
 *
 * The platform refuses to install a CA certificate inline (`KeyChain`
 * install intents answer "Install CA certificates in Settings"), so the
 * user has to walk the Settings flow: Encryption & credentials → Install a
 * certificate → CA certificate → pick the exported file → confirm the
 * monitoring warning. [AndroidCaExporter] puts that file where the picker can
 * reach it.
 */
fun CoreEngine.installCertificateIntent(): Intent =
    Intent(Settings.ACTION_SECURITY_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

/**
 * Copies the CA certificate to the shared Downloads folder through the media
 * store, replacing any earlier copy so the picker never shows the certificate
 * twice. Only the certificate travels; the private half stays in the core's
 * directory.
 */
class AndroidCaExporter : git.shin.adfree.platform.CaExporter {

    override fun export(pem: String): String? {
        val name = "AdFree-CA.crt"
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return runCatching {
                @Suppress("DEPRECATION")
                val downloads = Environment
                    .getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                if (!downloads.exists() && !downloads.mkdirs()) return null
                File(downloads, name).writeText(pem)
                name
            }.getOrNull()
        }
        return runCatching {
            val resolver = AdGuardApplication.instance.contentResolver
            val collection = MediaStore.Downloads.EXTERNAL_CONTENT_URI
            // Replace any earlier copy: two identical rows would leave the
            // picker showing the same certificate twice with no way to tell
            // them apart.
            resolver.delete(
                collection,
                "${MediaStore.Downloads.DISPLAY_NAME} = ?",
                arrayOf(name),
            )
            val uri = resolver.insert(
                collection,
                ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, name)
                    put(MediaStore.Downloads.MIME_TYPE, "application/x-x509-ca-cert")
                    put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                    put(MediaStore.Downloads.IS_PENDING, 1)
                },
            ) ?: return null
            resolver.openOutputStream(uri)?.use { it.write(pem.toByteArray()) }
            resolver.update(
                uri,
                ContentValues().apply { put(MediaStore.Downloads.IS_PENDING, 0) },
                null,
                null,
            )
            name
        }.getOrNull()
    }
}

/**
 * True when the PEM's DER bytes match any certificate in the Android trust
 * store. Comparing bytes, not aliases: the same certificate can live in the
 * user store (installed through the dialog) or the system store (preloaded
 * images, emulator tooling), and either way the leaves we mint are accepted.
 */
class AndroidCaTrustChecker : git.shin.adfree.platform.CaTrustChecker {

    override fun isTrusted(pem: String): Boolean {
        val expected = runCatching {
            CertificateFactory.getInstance("X.509")
                .generateCertificate(pem.byteInputStream())
        }.getOrNull() as? X509Certificate ?: return false
        val store = runCatching {
            KeyStore.getInstance("AndroidCAStore").apply { load(null, null) }
        }.getOrNull() ?: return false
        return runCatching {
            val aliases = store.aliases()
            while (aliases.hasMoreElements()) {
                val cert = store.getCertificate(aliases.nextElement()) as? X509Certificate
                    ?: continue
                if (cert.encoded.contentEquals(expected.encoded)) return true
            }
            false
        }.getOrDefault(false)
    }
}

/**
 * The core's `$app=` attribution, answered by the framework.
 *
 * `ConnectivityManager.getConnectionOwnerUid` (API 29+) is the only
 * unprivileged way to learn which app owns a connection: a VpnService may ask
 * it about the flows its own tunnel carries, and the system names their owner
 * from the kernel's socket table on our behalf. `/proc/net/tcp` — what the
 * desktop core reads — has been closed to apps since Android 10.
 *
 * Every failure has to look like "no answer": an older release, a flow the
 * kernel already forgot, a permission the system no longer grants. The core
 * reads a missing uid as "apply no `$app=` rule at all", never as "apply every
 * one of them", so this stays safe while remaining useful.
 */
private class FrameworkUidLookup(private val context: Context) :
    git.shin.adfree.core.ConnectionUidLookup {

    override fun ownerUid(
        protocol: UByte,
        localIp: String,
        localPort: UShort,
        remoteIp: String,
        remotePort: UShort,
    ): UInt? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return null
        return runCatching {
            val connections = context.getSystemService(android.net.ConnectivityManager::class.java)
                ?: return null
            // The core hands us the IP protocol number (6 TCP, 17 UDP), which
            // is what `getConnectionOwnerUid` documents as its first argument.
            val uid = connections.getConnectionOwnerUid(
                protocol.toInt(),
                java.net.InetSocketAddress(localIp, localPort.toInt()),
                java.net.InetSocketAddress(remoteIp, remotePort.toInt()),
            )
            if (uid == android.os.Process.INVALID_UID) null else uid.toUInt()
        }.getOrNull()
    }
}
