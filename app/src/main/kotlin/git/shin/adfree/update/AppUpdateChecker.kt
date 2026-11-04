package git.shin.adfree.update

import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.FileProvider
import git.shin.adfree.BuildConfig
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

/**
 * Checks the signed APK attached to the newest GitHub Release of this project
 * and installs it through the system package installer.
 *
 * Mirrors the Komorei reader's updater, which is the shape this repo's release
 * workflow produces: one `app-release.apk` asset per release, published by
 * semantic-release, with the tag equal to `versionName`. The GitHub API's
 * server-side `digest` is checked again over the downloaded bytes, and the
 * package itself is verified — same package name, higher versionCode, and the
 * signing certificate of the installed build — before the installer is
 * opened, so a debug build can never be swapped by an APK signed with a
 * different key.
 */
class AppUpdateChecker(
    private val context: Context,
) {
    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .followRedirects(false)
        .build()

    suspend fun checkForUpdate(): Result<UpdateCheckResult> =
        withContext(Dispatchers.IO) {
            try {
                val request =
                    Request
                        .Builder()
                        .url(LATEST_RELEASE_URL)
                        .header("Accept", "application/vnd.github+json")
                        .header("X-GitHub-Api-Version", "2022-11-28")
                        .header("User-Agent", "AdFree/${BuildConfig.VERSION_NAME}")
                        .build()
                val result =
                    client.newCall(request).execute().use { response ->
                        if (!response.isSuccessful) {
                            throw IOException("release request failed (${response.code})")
                        }
                        val release = JSONObject(response.body?.string() ?: throw IOException("empty release body"))
                        val tag = release.optString("tag_name").trim()
                        val version =
                            normalizeVersion(tag)
                                ?: throw IOException("release has an invalid tag")
                        if (!shouldOfferUpdate(version, BuildConfig.VERSION_NAME)) {
                            UpdateCheckResult.UpToDate
                        } else {
                            val asset =
                                findApkAsset(release.optJSONArray("assets"))
                                    ?: throw IOException("release has no unambiguous APK asset")
                            val assetId = asset.optLong("id", -1L)
                            val expectedSize = asset.optLong("size", -1L)
                            val digest = asset.optString("digest")
                            if (assetId <= 0L || expectedSize <= 0L || !digest.isValidSha256Digest()) {
                                throw IOException("release APK metadata is incomplete")
                            }
                            val downloadUrl =
                                asset
                                    .optString("browser_download_url")
                                    .toHttpUrlOrNull()
                                    ?.takeIf { it.scheme == "https" && it.host == "github.com" }
                                    ?.toString()
                                    ?: throw IOException("release APK URL is not trusted")
                            UpdateCheckResult.Available(
                                UpdateInfo(
                                    version = version,
                                    releaseNotes = release.optString("body").take(MAX_RELEASE_NOTES_CHARS),
                                    downloadUrl = downloadUrl,
                                    assetId = assetId,
                                    expectedSize = expectedSize,
                                    sha256 = digest.substring(DIGEST_PREFIX.length),
                                ),
                            )
                        }
                    }
                Result.success(result)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                Result.failure(error)
            }
        }

    /**
     * Downloads the APK into the app cache, verifies size, digest and package
     * signature, then hands it to the system installer. Throws on any failed
     * verification and leaves no file behind.
     */
    suspend fun downloadAndInstall(
        info: UpdateInfo,
        onProgress: (Int) -> Unit = {},
    ) {
        val url =
            info.downloadUrl
                .toHttpUrlOrNull()
                ?.takeIf { it.scheme == "https" && it.host == "github.com" }
                ?: throw IOException("update URL is not trusted")
        withContext(Dispatchers.IO) {
            val directory = File(context.cacheDir, UPDATE_DIRECTORY).apply { mkdirs() }
            val file = File(directory, "adfree-${info.assetId}.apk")
            file.delete()
            try {
                val request =
                    Request
                        .Builder()
                        .url(url)
                        .header("Accept", "application/vnd.android.package-archive")
                        .header("User-Agent", "AdFree/${BuildConfig.VERSION_NAME}")
                        .build()
                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) {
                        throw IOException("download failed (${response.code})")
                    }
                    val body = response.body ?: throw IOException("empty download body")
                    val contentLength = body.contentLength()
                    if (contentLength > 0L && contentLength != info.expectedSize) {
                        throw IOException("content length does not match release metadata")
                    }
                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                    val digest = MessageDigest.getInstance("SHA-256")
                    var total = 0L
                    body.byteStream().use { input ->
                        FileOutputStream(file).use { output ->
                            while (true) {
                                val count = input.read(buffer)
                                if (count < 0) break
                                total += count
                                if (total > MAX_APK_BYTES || total > info.expectedSize) {
                                    throw IOException("APK is larger than the release metadata")
                                }
                                digest.update(buffer, 0, count)
                                output.write(buffer, 0, count)
                                if (info.expectedSize > 0L) {
                                    onProgress(((total * 100L) / info.expectedSize).toInt().coerceIn(0, 99))
                                }
                            }
                        }
                    }
                    if (total != info.expectedSize) {
                        throw IOException("downloaded size does not match release metadata")
                    }
                    val actualDigest = digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
                    if (!actualDigest.equals(info.sha256, ignoreCase = true)) {
                        throw IOException("downloaded APK does not match the release digest")
                    }
                }
                onProgress(100)
                if (!verifyApk(file)) {
                    throw IOException("APK failed package and signature validation")
                }
                installApk(file)
            } catch (error: Exception) {
                file.delete()
                throw error
            }
        }
    }

    private fun findApkAsset(assets: JSONArray?): JSONObject? {
        if (assets == null) return null
        val apkAssets =
            buildList {
                for (index in 0 until assets.length()) {
                    val asset = assets.optJSONObject(index) ?: continue
                    if (asset.optString("name").endsWith(".apk", ignoreCase = true)) {
                        add(asset)
                    }
                }
            }
        // One APK, or none. A release carrying two candidate APKs must not be
        // guessed at: the wrong split build could fail to install, or worse,
        // install over a different abi set.
        return apkAssets.singleOrNull()
    }

    private fun String.isValidSha256Digest(): Boolean =
        startsWith(DIGEST_PREFIX, ignoreCase = true) &&
            length == DIGEST_PREFIX.length + 64 &&
            substring(DIGEST_PREFIX.length).all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }

    private fun verifyApk(file: File): Boolean {
        val packageManager = context.packageManager
        val flags =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageManager.GET_SIGNING_CERTIFICATES
            } else {
                @Suppress("DEPRECATION")
                PackageManager.GET_SIGNATURES
            }
        val downloaded =
            packageManager.getPackageArchiveInfo(file.absolutePath, flags)
                ?: return false
        if (downloaded.packageName != context.packageName) return false

        val current = packageManager.getPackageInfo(context.packageName, flags)
        val downloadedCode = downloaded.longVersionCodeOrVersionCode()
        val currentCode = current.longVersionCodeOrVersionCode()
        if (downloadedCode <= currentCode) return false

        val currentCertificates = certificateFingerprints(current)
        val downloadedCertificates = certificateFingerprints(downloaded)
        return currentCertificates.isNotEmpty() &&
            downloadedCertificates.isNotEmpty() &&
            downloadedCertificates.all { it in currentCertificates }
    }

    @Suppress("DEPRECATION")
    private fun PackageInfo.longVersionCodeOrVersionCode(): Long =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) longVersionCode else versionCode.toLong()

    private fun certificateFingerprints(info: PackageInfo): Set<String> {
        val signatures =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val signingInfo = info.signingInfo ?: return emptySet()
                if (signingInfo.hasMultipleSigners()) {
                    signingInfo.apkContentsSigners
                } else {
                    signingInfo.signingCertificateHistory
                }
            } else {
                @Suppress("DEPRECATION")
                info.signatures
            }
        return signatures
            .orEmpty()
            .map { signature ->
                MessageDigest
                    .getInstance("SHA-256")
                    .digest(signature.toByteArray())
                    .joinToString("") { "%02x".format(it.toInt() and 0xff) }
            }.toSet()
    }

    private fun installApk(file: File) {
        val uri =
            FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                file,
            )
        val intent =
            Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, APK_MIME_TYPE)
                clipData = android.content.ClipData.newRawUri("AdFree update", uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
        context.startActivity(intent)
    }

    private companion object {
        const val LATEST_RELEASE_URL =
            "https://api.github.com/repos/tachibana-shin/adfree/releases/latest"
        const val UPDATE_DIRECTORY = "updates"
        const val APK_MIME_TYPE = "application/vnd.android.package-archive"
        const val DIGEST_PREFIX = "sha256:"
        const val MAX_APK_BYTES = 200L * 1024L * 1024L
        const val MAX_RELEASE_NOTES_CHARS = 10_000
    }
}
