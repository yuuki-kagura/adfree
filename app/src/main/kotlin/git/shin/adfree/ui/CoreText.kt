package git.shin.adfree.ui

import git.shin.adfree.l10n.Strings
import git.shin.adfree.R
import git.shin.adfree.core.BackupError
import git.shin.adfree.core.ConfigWarning
import git.shin.adfree.core.DnsError
import git.shin.adfree.core.DnsProbeError
import git.shin.adfree.core.DnsProbeResult
import git.shin.adfree.core.DnsRewriteError
import git.shin.adfree.core.DownloadError
import git.shin.adfree.core.TrustDetail
import git.shin.adfree.model.FilterUrlError

/**
 * Maps codes returned by the Rust core to localized wording. Rust never
 * formats user-facing text; Kotlin owns every string.
 */
object CoreText {

    fun configWarning(warning: ConfigWarning): UiText? = when (warning) {
        ConfigWarning.NONE -> null
        ConfigWarning.PROVIDER_MISSING -> UiText.Resource(Strings.config_warning_provider_missing)
        ConfigWarning.ADDRESS_INVALID -> UiText.Resource(Strings.config_warning_address_invalid)
        ConfigWarning.PROXY_INVALID -> UiText.Resource(Strings.config_warning_proxy_invalid)
        ConfigWarning.STORE_UNAVAILABLE -> UiText.Resource(Strings.config_warning_store_unavailable)
    }

    fun backupError(error: BackupError): UiText? = when (error) {
        BackupError.NONE -> null
        BackupError.NOT_BACKUP -> UiText.Resource(Strings.backup_error_not_backup)
        BackupError.UNSUPPORTED_VERSION -> UiText.Resource(Strings.backup_error_unsupported_version)
        BackupError.MALFORMED -> UiText.Resource(Strings.backup_error_malformed)
        BackupError.STORE_UNAVAILABLE -> UiText.Resource(Strings.backup_error_store_unavailable)
    }

    fun dnsError(error: DnsError): UiText? = when (error) {
        DnsError.NONE -> null
        DnsError.EMPTY -> UiText.Resource(Strings.dns_error_empty)
        DnsError.INVALID_ADDRESS -> UiText.Resource(Strings.dns_error_invalid_address)
        DnsError.INVALID_PORT -> UiText.Resource(Strings.dns_error_invalid_port)
        DnsError.UNSUPPORTED_SCHEME -> UiText.Resource(Strings.dns_error_unsupported_scheme)
        DnsError.IP_V6_UDP_UNSUPPORTED -> UiText.Resource(Strings.dns_error_ipv6_udp_unsupported)
    }

    fun dnsRewriteError(error: DnsRewriteError): UiText? = when (error) {
        DnsRewriteError.NONE -> null
        DnsRewriteError.HOST_EMPTY -> UiText.Resource(Strings.dns_rewrite_error_host_empty)
        DnsRewriteError.HOST_INVALID -> UiText.Resource(Strings.dns_rewrite_error_host_invalid)
        DnsRewriteError.ANSWER_EMPTY -> UiText.Resource(Strings.dns_rewrite_error_answer_empty)
        DnsRewriteError.ANSWER_INVALID -> UiText.Resource(Strings.dns_rewrite_error_answer_invalid)
    }

    /** One line for the probe result: latency on success, the reason on failure. */
    fun dnsProbeResult(result: DnsProbeResult): UiText =
        if (result.ok) {
            UiText.Formatted(Strings.dns_probe_ok, result.latencyMs.toInt())
        } else {
            dnsProbeError(result.error) ?: UiText.Resource(Strings.dns_probe_failed)
        }

    private fun dnsProbeError(error: DnsProbeError): UiText? = when (error) {
        DnsProbeError.NONE -> null
        DnsProbeError.ADDRESS_INVALID -> UiText.Resource(Strings.dns_probe_address_invalid)
        DnsProbeError.UNSUPPORTED -> UiText.Resource(Strings.dns_probe_unsupported)
        DnsProbeError.PROTECTED_SOCKET -> UiText.Resource(Strings.dns_probe_protected_socket)
        DnsProbeError.NETWORK -> UiText.Resource(Strings.dns_probe_network)
        DnsProbeError.TIMEOUT -> UiText.Resource(Strings.dns_probe_timeout)
        DnsProbeError.BAD_RESPONSE -> UiText.Resource(Strings.dns_probe_bad_response)
    }

    fun downloadError(error: DownloadError): UiText? = when (error) {
        DownloadError.NONE -> null
        DownloadError.STORE_UNAVAILABLE -> UiText.Resource(Strings.download_error_store_unavailable)
        DownloadError.NO_URL -> UiText.Resource(Strings.download_error_no_url)
        DownloadError.HTTP -> UiText.Resource(Strings.download_error_http)
        DownloadError.EMPTY -> UiText.Resource(Strings.download_error_empty)
        DownloadError.NETWORK -> UiText.Resource(Strings.download_error_network)
        DownloadError.WRITE -> UiText.Resource(Strings.download_error_write)
        DownloadError.TOO_LARGE -> UiText.Resource(Strings.download_error_too_large)
    }

    internal fun filterUrlError(error: FilterUrlError): UiText = when (error) {
        FilterUrlError.EMPTY -> UiText.Resource(Strings.filter_url_empty)
        FilterUrlError.TOO_LONG -> UiText.Resource(Strings.filter_url_too_long)
        FilterUrlError.INVALID -> UiText.Resource(Strings.filter_url_invalid)
        FilterUrlError.UNSUPPORTED_SCHEME -> UiText.Resource(Strings.filter_url_scheme)
        FilterUrlError.NO_HOST -> UiText.Resource(Strings.filter_url_no_host)
    }

    fun trustDetail(detail: TrustDetail): UiText? = when (detail) {
        TrustDetail.NONE -> null
        TrustDetail.PLATFORM_UNSUPPORTED -> UiText.Resource(Strings.trust_platform_unsupported)
        TrustDetail.INVALID_CA -> UiText.Resource(Strings.trust_invalid_ca)
        TrustDetail.SU_MISSING -> UiText.Resource(Strings.trust_su_missing)
        TrustDetail.ALREADY_INSTALLED -> UiText.Resource(Strings.trust_already_installed)
        TrustDetail.ROOT_GRANTED -> UiText.Resource(Strings.trust_root_granted)
        TrustDetail.ROOT_PENDING -> UiText.Resource(Strings.trust_root_pending)
        TrustDetail.PERMISSION_DENIED -> UiText.Resource(Strings.trust_permission_denied)
        TrustDetail.MAGISK_MODULE_WRITTEN -> UiText.Resource(Strings.trust_magisk_written)
        TrustDetail.MAGISK_WRITE_FAILED -> UiText.Resource(Strings.trust_magisk_write_failed)
        TrustDetail.INSTALLED_LIVE -> UiText.Resource(Strings.trust_installed_live)
        TrustDetail.MOUNT_PENDING -> UiText.Resource(Strings.trust_mount_pending)
        TrustDetail.MOUNT_FAILED -> UiText.Resource(Strings.trust_mount_failed)
        TrustDetail.UNINSTALLED -> UiText.Resource(Strings.trust_uninstalled)
        TrustDetail.UNINSTALLED_NEEDS_REBOOT -> UiText.Resource(Strings.trust_uninstalled_reboot)
        TrustDetail.UNINSTALL_FAILED -> UiText.Resource(Strings.trust_uninstall_failed)
        TrustDetail.NEEDS_ROOT -> UiText.Resource(Strings.trust_needs_root)
        TrustDetail.NEEDS_ROOT_TO_REMOVE -> UiText.Resource(Strings.trust_needs_root_remove)
        TrustDetail.TEMP_WRITE_FAILED -> UiText.Resource(Strings.trust_temp_write_failed)
        TrustDetail.INSTALLED_LINUX -> UiText.Resource(Strings.trust_installed_linux)
        TrustDetail.LINUX_INSTALL_FAILED -> UiText.Resource(Strings.trust_linux_install_failed)
        TrustDetail.REMOVED_LINUX -> UiText.Resource(Strings.trust_removed_linux)
        TrustDetail.LINUX_REMOVE_FAILED -> UiText.Resource(Strings.trust_linux_remove_failed)
        TrustDetail.NO_CA -> UiText.Resource(Strings.trust_no_ca)
        TrustDetail.NO_CA_TO_REMOVE -> UiText.Resource(Strings.trust_no_ca_remove)
    }
}
