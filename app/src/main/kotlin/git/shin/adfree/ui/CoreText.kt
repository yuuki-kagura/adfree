package git.shin.adfree.ui

import git.shin.adfree.R
import git.shin.adfree.core.BackupError
import git.shin.adfree.core.ConfigWarning
import git.shin.adfree.core.DnsError
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
        ConfigWarning.PROVIDER_MISSING -> UiText.Resource(R.string.config_warning_provider_missing)
        ConfigWarning.ADDRESS_INVALID -> UiText.Resource(R.string.config_warning_address_invalid)
        ConfigWarning.PROXY_INVALID -> UiText.Resource(R.string.config_warning_proxy_invalid)
        ConfigWarning.STORE_UNAVAILABLE -> UiText.Resource(R.string.config_warning_store_unavailable)
    }

    fun backupError(error: BackupError): UiText? = when (error) {
        BackupError.NONE -> null
        BackupError.NOT_BACKUP -> UiText.Resource(R.string.backup_error_not_backup)
        BackupError.UNSUPPORTED_VERSION -> UiText.Resource(R.string.backup_error_unsupported_version)
        BackupError.MALFORMED -> UiText.Resource(R.string.backup_error_malformed)
        BackupError.STORE_UNAVAILABLE -> UiText.Resource(R.string.backup_error_store_unavailable)
    }

    fun dnsError(error: DnsError): UiText? = when (error) {
        DnsError.NONE -> null
        DnsError.EMPTY -> UiText.Resource(R.string.dns_error_empty)
        DnsError.INVALID_ADDRESS -> UiText.Resource(R.string.dns_error_invalid_address)
        DnsError.INVALID_PORT -> UiText.Resource(R.string.dns_error_invalid_port)
        DnsError.UNSUPPORTED_SCHEME -> UiText.Resource(R.string.dns_error_unsupported_scheme)
        DnsError.IP_V6_UDP_UNSUPPORTED -> UiText.Resource(R.string.dns_error_ipv6_udp_unsupported)
    }

    fun downloadError(error: DownloadError): UiText? = when (error) {
        DownloadError.NONE -> null
        DownloadError.STORE_UNAVAILABLE -> UiText.Resource(R.string.download_error_store_unavailable)
        DownloadError.NO_URL -> UiText.Resource(R.string.download_error_no_url)
        DownloadError.HTTP -> UiText.Resource(R.string.download_error_http)
        DownloadError.EMPTY -> UiText.Resource(R.string.download_error_empty)
        DownloadError.NETWORK -> UiText.Resource(R.string.download_error_network)
        DownloadError.WRITE -> UiText.Resource(R.string.download_error_write)
        DownloadError.TOO_LARGE -> UiText.Resource(R.string.download_error_too_large)
    }

    internal fun filterUrlError(error: FilterUrlError): UiText = when (error) {
        FilterUrlError.EMPTY -> UiText.Resource(R.string.filter_url_empty)
        FilterUrlError.TOO_LONG -> UiText.Resource(R.string.filter_url_too_long)
        FilterUrlError.INVALID -> UiText.Resource(R.string.filter_url_invalid)
        FilterUrlError.UNSUPPORTED_SCHEME -> UiText.Resource(R.string.filter_url_scheme)
        FilterUrlError.NO_HOST -> UiText.Resource(R.string.filter_url_no_host)
    }

    fun trustDetail(detail: TrustDetail): UiText? = when (detail) {
        TrustDetail.NONE -> null
        TrustDetail.PLATFORM_UNSUPPORTED -> UiText.Resource(R.string.trust_platform_unsupported)
        TrustDetail.INVALID_CA -> UiText.Resource(R.string.trust_invalid_ca)
        TrustDetail.SU_MISSING -> UiText.Resource(R.string.trust_su_missing)
        TrustDetail.ALREADY_INSTALLED -> UiText.Resource(R.string.trust_already_installed)
        TrustDetail.ROOT_GRANTED -> UiText.Resource(R.string.trust_root_granted)
        TrustDetail.ROOT_PENDING -> UiText.Resource(R.string.trust_root_pending)
        TrustDetail.PERMISSION_DENIED -> UiText.Resource(R.string.trust_permission_denied)
        TrustDetail.MAGISK_MODULE_WRITTEN -> UiText.Resource(R.string.trust_magisk_written)
        TrustDetail.MAGISK_WRITE_FAILED -> UiText.Resource(R.string.trust_magisk_write_failed)
        TrustDetail.INSTALLED_LIVE -> UiText.Resource(R.string.trust_installed_live)
        TrustDetail.MOUNT_PENDING -> UiText.Resource(R.string.trust_mount_pending)
        TrustDetail.MOUNT_FAILED -> UiText.Resource(R.string.trust_mount_failed)
        TrustDetail.UNINSTALLED -> UiText.Resource(R.string.trust_uninstalled)
        TrustDetail.UNINSTALLED_NEEDS_REBOOT -> UiText.Resource(R.string.trust_uninstalled_reboot)
        TrustDetail.UNINSTALL_FAILED -> UiText.Resource(R.string.trust_uninstall_failed)
        TrustDetail.NEEDS_ROOT -> UiText.Resource(R.string.trust_needs_root)
        TrustDetail.NEEDS_ROOT_TO_REMOVE -> UiText.Resource(R.string.trust_needs_root_remove)
        TrustDetail.TEMP_WRITE_FAILED -> UiText.Resource(R.string.trust_temp_write_failed)
        TrustDetail.INSTALLED_LINUX -> UiText.Resource(R.string.trust_installed_linux)
        TrustDetail.LINUX_INSTALL_FAILED -> UiText.Resource(R.string.trust_linux_install_failed)
        TrustDetail.REMOVED_LINUX -> UiText.Resource(R.string.trust_removed_linux)
        TrustDetail.LINUX_REMOVE_FAILED -> UiText.Resource(R.string.trust_linux_remove_failed)
        TrustDetail.NO_CA -> UiText.Resource(R.string.trust_no_ca)
        TrustDetail.NO_CA_TO_REMOVE -> UiText.Resource(R.string.trust_no_ca_remove)
    }
}
