package git.shin.adfree.ui

import git.shin.adfree.model.AppFirewallRule
import git.shin.adfree.model.AppLanguage
import git.shin.adfree.model.DnsBlockMode
import git.shin.adfree.model.DnsProvider
import git.shin.adfree.model.DnsRewriteRule
import git.shin.adfree.model.FilterList
import git.shin.adfree.model.FilterStatus
import git.shin.adfree.model.NetworkRequestLog
import git.shin.adfree.model.ProtectionSettings
import git.shin.adfree.model.ProtectionStats
import git.shin.adfree.model.ProtocolType
import git.shin.adfree.model.ThreatAnalysisResult
import git.shin.adfree.model.ThemeMode
import git.shin.adfree.model.UserScriptInfo
import git.shin.adfree.model.UserScriptStoreSort
import git.shin.adfree.model.UserScriptStoreState

/** Consolidated MVI state. */
data class AdGuardUiState(
    val currentTab: AdGuardTab = AdGuardTab.HOME,
    val settings: ProtectionSettings = ProtectionSettings(),
    val stats: ProtectionStats = ProtectionStats(),
    val logs: List<NetworkRequestLog> = emptyList(),
    val filteredLogs: List<NetworkRequestLog> = emptyList(),
    val logTotal: Long = 0L,
    val filterLists: List<FilterList> = emptyList(),
    val appFirewallRules: List<AppFirewallRule> = emptyList(),
    /** package -> display name for every installed app, regardless of the Apps tab filter. */
    val appNames: Map<String, String> = emptyMap(),
    val dnsProviders: List<DnsProvider> = emptyList(),
    val dnsRewrites: List<DnsRewriteRule> = emptyList(),
    val isDnsProbeRunning: Boolean = false,
    val isVpnActive: Boolean = false,
    val inspectedLog: NetworkRequestLog? = null,
    val searchQuery: String = "",
    val statusFilter: FilterStatus? = null,
    val showCustomRuleDialog: Boolean = false,
    val showCustomRuleEditor: Boolean = false,
    val inspectedApp: AppFirewallRule? = null,
    val appSearchQuery: String = "",
    val appCategoryFilter: String? = null,
    val selectedAppFilter: String? = null,
    val aiLabState: AiLabUiState = AiLabUiState.Idle,
    val showVpnPermissionPrompt: Boolean = false,
    val loadingMessage: UiText? = null,
    // Filters tab
    val filterSearchQuery: String = "",
    val inspectedFilterId: String? = null,
    val showAddFilterDialog: Boolean = false,
    val userscripts: List<UserScriptInfo> = emptyList(),
    val scriptsMasterEnabled: Boolean = false,
    val inspectedScriptId: String? = null,
    val showAddScriptDialog: Boolean = false,
    val showScriptStore: Boolean = false,
    val scriptStore: UserScriptStoreState = UserScriptStoreState(),
)

/** MVI intents. */
sealed interface AdGuardIntent {
    data class SelectTab(val tab: AdGuardTab) : AdGuardIntent
    data object ToggleProtection : AdGuardIntent
    data object ToggleAdBlocking : AdGuardIntent
    data object ToggleTracking : AdGuardIntent
    data object ToggleDns : AdGuardIntent
    data object ToggleHttps : AdGuardIntent
    data object ToggleFirewall : AdGuardIntent
    data object ToggleEcoMode : AdGuardIntent
    data object ToggleStealth : AdGuardIntent
    data class SetAppLanguage(val language: AppLanguage) : AdGuardIntent
    data class SetThemeMode(val mode: ThemeMode) : AdGuardIntent
    data class ToggleBlockQuic(val enabled: Boolean) : AdGuardIntent
    data class ToggleBlockDoh(val enabled: Boolean) : AdGuardIntent
    data class ToggleBlockDot(val enabled: Boolean) : AdGuardIntent
    data class ToggleSafeSearch(val enabled: Boolean) : AdGuardIntent
    data class ToggleSmartFiltering(val enabled: Boolean) : AdGuardIntent
    /** Element hiding and scriptlets; only takes effect with HTTPS filtering. */
    data class ToggleCosmeticFiltering(val enabled: Boolean) : AdGuardIntent
    /** Terminate and filter QUIC instead of dropping it; needs HTTPS filtering. */
    data class ToggleFilterHttp3(val enabled: Boolean) : AdGuardIntent
    /** Restore protection after a reboot; requires the user's opt-in. */
    data class ToggleAutoStart(val enabled: Boolean) : AdGuardIntent
    /** Subscription refresh interval in hours; 0 turns it off. */
    data class SetFilterAutoUpdate(val hours: Int) : AdGuardIntent
    data class ToggleLogAllowed(val enabled: Boolean) : AdGuardIntent
    data class SetBlockMode(val mode: DnsBlockMode) : AdGuardIntent
    data class SearchQueryChanged(val query: String) : AdGuardIntent
    data class FilterStatusChanged(val status: FilterStatus?) : AdGuardIntent
    data class InspectLog(val log: NetworkRequestLog?) : AdGuardIntent
    data class AddCustomRule(val rule: String) : AdGuardIntent
    data class RemoveCustomRule(val rule: String) : AdGuardIntent
    data class UpdateAllCustomRules(val rules: List<String>) : AdGuardIntent
    data class AddToWhitelist(val domain: String) : AdGuardIntent
    data class AddToBlacklist(val domain: String) : AdGuardIntent
    data class SelectDnsProvider(val id: String) : AdGuardIntent
    data class AddCustomDnsProvider(
        val name: String,
        val address: String,
        val type: ProtocolType = ProtocolType.DNS_UDP,
    ) : AdGuardIntent
    data class ProbeDnsProvider(val id: String) : AdGuardIntent
    data class AddDnsRewrite(val host: String, val answer: String) : AdGuardIntent
    data class RemoveDnsRewrite(val host: String) : AdGuardIntent
    data class UpdateAppFirewall(
        val packageName: String,
        val cellular: Boolean? = null,
        val wifi: Boolean? = null,
        val filtered: Boolean? = null,
        val blockWhenScreenOff: Boolean? = null,
        val httpsFiltered: Boolean? = null,
    ) : AdGuardIntent
    /** Rebuild the running tunnel so the latest app exclusions apply. */
    data object RestartVpn : AdGuardIntent

    data class InspectAppDetails(val app: AppFirewallRule?) : AdGuardIntent
    data class ViewAppLogs(val app: AppFirewallRule) : AdGuardIntent
    data class FilterLogsByApp(val appPackageOrName: String?) : AdGuardIntent
    data class AppSearchQueryChanged(val query: String) : AdGuardIntent
    data class AppCategoryFilterChanged(val filter: String?) : AdGuardIntent
    data object ClearLogs : AdGuardIntent
    data object ResetStats : AdGuardIntent
    data object LoadMoreLogs : AdGuardIntent

    /** Sent by the log screen as it is scrolled to its top (or away from it). */
    data class SetLogTailing(val tailing: Boolean) : AdGuardIntent
    data class ShowCustomRuleDialog(val show: Boolean) : AdGuardIntent
    data class ShowCustomRuleEditor(val show: Boolean) : AdGuardIntent
    data class FilterSearchQueryChanged(val query: String) : AdGuardIntent
    data class ShowAddFilterDialog(val show: Boolean) : AdGuardIntent
    data class AddCustomFilter(val name: String, val url: String) : AdGuardIntent
    data class ImportLocalFilter(val uri: String) : AdGuardIntent
    /** Write settings + filter choices to a JSON backup (SAF URI). */
    data class ExportBackup(val uri: String) : AdGuardIntent
    /** Restore settings + filter choices from a JSON backup (SAF URI). */
    data class ImportBackup(val uri: String) : AdGuardIntent
    data class InspectFilter(val id: String?) : AdGuardIntent
    data object RestoreDefaultFilters : AdGuardIntent
    data class ShowAddScriptDialog(val show: Boolean) : AdGuardIntent
    /** Add a userscript from a URL. */
    data class AddScript(val name: String, val url: String) : AdGuardIntent
    /** Import a userscript body from a file (SAF URI). */
    data class ImportLocalScript(val uri: String) : AdGuardIntent
    /** Create a new userscript from text (editor). */
    data class CreateScript(val name: String, val text: String) : AdGuardIntent
    /** Overwrite an existing userscript body and save it. */
    data class UpdateScriptText(val id: String, val name: String, val text: String) : AdGuardIntent
    data class ShowScriptStore(val show: Boolean) : AdGuardIntent
    data class SearchScriptStore(val query: String) : AdGuardIntent
    data class SortScriptStore(val sort: UserScriptStoreSort) : AdGuardIntent
    data object LoadMoreScriptStore : AdGuardIntent
    data class InstallStoreScript(
        val name: String,
        val url: String,
        val description: String,
    ) : AdGuardIntent
    data class ToggleScript(val id: String, val enabled: Boolean) : AdGuardIntent
    data class ToggleScriptsMaster(val enabled: Boolean) : AdGuardIntent
    data class RefreshScript(val id: String) : AdGuardIntent
    data class DeleteScript(val id: String) : AdGuardIntent
    data class InspectScript(val id: String?) : AdGuardIntent
    data class DeleteFilterList(val id: String) : AdGuardIntent
    /** Edits a user-added list's name and/or source URL. */
    data class UpdateCustomFilter(val id: String, val name: String, val url: String) : AdGuardIntent
    data class RefreshSubscription(val id: String) : AdGuardIntent
    data object RefreshAllSubscriptions : AdGuardIntent
    data class ToggleFilterList(val id: String, val enabled: Boolean) : AdGuardIntent
    data class SetFilterTrusted(val id: String, val trusted: Boolean) : AdGuardIntent
    data class RunThreatScan(val domain: String) : AdGuardIntent
    data object ResetAiLab : AdGuardIntent
    data class UpdateStealth(
        val stripUtm: Boolean? = null,
        val blockWebRtc: Boolean? = null,
        val disguiseUa: Boolean? = null,
        val blockCookies: Boolean? = null,
    ) : AdGuardIntent

    data object DismissLoading : AdGuardIntent
    data class VpnPermissionResolved(val granted: Boolean) : AdGuardIntent
    data object DismissVpnPermission : AdGuardIntent
}

/** One-off side effects. */
sealed interface AdGuardEffect {
    data class ShowSnackbar(val message: UiText) : AdGuardEffect
    data object RequestVpnPermission : AdGuardEffect
}

/** Result shown on the Security Lab screen. */
typealias ThreatAnalysis = ThreatAnalysisResult
