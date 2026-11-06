package git.shin.adfree.ui

import git.shin.adfree.model.AppFirewallRule
import git.shin.adfree.model.AppLanguage
import git.shin.adfree.model.AppUsageRange
import git.shin.adfree.model.AppUsageTransport
import git.shin.adfree.model.DnsBackup
import git.shin.adfree.model.DnsBackupMode
import git.shin.adfree.model.DnsBlockMode
import git.shin.adfree.model.DnsProvider
import git.shin.adfree.model.DnsRewriteRule
import git.shin.adfree.model.FilterList
import git.shin.adfree.model.FilterStatus
import git.shin.adfree.model.FirewallAccess
import git.shin.adfree.model.LogLevel
import git.shin.adfree.model.LogRuleSwitch
import git.shin.adfree.model.LogTypeTab
import git.shin.adfree.model.LogWindowTotals
import git.shin.adfree.model.NetworkRequestLog
import git.shin.adfree.model.ProtectionSettings
import git.shin.adfree.model.ProtectionStats
import git.shin.adfree.model.ProtocolType
import git.shin.adfree.model.ProxyAccess
import git.shin.adfree.model.ServiceUsage
import git.shin.adfree.model.StealthPreset
import git.shin.adfree.model.ThreatAnalysisResult
import git.shin.adfree.model.ThemeMode
import git.shin.adfree.model.UserScriptInfo
import git.shin.adfree.model.UserScriptStoreSort
import git.shin.adfree.model.UserScriptStoreState

enum class AdGuardTab { HOME, PROTECTION, ACTIVITY, APPS, STATISTICS, AI_LAB, SETTINGS }

sealed interface AiLabUiState {
    data object Idle : AiLabUiState
    data class Loading(val message: UiText) : AiLabUiState
    data class Success(val result: ThreatAnalysisResult) : AiLabUiState
    data class Error(val message: UiText) : AiLabUiState
}

/** Consolidated MVI state. */
data class AdGuardUiState(
    val currentTab: AdGuardTab = AdGuardTab.HOME,
    val settings: ProtectionSettings = ProtectionSettings(),
    val stats: ProtectionStats = ProtectionStats(),
    /** Totals for the Statistics tab's selected window and network. */
    val windowTotals: LogWindowTotals = LogWindowTotals(),
    /**
     * Per-domain groups for the services breakdown, same window as
     * [windowTotals]. Empty while the switch is off — the section then shows
     * nothing rather than an empty list.
     */
    val serviceUsage: List<ServiceUsage> = emptyList(),
    val logs: List<NetworkRequestLog> = emptyList(),
    val filteredLogs: List<NetworkRequestLog> = emptyList(),
    val logTotal: Long = 0L,
    /** Whole-log totals per decision; the chips count the log, not the window. */
    val logBlockedTotal: Long = 0L,
    val logAllowedTotal: Long = 0L,
    /**
     * Name of the log file the screen is reading, null while it shows the
     * live log. [logs] and the three totals above describe that file instead
     * of the store while it is set.
     */
    val importedLogName: String? = null,
    val filterLists: List<FilterList> = emptyList(),
    val appFirewallRules: List<AppFirewallRule> = emptyList(),
    /** Every installed app, before the Apps-tab search and chip filters. */
    val allAppFirewallRules: List<AppFirewallRule> = emptyList(),
    /** package -> display name for every installed app, regardless of the Apps tab filter. */
    val appNames: Map<String, String> = emptyMap(),
    val dnsProviders: List<DnsProvider> = emptyList(),
    val dnsRewrites: List<DnsRewriteRule> = emptyList(),
    val dnsBackup: DnsBackup? = null,
    val dnsBackupMode: DnsBackupMode = DnsBackupMode.SYSTEM,
    val isDnsProbeRunning: Boolean = false,
    val isVpnActive: Boolean = false,
    val inspectedLog: NetworkRequestLog? = null,
    val searchQuery: String = "",
    val statusFilter: FilterStatus? = null,
    /**
     * The log's request-type tab, the strip across the top of AdGuard's own
     * log. `ALL` keeps every row.
     */
    val logTypeFilter: LogTypeTab = LogTypeTab.ALL,
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
    val showAddDnsFilterDialog: Boolean = false,
    val userscripts: List<UserScriptInfo> = emptyList(),
    val scriptsMasterEnabled: Boolean = false,
    val inspectedScriptId: String? = null,
    val showAddScriptDialog: Boolean = false,
    val showScriptStore: Boolean = false,
    val scriptStore: UserScriptStoreState = UserScriptStoreState(),
)

/** A Protection-tab detail page another screen can navigate to directly. */
enum class ProtectionSection {
    AD_BLOCKING, ANNOYANCES, TRACKING, DNS, HTTPS, FIREWALL, BROWSING_SECURITY, ECO, FILTERS, EXTENSIONS
}

/** MVI intents. */
sealed interface AdGuardIntent {
    data class SelectTab(val tab: AdGuardTab) : AdGuardIntent

    /** Open the Protection tab landing on one module's detail page. */
    data class OpenProtectionSection(val section: ProtectionSection) : AdGuardIntent
    data object ToggleProtection : AdGuardIntent
    data object ToggleAdBlocking : AdGuardIntent
    data object ToggleAnnoyances : AdGuardIntent
    data object ToggleBrowsingSecurity : AdGuardIntent
    data object ToggleTracking : AdGuardIntent
    data object ToggleDns : AdGuardIntent
    data object ToggleHttps : AdGuardIntent
    data object ToggleFirewall : AdGuardIntent
    data object ToggleEcoMode : AdGuardIntent
    data object ToggleStealth : AdGuardIntent
    /** Writes one privacy level's documented switch set. */
    data class SetStealthPreset(val preset: StealthPreset) : AdGuardIntent
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
    /** How much of the core's own diagnostics the log ring keeps. */
    data class SetLogLevel(val level: LogLevel) : AdGuardIntent
    /** Whether another app may switch protection, once it proves the token. */
    data class ToggleExternalControl(val enabled: Boolean) : AdGuardIntent
    /** Retires the current token; the switch goes back off with it. */
    data object RotateControlToken : AdGuardIntent
    data class SetBlockMode(val mode: DnsBlockMode) : AdGuardIntent
    data class SearchQueryChanged(val query: String) : AdGuardIntent
    data class FilterStatusChanged(val status: FilterStatus?) : AdGuardIntent
    /** Picks the log's request-type tab; [LogTypeTab.ALL] clears it. */
    data class FilterLogTypeChanged(val tab: LogTypeTab) : AdGuardIntent
    data class InspectLog(val log: NetworkRequestLog?) : AdGuardIntent
    /**
     * Switches one of the rules the detail panel lists for a request. Kept
     * separate from [ToggleFilterList] and [ReplaceCustomRule] because the
     * panel also reports the change back with a way to take it undone.
     */
    data class SwitchLogRule(val rule: LogRuleSwitch, val enabled: Boolean) : AdGuardIntent
    data class AddCustomRule(val rule: String) : AdGuardIntent
    data class RemoveCustomRule(val rule: String) : AdGuardIntent
    data class ReplaceCustomRule(val oldRule: String, val newRule: String) : AdGuardIntent
    data class UpdateAllCustomRules(val rules: List<String>) : AdGuardIntent
    data class SelectDnsProvider(val id: String) : AdGuardIntent
    data class AddCustomDnsProvider(
        val name: String,
        val address: String,
        val type: ProtocolType = ProtocolType.DNS_UDP,
    ) : AdGuardIntent
    data class ProbeDnsProvider(val id: String) : AdGuardIntent
    /** Fallback choice; [providerId] is required only for [DnsBackupMode.FIXED]. */
    data class SetBackupDns(
        val mode: DnsBackupMode,
        val providerId: String? = null,
    ) : AdGuardIntent
    data class AddDnsRewrite(val host: String, val answer: String) : AdGuardIntent
    data class RemoveDnsRewrite(val host: String) : AdGuardIntent
    data class UpdateAppFirewall(
        val packageName: String,
        /** Display name used when the package has no row yet. */
        val appName: String? = null,
        val wifi: FirewallAccess? = null,
        val wifiScreenOff: FirewallAccess? = null,
        val cellular: FirewallAccess? = null,
        val cellularScreenOff: FirewallAccess? = null,
        val roaming: FirewallAccess? = null,
        val filtered: Boolean? = null,
        val httpsFiltered: Boolean? = null,
        val notifyBlocked: Boolean? = null,
        val proxyAccess: ProxyAccess? = null,
    ) : AdGuardIntent
    /** Global defaults and the two rule-set gates. */
    data class UpdateFirewallSettings(
        val globalRules: Boolean? = null,
        val customRules: Boolean? = null,
        val notifications: Boolean? = null,
        val allowWifi: Boolean? = null,
        val allowWifiScreenOff: Boolean? = null,
        val allowCellular: Boolean? = null,
        val allowCellularScreenOff: Boolean? = null,
        val allowRoaming: Boolean? = null,
    ) : AdGuardIntent
    /** Resets only the firewall section: defaults, overrides and mutes. */
    data object ResetFirewall : AdGuardIntent
    /** Creates the row for an app picked from the firewall app sheet. */
    data class EnsureFirewallApp(val packageName: String, val appName: String) : AdGuardIntent
    /** Opens the Apps-tab detail sheet for one package (quick-action menus). */
    data class OpenAppManagement(val app: AppFirewallRule) : AdGuardIntent
    /** Rebuild the running tunnel so the latest app exclusions apply. */
    data object RestartVpn : AdGuardIntent

    data class InspectAppDetails(val app: AppFirewallRule?) : AdGuardIntent
    data class ViewAppLogs(val app: AppFirewallRule) : AdGuardIntent
    data class FilterLogsByApp(val appPackageOrName: String?) : AdGuardIntent
    data class AppSearchQueryChanged(val query: String) : AdGuardIntent
    data class AppCategoryFilterChanged(val filter: String?) : AdGuardIntent
    data class SetAppUsageRange(val range: AppUsageRange) : AdGuardIntent
    data class SetAppUsageTransport(val transport: AppUsageTransport) : AdGuardIntent
    data object ClearLogs : AdGuardIntent
    data object ResetStats : AdGuardIntent
    data object LoadMoreLogs : AdGuardIntent
    /** Write the loaded activity window to a CSV document (SAF URI). */
    data class ExportLogs(val uri: String) : AdGuardIntent
    /** Show a CSV document the user picked, instead of this machine's log. */
    data class ImportLogs(val uri: String) : AdGuardIntent
    /** Leave the imported file and go back to the live log. */
    data object CloseImportedLogs : AdGuardIntent

    /** Sent by the log screen as it is scrolled to its top (or away from it). */
    data class SetLogTailing(val tailing: Boolean) : AdGuardIntent
    data class ShowCustomRuleDialog(val show: Boolean) : AdGuardIntent
    data class ShowCustomRuleEditor(val show: Boolean) : AdGuardIntent
    data class FilterSearchQueryChanged(val query: String) : AdGuardIntent
    data class ShowAddFilterDialog(val show: Boolean) : AdGuardIntent
    data class ShowAddDnsFilterDialog(val show: Boolean) : AdGuardIntent
    data class AddCustomFilter(val name: String, val url: String) : AdGuardIntent
    /** Adds a subscription under "DNS filters" (name lookups only). */
    data class AddDnsFilter(val name: String, val url: String) : AdGuardIntent
    data class ImportLocalFilter(val uri: String, val dnsOnly: Boolean = false) : AdGuardIntent
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
    /** Turns the per-domain breakdown on the Statistics tab on or off. */
    data class SetServicesBreakdown(val visible: Boolean) : AdGuardIntent
    /** Subscribed table of domain owners; an empty URL restores the shipped one. */
    data class SetServicesTableUrl(val url: String) : AdGuardIntent
    data object RefreshServicesTable : AdGuardIntent
    /** Replaces the services table with a dataset in a file the user picked. */
    data class ImportServicesTable(val uri: String) : AdGuardIntent
    data class RunThreatScan(val domain: String) : AdGuardIntent
    data object ResetAiLab : AdGuardIntent
    /**
     * Writes one or more stealth sub-switches. A `null` means "not this row's
     * business" and keeps the stored value, so a toggle cannot reset its
     * neighbours and a privacy level can write a whole set in one intent.
     */
    data class UpdateStealth(
        val stripUtm: Boolean? = null,
        val blockWebRtc: Boolean? = null,
        val disguiseUa: Boolean? = null,
        val blockCookies: Boolean? = null,
        val blockAllCookies: Boolean? = null,
        val stripEtag: Boolean? = null,
        val stripThirdPartyAuthorization: Boolean? = null,
        val hideThirdPartyReferer: Boolean? = null,
        val injectGpcDnt: Boolean? = null,
        val hideSearchQuery: Boolean? = null,
        val blockPushApi: Boolean? = null,
        val blockGeolocationApi: Boolean? = null,
        val antiDpi: Boolean? = null,
        val maskIp: String? = null,
    ) : AdGuardIntent

    data object DismissLoading : AdGuardIntent
    data class VpnPermissionResolved(val granted: Boolean) : AdGuardIntent
    data object DismissVpnPermission : AdGuardIntent
}

/** One-off side effects. */
sealed interface AdGuardEffect {
    data class ShowSnackbar(val message: UiText) : AdGuardEffect

    /**
     * A change the user can take back. [undo] is the intent that puts things
     * the way they were, so the panel does not have to remember the previous
     * state itself; it is sent only when the snackbar's action is pressed.
     */
    data class ShowUndoSnackbar(
        val message: UiText,
        val actionLabel: UiText,
        val undo: AdGuardIntent,
    ) : AdGuardEffect

    data object RequestVpnPermission : AdGuardEffect
}

/** Result shown on the Security Lab screen. */
typealias ThreatAnalysis = ThreatAnalysisResult
