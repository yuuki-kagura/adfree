package com.example.ui

import com.example.model.AppFirewallRule
import com.example.model.DnsProvider
import com.example.model.FilterList
import com.example.model.FilterStatus
import com.example.model.NetworkRequestLog
import com.example.model.ProtectionSettings
import com.example.model.ProtectionStats
import com.example.model.ThreatAnalysisResult

/**
 * Consolidated immutable UI State according to Google Modern Android MVI Architecture.
 */
data class AdGuardUiState(
    val currentTab: AdGuardTab = AdGuardTab.HOME,
    val settings: ProtectionSettings = ProtectionSettings(),
    val stats: ProtectionStats = ProtectionStats(),
    val logs: List<NetworkRequestLog> = emptyList(),
    val filteredLogs: List<NetworkRequestLog> = emptyList(),
    val filterLists: List<FilterList> = emptyList(),
    val appFirewallRules: List<AppFirewallRule> = emptyList(),
    val dnsProviders: List<DnsProvider> = emptyList(),
    val inspectedLog: NetworkRequestLog? = null,
    val searchQuery: String = "",
    val statusFilter: FilterStatus? = null,
    val isSimulationModeEnabled: Boolean = false, // UI test simulation toggle requested by user
    val showCustomRuleDialog: Boolean = false,
    val showOnlineSubDialog: Boolean = false,
    val showCustomRuleEditor: Boolean = false,
    val inspectedApp: AppFirewallRule? = null,
    val appSearchQuery: String = "",
    val appCategoryFilter: String? = null,
    val selectedAppFilter: String? = null, // Filter query log by specific app
    val aiMode: AiAnalysisMode = AiAnalysisMode.SEARCH_GROUNDING,
    val aiLabState: AiLabUiState = AiLabUiState.Idle,
    val isUpdatingFilters: Boolean = false
)

/**
 * MVI Intents (User Actions & System Events).
 */
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
    data class ToggleSimulationMode(val enabled: Boolean) : AdGuardIntent
    data class SearchQueryChanged(val query: String) : AdGuardIntent
    data class FilterStatusChanged(val status: FilterStatus?) : AdGuardIntent
    data class InspectLog(val log: NetworkRequestLog?) : AdGuardIntent
    data class AddCustomRule(val rule: String) : AdGuardIntent
    data class RemoveCustomRule(val rule: String) : AdGuardIntent
    data class UpdateAllCustomRules(val rules: List<String>) : AdGuardIntent
    data class AddToWhitelist(val domain: String) : AdGuardIntent
    data class AddToBlacklist(val domain: String) : AdGuardIntent
    data class SelectDnsProvider(val id: String) : AdGuardIntent
    data class UpdateAppFirewall(
        val packageName: String,
        val cellular: Boolean? = null,
        val wifi: Boolean? = null,
        val filtered: Boolean? = null,
        val blockWhenScreenOff: Boolean? = null
    ) : AdGuardIntent
    data class InspectAppDetails(val app: AppFirewallRule?) : AdGuardIntent
    data class ViewAppLogs(val app: AppFirewallRule) : AdGuardIntent
    data class FilterLogsByApp(val appPackageOrName: String?) : AdGuardIntent
    data class AppSearchQueryChanged(val query: String) : AdGuardIntent
    data class AppCategoryFilterChanged(val filter: String?) : AdGuardIntent
    data object ClearLogs : AdGuardIntent
    data class ShowCustomRuleDialog(val show: Boolean) : AdGuardIntent
    data class ShowOnlineSubDialog(val show: Boolean) : AdGuardIntent
    data class ShowCustomRuleEditor(val show: Boolean) : AdGuardIntent
    data class AddOnlineSubscription(val name: String, val url: String, val category: String) : AdGuardIntent
    data class DeleteFilterList(val id: String) : AdGuardIntent
    data class RefreshSubscription(val id: String) : AdGuardIntent
    data class SetAiMode(val mode: AiAnalysisMode) : AdGuardIntent
    data class RunThreatScan(val domain: String) : AdGuardIntent
    data object ResetAiLab : AdGuardIntent
    data object UpdateFilterLists : AdGuardIntent
    data class UpdateStealth(
        val stripUtm: Boolean? = null,
        val blockWebRtc: Boolean? = null,
        val disguiseUa: Boolean? = null,
        val blockCookies: Boolean? = null
    ) : AdGuardIntent
}

/**
 * One-off UI side-effects (Navigation, Snackbars, System Dialogs).
 */
sealed interface AdGuardEffect {
    data class ShowSnackbar(val message: String) : AdGuardEffect
    data object RequestVpnPermission : AdGuardEffect
}
