package com.example.ui

import com.example.model.AppFirewallRule
import com.example.model.DnsBlockMode
import com.example.model.DnsProvider
import com.example.model.FilterList
import com.example.model.FilterStatus
import com.example.model.NetworkRequestLog
import com.example.model.ProtectionSettings
import com.example.model.ProtectionStats
import com.example.model.ThreatAnalysisResult

/** Consolidated MVI state. */
data class AdGuardUiState(
    val currentTab: AdGuardTab = AdGuardTab.HOME,
    val settings: ProtectionSettings = ProtectionSettings(),
    val stats: ProtectionStats = ProtectionStats(),
    val logs: List<NetworkRequestLog> = emptyList(),
    val filteredLogs: List<NetworkRequestLog> = emptyList(),
    val filterLists: List<FilterList> = emptyList(),
    val appFirewallRules: List<AppFirewallRule> = emptyList(),
    val dnsProviders: List<DnsProvider> = emptyList(),
    val isVpnActive: Boolean = false,
    val inspectedLog: NetworkRequestLog? = null,
    val searchQuery: String = "",
    val statusFilter: FilterStatus? = null,
    val showCustomRuleDialog: Boolean = false,
    val showOnlineSubDialog: Boolean = false,
    val showCustomRuleEditor: Boolean = false,
    val inspectedApp: AppFirewallRule? = null,
    val appSearchQuery: String = "",
    val appCategoryFilter: String? = null,
    val selectedAppFilter: String? = null,
    val aiLabState: AiLabUiState = AiLabUiState.Idle,
    val showVpnPermissionPrompt: Boolean = false,
    val loadingMessage: String? = null,
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
    data class ToggleBlockQuic(val enabled: Boolean) : AdGuardIntent
    data class ToggleBlockDoh(val enabled: Boolean) : AdGuardIntent
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
    data class AddCustomDnsProvider(val name: String, val address: String) : AdGuardIntent
    data class UpdateAppFirewall(
        val packageName: String,
        val cellular: Boolean? = null,
        val wifi: Boolean? = null,
        val filtered: Boolean? = null,
        val blockWhenScreenOff: Boolean? = null,
    ) : AdGuardIntent

    data class InspectAppDetails(val app: AppFirewallRule?) : AdGuardIntent
    data class ViewAppLogs(val app: AppFirewallRule) : AdGuardIntent
    data class FilterLogsByApp(val appPackageOrName: String?) : AdGuardIntent
    data class AppSearchQueryChanged(val query: String) : AdGuardIntent
    data class AppCategoryFilterChanged(val filter: String?) : AdGuardIntent
    data object ClearLogs : AdGuardIntent
    data object ResetStats : AdGuardIntent
    data class ShowCustomRuleDialog(val show: Boolean) : AdGuardIntent
    data class ShowOnlineSubDialog(val show: Boolean) : AdGuardIntent
    data class ShowCustomRuleEditor(val show: Boolean) : AdGuardIntent
    data class AddOnlineSubscription(val name: String, val url: String, val category: String) : AdGuardIntent
    data class DeleteFilterList(val id: String) : AdGuardIntent
    data class RefreshSubscription(val id: String) : AdGuardIntent
    data object RefreshAllSubscriptions : AdGuardIntent
    data class ToggleFilterList(val id: String, val enabled: Boolean) : AdGuardIntent
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
    data class ShowSnackbar(val message: String) : AdGuardEffect
    data object RequestVpnPermission : AdGuardEffect
}

/** Result shown on the Security Lab screen. */
typealias ThreatAnalysis = ThreatAnalysisResult
