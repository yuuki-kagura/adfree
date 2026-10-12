package com.example.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.ai.GeminiSecurityLabService
import com.example.data.AdGuardRepository
import com.example.model.AppFirewallRule
import com.example.model.FilterStatus
import com.example.model.NetworkRequestLog
import com.example.model.ThreatAnalysisResult
import com.example.vpn.VpnController
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

enum class AdGuardTab {
    HOME,
    ACTIVITY,
    FILTERS,
    APPS,
    AI_LAB,
    SETTINGS
}

enum class AiAnalysisMode {
    SEARCH_GROUNDING, // gemini-3.5-flash with Google Search
    HIGH_THINKING     // gemini-3.1-pro-preview with thinkingLevel HIGH
}

sealed interface AiLabUiState {
    data object Idle : AiLabUiState
    data class Loading(val message: String) : AiLabUiState
    data class Success(val result: ThreatAnalysisResult) : AiLabUiState
    data class Error(val message: String) : AiLabUiState
}

/**
 * Modern Android MVI ViewModel.
 * Unidirectional Data Flow (UDF) adhering to Google Architecture Guidelines.
 */
class AdGuardViewModel(
    private val repository: AdGuardRepository,
    private val aiLabService: GeminiSecurityLabService,
    val vpnController: VpnController
) : ViewModel() {

    private val _currentTab = MutableStateFlow(AdGuardTab.HOME)
    private val _searchQuery = MutableStateFlow("")
    private val _statusFilter = MutableStateFlow<FilterStatus?>(null)
    private val _inspectedLog = MutableStateFlow<NetworkRequestLog?>(null)
    private val _showCustomRuleDialog = MutableStateFlow(false)
    private val _showOnlineSubDialog = MutableStateFlow(false)
    private val _showCustomRuleEditor = MutableStateFlow(false)
    private val _inspectedApp = MutableStateFlow<AppFirewallRule?>(null)
    private val _appSearchQuery = MutableStateFlow("")
    private val _appCategoryFilter = MutableStateFlow<String?>(null)
    private val _selectedAppFilter = MutableStateFlow<String?>(null)
    private val _aiMode = MutableStateFlow(AiAnalysisMode.SEARCH_GROUNDING)
    private val _aiLabState = MutableStateFlow<AiLabUiState>(AiLabUiState.Idle)
    private val _isUpdatingFilters = MutableStateFlow(false)

    // Side-effects channel
    private val _effect = MutableSharedFlow<AdGuardEffect>()
    val effect: SharedFlow<AdGuardEffect> = _effect.asSharedFlow()

    // Consolidated single UiState
    val uiState: StateFlow<AdGuardUiState> = combine(
        combine(
            _currentTab,
            repository.settings,
            repository.stats,
            repository.logs,
            _searchQuery
        ) { tab, settings, stats, logs, query ->
            FiveState(tab, settings, stats, logs, query)
        },
        combine(
            _statusFilter,
            repository.filterLists,
            repository.appFirewallRules,
            repository.dnsProviders,
            repository.isSimulationMode
        ) { status, filters, apps, dns, simMode ->
            FiveStateB(status, filters, apps, dns, simMode)
        },
        combine(
            _inspectedLog,
            _showCustomRuleDialog,
            _showOnlineSubDialog,
            _showCustomRuleEditor,
            _inspectedApp
        ) { inspected, showCustom, showOnline, showEditor, inspectedApp ->
            FiveStateC(inspected, showCustom, showOnline, showEditor, inspectedApp)
        },
        combine(
            _appSearchQuery,
            _appCategoryFilter,
            _selectedAppFilter,
            _aiMode,
            combine(_aiLabState, _isUpdatingFilters) { lab, upd -> Pair(lab, upd) }
        ) { appSearch, appCat, selectedApp, aiMode, (aiLabState, updating) ->
            FiveStateD(appSearch, appCat, selectedApp, aiMode, aiLabState, updating)
        }
    ) { partA, partB, partC, partD ->
        val filteredLogs = partA.logs.filter { log ->
            val matchesQuery = partA.query.isBlank() ||
                log.domain.contains(partA.query, ignoreCase = true) ||
                log.appName.contains(partA.query, ignoreCase = true) ||
                (log.matchedRule?.contains(partA.query, ignoreCase = true) == true)
            val matchesStatus = partB.status == null || log.status == partB.status
            val matchesApp = partD.selectedApp == null ||
                log.appPackage == partD.selectedApp ||
                log.appName.equals(partD.selectedApp, ignoreCase = true)
            matchesQuery && matchesStatus && matchesApp
        }

        val filteredApps = partB.apps.filter { app ->
            val matchesSearch = partD.appSearch.isBlank() ||
                app.appName.contains(partD.appSearch, ignoreCase = true) ||
                app.packageName.contains(partD.appSearch, ignoreCase = true)
            val matchesCat = when (partD.appCat) {
                null, "Tất cả" -> true
                "Đang chặn" -> !app.isCellularAllowed || !app.isWifiAllowed
                "Được lọc" -> app.isFilterRouted
                "Bỏ qua lọc" -> !app.isFilterRouted
                else -> app.category.contains(partD.appCat, ignoreCase = true)
            }
            matchesSearch && matchesCat
        }

        AdGuardUiState(
            currentTab = partA.tab,
            settings = partA.settings,
            stats = partA.stats,
            logs = partA.logs,
            filteredLogs = filteredLogs,
            filterLists = partB.filters,
            appFirewallRules = filteredApps,
            dnsProviders = partB.dns,
            isSimulationModeEnabled = partB.simMode,
            inspectedLog = partC.inspected,
            searchQuery = partA.query,
            statusFilter = partB.status,
            showCustomRuleDialog = partC.showCustom,
            showOnlineSubDialog = partC.showOnline,
            showCustomRuleEditor = partC.showEditor,
            inspectedApp = partC.inspectedApp,
            appSearchQuery = partD.appSearch,
            appCategoryFilter = partD.appCat,
            selectedAppFilter = partD.selectedApp,
            aiMode = partD.aiMode,
            aiLabState = partD.aiLabState,
            isUpdatingFilters = partD.updating
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = AdGuardUiState()
    )

    private data class FiveState(
        val tab: AdGuardTab,
        val settings: com.example.model.ProtectionSettings,
        val stats: com.example.model.ProtectionStats,
        val logs: List<NetworkRequestLog>,
        val query: String
    )

    private data class FiveStateB(
        val status: FilterStatus?,
        val filters: List<com.example.model.FilterList>,
        val apps: List<com.example.model.AppFirewallRule>,
        val dns: List<com.example.model.DnsProvider>,
        val simMode: Boolean
    )

    private data class FiveStateC(
        val inspected: NetworkRequestLog?,
        val showCustom: Boolean,
        val showOnline: Boolean,
        val showEditor: Boolean,
        val inspectedApp: AppFirewallRule?
    )

    private data class FiveStateD(
        val appSearch: String,
        val appCat: String?,
        val selectedApp: String?,
        val aiMode: AiAnalysisMode,
        val aiLabState: AiLabUiState,
        val updating: Boolean
    )

    /**
     * MVI Intent Dispatcher.
     */
    fun onIntent(intent: AdGuardIntent) {
        when (intent) {
            is AdGuardIntent.SelectTab -> _currentTab.value = intent.tab
            is AdGuardIntent.ToggleProtection -> {
                val next = !uiState.value.settings.isProtectionActive
                repository.toggleProtection(next)
                emitEffect(AdGuardEffect.ShowSnackbar(if (next) "Bảo vệ đang BẬT" else "Bảo vệ đã TẮT"))
            }
            is AdGuardIntent.ToggleAdBlocking -> repository.toggleAdBlocking(!uiState.value.settings.isAdBlockingEnabled)
            is AdGuardIntent.ToggleTracking -> repository.toggleTrackingProtection(!uiState.value.settings.isTrackingProtectionEnabled)
            is AdGuardIntent.ToggleDns -> repository.toggleDnsProtection(!uiState.value.settings.isDnsProtectionEnabled)
            is AdGuardIntent.ToggleHttps -> repository.toggleHttpsFiltering(!uiState.value.settings.isHttpsFilteringEnabled)
            is AdGuardIntent.ToggleFirewall -> repository.toggleFirewall(!uiState.value.settings.isFirewallEnabled)
            is AdGuardIntent.ToggleEcoMode -> repository.toggleEcoBatteryMode(!uiState.value.settings.isEcoBatteryModeEnabled)
            is AdGuardIntent.ToggleStealth -> repository.toggleStealthMode(!uiState.value.settings.isStealthModeEnabled)
            is AdGuardIntent.ToggleSimulationMode -> {
                repository.toggleSimulationMode(intent.enabled)
                emitEffect(
                    AdGuardEffect.ShowSnackbar(
                        if (intent.enabled) "Đã bật chế độ test UI (phát dữ liệu giả lập)" else "Đã tắt test UI: 100% gói tin THẬT từ Android VPN"
                    )
                )
            }
            is AdGuardIntent.SearchQueryChanged -> _searchQuery.value = intent.query
            is AdGuardIntent.FilterStatusChanged -> _statusFilter.value = intent.status
            is AdGuardIntent.InspectLog -> _inspectedLog.value = intent.log
            is AdGuardIntent.AddCustomRule -> {
                repository.addCustomRule(intent.rule)
                _showCustomRuleDialog.value = false
                emitEffect(AdGuardEffect.ShowSnackbar("Đã thêm quy tắc: ${intent.rule}"))
            }
            is AdGuardIntent.RemoveCustomRule -> {
                repository.removeCustomRule(intent.rule)
                emitEffect(AdGuardEffect.ShowSnackbar("Đã xóa quy tắc: ${intent.rule}"))
            }
            is AdGuardIntent.UpdateAllCustomRules -> {
                repository.updateAllCustomRules(intent.rules)
                _showCustomRuleEditor.value = false
                emitEffect(AdGuardEffect.ShowSnackbar("Đã lưu ${intent.rules.size} quy tắc tùy chỉnh vào bộ nhớ"))
            }
            is AdGuardIntent.AddToWhitelist -> {
                repository.addDomainToWhitelist(intent.domain)
                _inspectedLog.value = null
                emitEffect(AdGuardEffect.ShowSnackbar("Đã thêm vào danh sách trắng: @@||${intent.domain}^"))
            }
            is AdGuardIntent.AddToBlacklist -> {
                repository.addDomainToBlacklist(intent.domain)
                _inspectedLog.value = null
                emitEffect(AdGuardEffect.ShowSnackbar("Đã chặn tên miền: ||${intent.domain}^"))
            }
            is AdGuardIntent.SelectDnsProvider -> repository.selectDnsProvider(intent.id)
            is AdGuardIntent.UpdateAppFirewall -> {
                repository.updateAppFirewall(
                    intent.packageName,
                    intent.cellular,
                    intent.wifi,
                    intent.filtered,
                    intent.blockWhenScreenOff
                )
                // If currently inspecting this app, update inspectedApp state
                val updatedApp = repository.appFirewallRules.value.find { it.packageName == intent.packageName }
                if (updatedApp != null && _inspectedApp.value?.packageName == intent.packageName) {
                    _inspectedApp.value = updatedApp
                }
            }
            is AdGuardIntent.InspectAppDetails -> _inspectedApp.value = intent.app
            is AdGuardIntent.ViewAppLogs -> {
                _selectedAppFilter.value = intent.app.packageName
                _currentTab.value = AdGuardTab.ACTIVITY
                _inspectedApp.value = null
                emitEffect(AdGuardEffect.ShowSnackbar("Đang hiển thị nhật ký cho ${intent.app.appName}"))
            }
            is AdGuardIntent.FilterLogsByApp -> {
                _selectedAppFilter.value = intent.appPackageOrName
            }
            is AdGuardIntent.AppSearchQueryChanged -> _appSearchQuery.value = intent.query
            is AdGuardIntent.AppCategoryFilterChanged -> _appCategoryFilter.value = intent.filter
            is AdGuardIntent.ClearLogs -> repository.clearLogs()
            is AdGuardIntent.ShowCustomRuleDialog -> _showCustomRuleDialog.value = intent.show
            is AdGuardIntent.ShowOnlineSubDialog -> _showOnlineSubDialog.value = intent.show
            is AdGuardIntent.ShowCustomRuleEditor -> _showCustomRuleEditor.value = intent.show
            is AdGuardIntent.AddOnlineSubscription -> {
                repository.addOnlineSubscription(intent.name, intent.url, intent.category)
                _showOnlineSubDialog.value = false
                emitEffect(AdGuardEffect.ShowSnackbar("Đã thêm bộ lọc online: ${intent.name}"))
            }
            is AdGuardIntent.DeleteFilterList -> {
                repository.deleteFilterList(intent.id)
                emitEffect(AdGuardEffect.ShowSnackbar("Đã xóa bộ lọc"))
            }
            is AdGuardIntent.RefreshSubscription -> {
                repository.refreshSubscription(intent.id)
                emitEffect(AdGuardEffect.ShowSnackbar("Đã cập nhật quy tắc mới nhất từ nguồn online"))
            }
            is AdGuardIntent.SetAiMode -> _aiMode.value = intent.mode
            is AdGuardIntent.RunThreatScan -> handleThreatScan(intent.domain)
            is AdGuardIntent.ResetAiLab -> _aiLabState.value = AiLabUiState.Idle
            is AdGuardIntent.UpdateFilterLists -> handleFilterUpdate()
            is AdGuardIntent.UpdateStealth -> repository.updateStealthSetting(
                intent.stripUtm,
                intent.blockWebRtc,
                intent.disguiseUa,
                intent.blockCookies
            )
        }
    }

    private fun emitEffect(effect: AdGuardEffect) {
        viewModelScope.launch {
            _effect.emit(effect)
        }
    }

    private fun handleThreatScan(domain: String) {
        if (domain.isBlank()) return
        viewModelScope.launch {
            if (_aiMode.value == AiAnalysisMode.SEARCH_GROUNDING) {
                _aiLabState.value = AiLabUiState.Loading("Tìm kiếm cơ sở dữ liệu mối đe dọa Google với gemini-3.5-flash...")
                val res = aiLabService.analyzeDomainWithSearch(domain)
                _aiLabState.value = AiLabUiState.Success(res)
            } else {
                _aiLabState.value = AiLabUiState.Loading("Kích hoạt gemini-3.1-pro-preview High Thinking để phân tích vật lý tiêu thụ pin & độ phức tạp regex...")
                val context = "Lưu lượng mạng thiết bị Android. Đánh giá tính an toàn và chi phí CPU của regex."
                val res = aiLabService.deepForensicAnalysis(domain, context)
                _aiLabState.value = AiLabUiState.Success(res)
            }
        }
    }

    private fun handleFilterUpdate() {
        viewModelScope.launch {
            _isUpdatingFilters.value = true
            kotlinx.coroutines.delay(1200)
            _isUpdatingFilters.value = false
            _effect.emit(AdGuardEffect.ShowSnackbar("Tất cả danh sách bộ lọc đã được cập nhật bản mới nhất"))
        }
    }
}
