package git.shin.adfree.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import git.shin.adfree.core.CoreEngine
import git.shin.adfree.data.AdGuardRepository
import git.shin.adfree.model.AppFirewallRule
import git.shin.adfree.model.DnsBlockMode
import git.shin.adfree.model.FilterStatus
import git.shin.adfree.model.NetworkRequestLog
import git.shin.adfree.model.ProtectionSettings
import git.shin.adfree.model.ProtectionStats
import git.shin.adfree.model.ThreatAnalysisResult
import git.shin.adfree.security.ThreatAnalyzer
import git.shin.adfree.vpn.VpnController
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

enum class AdGuardTab { HOME, ACTIVITY, FILTERS, APPS, AI_LAB, SETTINGS }

sealed interface AiLabUiState {
    data object Idle : AiLabUiState
    data class Loading(val message: String) : AiLabUiState
    data class Success(val result: ThreatAnalysisResult) : AiLabUiState
    data class Error(val message: String) : AiLabUiState
}

/**
 * MVI ViewModel.
 *
 * Single unidirectional state. Every number comes from [AdGuardRepository]
 * (atomics read from the Rust core) — no fake data.
 */
class AdGuardViewModel(
    private val repository: AdGuardRepository,
    private val vpnController: VpnController,
    private val threatAnalyzer: ThreatAnalyzer,
    private val coreEngine: CoreEngine,
    /** Callback that pushes settings down to the Rust core; supplied by DI. */
    private val onConfigChanged: () -> Unit = {},
) : ViewModel() {

    // ---------------------------------------------------------------- local UI

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
    private val _aiLabState = MutableStateFlow<AiLabUiState>(AiLabUiState.Idle)
    private val _showVpnPermissionPrompt = MutableStateFlow(false)

    private val _effect = MutableSharedFlow<AdGuardEffect>(
        replay = 0,
        extraBufferCapacity = 8,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    val effect: SharedFlow<AdGuardEffect> = _effect.asSharedFlow()

    val uiState: StateFlow<AdGuardUiState> = combine(
        combine(
            _currentTab,
            repository.settings,
            repository.stats,
            repository.logs,
            _searchQuery,
        ) { tab, settings, stats, logs, query -> UiPartA(tab, settings, stats, logs, query) },
        combine(
            _statusFilter,
            repository.filterLists,
            repository.appFirewallRules,
            repository.dnsProviders,
            vpnController.isVpnActive,
        ) { status, filters, apps, dns, active -> UiPartB(status, filters, apps, dns, active) },
        combine(
            _inspectedLog,
            _showCustomRuleDialog,
            _showOnlineSubDialog,
            _showCustomRuleEditor,
            _inspectedApp,
        ) { inspected, dialog, online, editor, app ->
            UiPartC(inspected, dialog, online, editor, app)
        },
        combine(
            combine(
                _appSearchQuery,
                _appCategoryFilter,
                _selectedAppFilter,
                _aiLabState,
            ) { q, cat, app, lab -> UiPartD(q, cat, app, lab) },
            combine(_showVpnPermissionPrompt, repository.loadingMessage) { prompt, loading ->
                prompt to loading
            },
        ) { d, (prompt, loading) -> d.plusExtras(prompt, loading) },
    ) { a, b, c, d ->
        val logs = a.logs.filter { log ->
            val query = a.query
            val matchesQuery = query.isBlank() ||
                log.domain.contains(query, true) ||
                log.matchedRule?.contains(query, true) == true ||
                log.filterListName?.contains(query, true) == true
            val matchesStatus = b.status == null || log.status == b.status
            val matchesApp = d.selectedApp == null || log.matchedRule?.contains(d.selectedApp, true) == true
            matchesQuery && matchesStatus && matchesApp
        }

        val apps = b.apps.filter { app ->
            val matchesSearch = d.appSearch.isBlank() ||
                app.appName.contains(d.appSearch, true) ||
                app.packageName.contains(d.appSearch, true)
            val matchesCat = when (d.appCategoryFilter) {
                null, "Tất cả" -> true
                "Đang chặn" -> !app.isCellularAllowed || !app.isWifiAllowed
                "Được lọc" -> app.isFilterRouted
                "Bỏ qua lọc" -> !app.isFilterRouted
                else -> app.category == d.appCategoryFilter
            }
            matchesSearch && matchesCat
        }

        AdGuardUiState(
            currentTab = a.tab,
            settings = a.settings,
            stats = a.stats,
            logs = a.logs,
            filteredLogs = logs,
            filterLists = b.filters,
            appFirewallRules = apps,
            dnsProviders = b.dns,
            isVpnActive = b.isVpnActive,
            inspectedLog = c.inspected,
            searchQuery = a.query,
            statusFilter = b.status,
            showCustomRuleDialog = c.showCustomRule,
            showOnlineSubDialog = c.showOnline,
            showCustomRuleEditor = c.showEditor,
            inspectedApp = c.inspectedApp,
            appSearchQuery = d.appSearch,
            appCategoryFilter = d.appCategoryFilter,
            selectedAppFilter = d.selectedApp,
            aiLabState = d.aiLabState,
            showVpnPermissionPrompt = d.showVpnPermission,
            loadingMessage = d.loadingMessage,
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = AdGuardUiState(),
    )

    init {
        repository.loadInstalledApps()
    }

    // ---------------------------------------------------------------- intents

    fun onIntent(intent: AdGuardIntent) {
        when (intent) {
            is AdGuardIntent.SelectTab -> _currentTab.value = intent.tab
            is AdGuardIntent.ToggleProtection -> toggleProtection()
            is AdGuardIntent.ToggleAdBlocking ->
                repository.toggleAdBlocking(!uiState.value.settings.isAdBlockingEnabled)

            is AdGuardIntent.ToggleTracking ->
                repository.toggleTrackingProtection(!uiState.value.settings.isTrackingProtectionEnabled)

            is AdGuardIntent.ToggleDns ->
                repository.toggleDnsProtection(!uiState.value.settings.isDnsProtectionEnabled)

            is AdGuardIntent.ToggleHttps ->
                repository.toggleHttpsFiltering(!uiState.value.settings.isHttpsFilteringEnabled)

            is AdGuardIntent.ToggleFirewall ->
                repository.toggleFirewall(!uiState.value.settings.isFirewallEnabled)

            is AdGuardIntent.ToggleEcoMode ->
                repository.toggleEcoBatteryMode(!uiState.value.settings.isEcoBatteryModeEnabled)

            is AdGuardIntent.ToggleStealth ->
                repository.toggleStealthMode(!uiState.value.settings.isStealthModeEnabled)

            is AdGuardIntent.ToggleBlockQuic -> repository.toggleBlockQuic(intent.enabled)
            is AdGuardIntent.ToggleBlockDoh -> repository.toggleBlockDoh(intent.enabled)
            is AdGuardIntent.ToggleLogAllowed -> repository.toggleLogAllowed(intent.enabled)
            is AdGuardIntent.SetBlockMode -> repository.setBlockMode(intent.mode)
            is AdGuardIntent.SearchQueryChanged -> _searchQuery.value = intent.query
            is AdGuardIntent.FilterStatusChanged -> _statusFilter.value = intent.status
            is AdGuardIntent.InspectLog -> _inspectedLog.value = intent.log
            is AdGuardIntent.AddCustomRule -> {
                repository.addCustomRule(intent.rule)
                _showCustomRuleDialog.value = false
                emit(AdGuardEffect.ShowSnackbar("Đã thêm quy tắc ${intent.rule}"))
            }

            is AdGuardIntent.RemoveCustomRule -> repository.removeCustomRule(intent.rule)
            is AdGuardIntent.UpdateAllCustomRules -> {
                repository.updateAllCustomRules(intent.rules)
                _showCustomRuleEditor.value = false
                emit(AdGuardEffect.ShowSnackbar("Đã lưu ${intent.rules.size} quy tắc"))
            }

            is AdGuardIntent.AddToWhitelist -> {
                repository.addDomainToWhitelist(intent.domain)
                _inspectedLog.value = null
                emit(AdGuardEffect.ShowSnackbar("Đã đưa ${intent.domain} vào danh sách trắng"))
            }

            is AdGuardIntent.AddToBlacklist -> {
                repository.addDomainToBlacklist(intent.domain)
                _inspectedLog.value = null
                emit(AdGuardEffect.ShowSnackbar("Đã chặn ${intent.domain}"))
            }

            is AdGuardIntent.SelectDnsProvider -> {
                repository.selectDnsProvider(intent.id)
                emit(AdGuardEffect.ShowSnackbar("Đã đổi upstream DNS"))
            }

            is AdGuardIntent.AddCustomDnsProvider -> {
                repository.addCustomDnsProvider(intent.name, intent.address)
                emit(AdGuardEffect.ShowSnackbar("Đã thêm DNS tuỳ chỉnh"))
            }

            is AdGuardIntent.UpdateAppFirewall -> {
                repository.updateAppFirewall(
                    intent.packageName,
                    intent.cellular,
                    intent.wifi,
                    intent.filtered,
                    intent.blockWhenScreenOff,
                )
                repository.pushAppRouting()
            }

            is AdGuardIntent.InspectAppDetails -> _inspectedApp.value = intent.app
            is AdGuardIntent.ViewAppLogs -> {
                _selectedAppFilter.value = intent.app.packageName
                _currentTab.value = AdGuardTab.ACTIVITY
                _inspectedApp.value = null
            }

            is AdGuardIntent.FilterLogsByApp -> _selectedAppFilter.value = intent.appPackageOrName
            is AdGuardIntent.AppSearchQueryChanged -> _appSearchQuery.value = intent.query
            is AdGuardIntent.AppCategoryFilterChanged -> _appCategoryFilter.value = intent.filter
            is AdGuardIntent.ClearLogs -> repository.clearLogs()
            is AdGuardIntent.ResetStats -> repository.resetStats()
            is AdGuardIntent.ShowCustomRuleDialog -> _showCustomRuleDialog.value = intent.show
            is AdGuardIntent.ShowOnlineSubDialog -> _showOnlineSubDialog.value = intent.show
            is AdGuardIntent.ShowCustomRuleEditor -> _showCustomRuleEditor.value = intent.show
            is AdGuardIntent.AddOnlineSubscription -> {
                repository.addOnlineSubscription(intent.name, intent.url, intent.category)
                _showOnlineSubDialog.value = false
            }

            is AdGuardIntent.DeleteFilterList -> repository.deleteFilterList(intent.id)
            is AdGuardIntent.RefreshSubscription -> repository.refreshSubscription(intent.id)
            is AdGuardIntent.RefreshAllSubscriptions -> repository.refreshAllSubscriptions()
            is AdGuardIntent.ToggleFilterList -> repository.toggleFilterList(intent.id, intent.enabled)
            is AdGuardIntent.RunThreatScan -> handleThreatScan(intent.domain)
            is AdGuardIntent.ResetAiLab -> _aiLabState.value = AiLabUiState.Idle
            is AdGuardIntent.UpdateStealth -> repository.updateStealthSetting(
                intent.stripUtm, intent.blockWebRtc, intent.disguiseUa, intent.blockCookies,
            )

            is AdGuardIntent.DismissLoading -> repository.dismissLoading()
            is AdGuardIntent.VpnPermissionResolved -> vpnController.onPermissionResult(intent.granted)
            is AdGuardIntent.DismissVpnPermission -> _showVpnPermissionPrompt.value = false
        }
        syncConfig()
    }

    private fun toggleProtection() {
        val next = !uiState.value.settings.isProtectionActive
        if (next) {
            val needsPermission = vpnController.prepareIfNeeded() != null
            if (needsPermission) {
                _showVpnPermissionPrompt.value = true
                repository.toggleProtection(true)
            } else {
                repository.toggleProtection(true)
                vpnController.startVpnService()
            }
        } else {
            repository.toggleProtection(false)
            vpnController.stopVpnService()
        }
        emit(AdGuardEffect.ShowSnackbar(if (next) "Đang bật bảo vệ" else "Đã tắt bảo vệ"))
    }

    private fun handleThreatScan(domain: String) {
        if (domain.isBlank()) return
        viewModelScope.launch {
            _aiLabState.value = AiLabUiState.Loading("Đang phân tích $domain trên thiết bị…")
            val result = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) {
                threatAnalyzer.analyze(domain)
            }
            _aiLabState.value = AiLabUiState.Success(result)
        }
    }

    /** After each intent, push the configuration down to the core. */
    private fun syncConfig() {
        onConfigChanged()
    }


    // ---------------------------------------------------------------- MITM

    /**
     * Reads the CA/script state from the core.
     *
     * The CA is restored from disk first so the state is correct after a restart
     * without the user having to re-create it.
     */
    fun readMitmStatus(): git.shin.adfree.core.MitmStatus? {
        coreEngine.ensureCa()
        return coreEngine.mitmStatus()
    }

    /**
     * Turns HTTPS filtering on or off.
     *
     * The engine is reconfigured right away: whether TLS termination happens is
     * decided by the core config, and leaving the switch and the engine out of
     * sync would filter (or fail to filter) behind the user's back.
     */
    fun setHttpsFiltering(enabled: Boolean, onDone: (git.shin.adfree.core.MitmStatus?) -> Unit) {
        repository.toggleHttpsFiltering(enabled)
        syncConfig()
        onDone(coreEngine.mitmStatus())
    }

    /** Creates (or recreates) the local CA and returns the new status. */
    fun createCa(onDone: (git.shin.adfree.core.MitmStatus?) -> Unit) {
        // Drop the persisted pair first, otherwise ensureCa() only restores.
        coreEngine.resetCa()
        coreEngine.ensureCa()
        onDone(coreEngine.mitmStatus())
    }

    /** Sends the user to the system screen that installs a CA certificate. */
    fun installCertificate() {
        runCatching { containerProvider()?.startActivity(coreEngine.installCertificateIntent()) }
    }

    /** Replaces the user script list. */
    fun setScripts(scripts: List<git.shin.adfree.core.ScriptBinding>, enabled: Boolean) {
        coreEngine.setScripts(scripts, enabled)
    }

    /** Context used to launch system screens; supplied by the Activity. */
    private var contextProvider: (() -> android.content.Context)? = null
    private fun containerProvider(): android.content.Context? = contextProvider?.invoke()

    fun attachContext(provider: () -> android.content.Context) {
        contextProvider = provider
    }

    private fun emit(effect: AdGuardEffect) {
        viewModelScope.launch { _effect.emit(effect) }
    }

    private data class UiPartA(
        val tab: AdGuardTab,
        val settings: ProtectionSettings,
        val stats: ProtectionStats,
        val logs: List<NetworkRequestLog>,
        val query: String,
    )

    private data class UiPartB(
        val status: FilterStatus?,
        val filters: List<git.shin.adfree.model.FilterList>,
        val apps: List<AppFirewallRule>,
        val dns: List<git.shin.adfree.model.DnsProvider>,
        val isVpnActive: Boolean,
    )

    private data class UiPartC(
        val inspected: NetworkRequestLog?,
        val showCustomRule: Boolean,
        val showOnline: Boolean,
        val showEditor: Boolean,
        val inspectedApp: AppFirewallRule?,
    )

    private data class UiPartD(
        val appSearch: String,
        val appCategoryFilter: String?,
        val selectedApp: String?,
        val aiLabState: AiLabUiState,
    ) {
        var showVpnPermission: Boolean = false
        var loadingMessage: String? = null

        fun plusExtras(prompt: Boolean, loading: String?): UiPartD = apply {
            showVpnPermission = prompt
            loadingMessage = loading
        }
    }
}
