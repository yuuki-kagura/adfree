package git.shin.adfree.ui

import android.util.Log
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
import git.shin.adfree.model.UserScriptInfo
import git.shin.adfree.model.UserScriptStoreState
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
    private val _showCustomRuleEditor = MutableStateFlow(false)
    private val _filterSearchQuery = MutableStateFlow("")
    private val _inspectedFilter = MutableStateFlow<String?>(null)
    private val _showAddFilterDialog = MutableStateFlow(false)
    private val _inspectedScript = MutableStateFlow<String?>(null)
    private val _showAddScriptDialog = MutableStateFlow(false)
    private val _showScriptStore = MutableStateFlow(false)
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
            combine(
                _currentTab,
                repository.settings,
                repository.stats,
            ) { tab, settings, stats -> Triple(tab, settings, stats) },
            repository.logs,
            repository.logTotal,
            _searchQuery,
        ) { head, logs, total, query ->
            val (tab, settings, stats) = head
            UiPartA(tab, settings, stats, logs, total, query)
        },
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
            _showCustomRuleEditor,
            _inspectedApp,
            _filterSearchQuery,
        ) { inspected, dialog, editor, app, filterSearch ->
            UiPartC(inspected, dialog, editor, app, filterSearch)
        },
        combine(
            _inspectedFilter,
            _showAddFilterDialog,
            _inspectedScript,
            _showAddScriptDialog,
            _showScriptStore,
        ) { filter, addFilter, script, addScript, store ->
            UiPartC2(filter, addFilter, script, addScript, store)
        },
        combine(
            combine(
                _appSearchQuery,
                _appCategoryFilter,
                _selectedAppFilter,
                _aiLabState,
            ) { q, cat, app, lab -> UiPartD(q, cat, app, lab) },
            combine(
                _showVpnPermissionPrompt,
                repository.loadingMessage,
                repository.userscripts,
                repository.scriptsMasterEnabled,
                repository.scriptStore,
            ) { prompt, loading, scripts, master, store ->
                UiExtras(prompt, loading, scripts, master, store)
            },
        ) { d, extras -> d.plusExtras(extras) },
    ) { a, b, c, c2, d ->
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
            logTotal = a.logTotal,
            filterLists = b.filters,
            appFirewallRules = apps,
            dnsProviders = b.dns,
            isVpnActive = b.isVpnActive,
            inspectedLog = c.inspected,
            searchQuery = a.query,
            statusFilter = b.status,
            showCustomRuleDialog = c.showCustomRule,
            showCustomRuleEditor = c.showEditor,
            inspectedApp = c.inspectedApp,
            filterSearchQuery = c.filterSearch,
            inspectedFilterId = c2.inspectedFilter,
            showAddFilterDialog = c2.showAddFilter,
            inspectedScriptId = c2.inspectedScript,
            showAddScriptDialog = c2.showAddScript,
            showScriptStore = c2.showScriptStore,
            userscripts = d.userscripts,
            scriptsMasterEnabled = d.scriptsMasterEnabled,
            scriptStore = d.scriptStore,
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
        // Protection that was on when the app last ran comes back by itself;
        // a first run has nothing saved and waits for the user. The consent
        // dialog can only be raised by the Activity, hence the flag.
        if (repository.protectionWasOn()) {
            repository.toggleProtection(true)
            if (vpnController.prepareIfNeeded() != null) {
                _showVpnPermissionPrompt.value = true
            } else {
                vpnController.startVpnService()
            }
        }
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

            is AdGuardIntent.ToggleEcoMode -> {
                repository.toggleEcoBatteryMode(!uiState.value.settings.isEcoBatteryModeEnabled)
                syncConfig()
            }

            is AdGuardIntent.ToggleStealth ->
                repository.toggleStealthMode(!uiState.value.settings.isStealthModeEnabled)

            is AdGuardIntent.ToggleBlockQuic -> {
                repository.toggleBlockQuic(intent.enabled)
                syncConfig()
            }
            is AdGuardIntent.ToggleBlockDoh -> {
                repository.toggleBlockDoh(intent.enabled)
                syncConfig()
            }
            is AdGuardIntent.SetFilterAutoUpdate ->
                repository.setFilterAutoUpdate(intent.hours)
            is AdGuardIntent.ToggleLogAllowed -> {
                repository.toggleLogAllowed(intent.enabled)
                syncConfig()
            }
            is AdGuardIntent.SetBlockMode -> {
                repository.setBlockMode(intent.mode)
                syncConfig()
            }
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
                // Keep the sheet open: add/delete/import are incremental edits,
                // and the import notice would vanish with the sheet.
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
                val message = repository.addCustomDnsProvider(intent.name, intent.address)
                emit(AdGuardEffect.ShowSnackbar(message))
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
            is AdGuardIntent.LoadMoreLogs -> repository.loadMoreLogs()
            is AdGuardIntent.SetLogTailing -> repository.setLogTailing(intent.tailing)
            is AdGuardIntent.ShowCustomRuleDialog -> _showCustomRuleDialog.value = intent.show
            is AdGuardIntent.ShowCustomRuleEditor -> _showCustomRuleEditor.value = intent.show
            is AdGuardIntent.FilterSearchQueryChanged -> _filterSearchQuery.value = intent.query
            is AdGuardIntent.ShowAddFilterDialog -> _showAddFilterDialog.value = intent.show
            is AdGuardIntent.AddCustomFilter -> {
                repository.addCustomFilter(intent.name, intent.url)
                _showAddFilterDialog.value = false
                emit(AdGuardEffect.ShowSnackbar("Đang tải bộ lọc mới…"))
            }

            is AdGuardIntent.ImportLocalFilter -> {
                repository.importLocalFilter(intent.uri)
                _showAddFilterDialog.value = false
            }

            is AdGuardIntent.InspectFilter -> _inspectedFilter.value = intent.id
            is AdGuardIntent.RestoreDefaultFilters -> {
                repository.restoreDefaultFilters()
                emit(AdGuardEffect.ShowSnackbar("Đã khôi phục bộ lọc mặc định"))
            }

            is AdGuardIntent.ShowAddScriptDialog -> _showAddScriptDialog.value = intent.show
            is AdGuardIntent.AddScript -> {
                repository.addScript(intent.name, intent.url)
                _showAddScriptDialog.value = false
            }
            is AdGuardIntent.ImportLocalScript -> {
                repository.importLocalScript(intent.uri)
                _showAddScriptDialog.value = false
            }
            is AdGuardIntent.CreateScript -> {
                repository.createScript(intent.name, intent.text)
                _showAddScriptDialog.value = false
            }
            is AdGuardIntent.UpdateScriptText -> {
                repository.updateScriptText(intent.id, intent.name, intent.text)
            }

            is AdGuardIntent.ShowScriptStore -> {
                _showScriptStore.value = intent.show
                if (intent.show) repository.openScriptStore()
            }
            is AdGuardIntent.SearchScriptStore -> repository.searchScriptStore(intent.query)
            is AdGuardIntent.SortScriptStore -> repository.setScriptStoreSort(intent.sort)
            is AdGuardIntent.LoadMoreScriptStore -> repository.loadMoreScriptStore()
            is AdGuardIntent.InstallStoreScript -> {
                repository.addScript(intent.name, intent.url, intent.description)
                emit(AdGuardEffect.ShowSnackbar("Đang cài ${intent.name}…"))
            }

            is AdGuardIntent.ToggleScript -> repository.toggleScript(intent.id, intent.enabled)
            is AdGuardIntent.ToggleScriptsMaster -> repository.toggleScriptsMaster(intent.enabled)
            is AdGuardIntent.RefreshScript -> repository.refreshScript(intent.id)
            is AdGuardIntent.DeleteScript -> repository.deleteScript(intent.id)
            is AdGuardIntent.InspectScript -> _inspectedScript.value = intent.id

            is AdGuardIntent.DeleteFilterList -> repository.deleteFilterList(intent.id)
            is AdGuardIntent.UpdateCustomFilter ->
                repository.updateCustomFilter(intent.id, intent.name, intent.url)
            is AdGuardIntent.RefreshSubscription -> repository.refreshSubscription(intent.id)
            is AdGuardIntent.RefreshAllSubscriptions -> repository.refreshAllSubscriptions()
            is AdGuardIntent.ToggleFilterList -> repository.toggleFilterList(intent.id, intent.enabled)
            is AdGuardIntent.SetFilterTrusted -> repository.setFilterTrusted(intent.id, intent.trusted)
            is AdGuardIntent.RunThreatScan -> handleThreatScan(intent.domain)
            is AdGuardIntent.ResetAiLab -> _aiLabState.value = AiLabUiState.Idle
            is AdGuardIntent.UpdateStealth -> repository.updateStealthSetting(
                intent.stripUtm, intent.blockWebRtc, intent.disguiseUa, intent.blockCookies,
            )

            is AdGuardIntent.DismissLoading -> repository.dismissLoading()
            is AdGuardIntent.VpnPermissionResolved -> {
                // The dialog is gone either way; leaving the flag set would keep
                // the next tap from raising it again.
                _showVpnPermissionPrompt.value = false
                vpnController.onPermissionResult(intent.granted)
                // A refusal means the tunnel cannot come up: record that as the
                // switch being off, so a later launch does not ask again by
                // itself (the persisted intent is what auto-start reads).
                if (!intent.granted) repository.toggleProtection(false)
            }
            is AdGuardIntent.DismissVpnPermission -> _showVpnPermissionPrompt.value = false
        }
        syncConfig()
    }

    private fun toggleProtection() {
        // The switch follows the VPN itself, not a remembered flag: the flag
        // defaulted to on while no tunnel existed, so the first tap after a
        // restart "switched off" protection that had never come up.
        val next = !vpnController.isVpnActive.value
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

    /** True when the CA is present in the device trust store. */
    fun isCaTrusted(): Boolean = coreEngine.isCaTrusted()

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

    /**
     * Full ECH: hand clients the origin's ECHConfigs so they can wrap their
     * hello end to end. The hosts that use it are then spliced, not filtered —
     * the trade this switch exists for. The engine reads the flag per DNS
     * answer, so this takes effect with the next lookup.
     */
    fun setFullEch(enabled: Boolean) {
        repository.toggleFullEch(enabled)
        syncConfig()
    }

    /** HTTPS allowlist: hosts the proxy must not decrypt. */
    fun addHttpsSkipHost(raw: String) {
        repository.addHttpsSkipHost(raw)
        syncConfig()
    }

    fun removeHttpsSkipHost(host: String) {
        repository.removeHttpsSkipHost(host)
        syncConfig()
    }

    /** HTTPS blocklist + inverse mode: decrypt only these hosts. */
    fun addHttpsOnlyHost(raw: String) {
        repository.addHttpsOnlyHost(raw)
        syncConfig()
    }

    fun removeHttpsOnlyHost(host: String) {
        repository.removeHttpsOnlyHost(host)
        syncConfig()
    }

    fun setHttpsOnlyMode(enabled: Boolean) {
        repository.setHttpsOnlyMode(enabled)
        syncConfig()
    }

    /** Creates (or recreates) the local CA and returns the new status. */
    fun createCa(onDone: (git.shin.adfree.core.MitmStatus?) -> Unit) {
        // Drop the persisted pair first, otherwise ensureCa() only restores.
        coreEngine.resetCa()
        coreEngine.ensureCa()
        onDone(coreEngine.mitmStatus())
    }

    /**
     * Exports the CA certificate to Downloads and opens the Settings screen
     * that leads to the installer. Returns the exported file name so the
     * caller can tell the user what to pick, or null when the export failed.
     */
    fun installCertificate(): String? {
        val name = coreEngine.exportCaCertificate()
        runCatching { containerProvider()?.startActivity(coreEngine.installCertificateIntent()) }
            .onFailure { Log.w("AdFree", "certificate install intent failed", it) }
        return name
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
        val logTotal: Long,
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
        val showEditor: Boolean,
        val inspectedApp: AppFirewallRule?,
        val filterSearch: String,
    )

    private data class UiPartC2(
        val inspectedFilter: String?,
        val showAddFilter: Boolean,
        val inspectedScript: String?,
        val showAddScript: Boolean,
        val showScriptStore: Boolean,
    )

    private data class UiPartD(
        val appSearch: String,
        val appCategoryFilter: String?,
        val selectedApp: String?,
        val aiLabState: AiLabUiState,
    ) {
        var showVpnPermission: Boolean = false
        var loadingMessage: String? = null
        var userscripts: List<UserScriptInfo> = emptyList()
        var scriptsMasterEnabled: Boolean = false
        var scriptStore: UserScriptStoreState = UserScriptStoreState()

        fun plusExtras(extras: UiExtras): UiPartD = apply {
            showVpnPermission = extras.showVpnPermission
            loadingMessage = extras.loadingMessage
            userscripts = extras.userscripts
            scriptsMasterEnabled = extras.scriptsMasterEnabled
            scriptStore = extras.scriptStore
        }
    }

    private data class UiExtras(
        val showVpnPermission: Boolean,
        val loadingMessage: String?,
        val userscripts: List<UserScriptInfo>,
        val scriptsMasterEnabled: Boolean,
        val scriptStore: UserScriptStoreState,
    )
}
