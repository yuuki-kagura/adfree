package git.shin.adfree.ui

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import git.shin.adfree.R
import git.shin.adfree.core.ConfigWarning
import git.shin.adfree.core.CoreEngine
import git.shin.adfree.data.AdGuardRepository
import git.shin.adfree.model.AppCategory
import git.shin.adfree.model.AppCategoryFilter
import git.shin.adfree.model.AppFirewallRule
import git.shin.adfree.model.AppUsageRange
import git.shin.adfree.model.AppUsageTransport
import git.shin.adfree.model.DnsBackup
import git.shin.adfree.model.DnsBackupMode
import git.shin.adfree.model.DnsBlockMode
import git.shin.adfree.model.FilterStatus
import git.shin.adfree.model.FirewallAccess
import git.shin.adfree.model.FirewallAppChoice
import git.shin.adfree.model.LogWindowTotals
import git.shin.adfree.model.NetworkRequestLog
import git.shin.adfree.model.ProtectionSettings
import git.shin.adfree.model.ProtectionStats
import git.shin.adfree.model.ProxyAccess
import git.shin.adfree.model.ProxySettings
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
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

enum class AdGuardTab { HOME, PROTECTION, ACTIVITY, APPS, STATISTICS, AI_LAB, SETTINGS }

sealed interface AiLabUiState {
    data object Idle : AiLabUiState
    data class Loading(val message: UiText) : AiLabUiState
    data class Success(val result: ThreatAnalysisResult) : AiLabUiState
    data class Error(val message: UiText) : AiLabUiState
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
    /** Reads Android's strict Private DNS setting; supplied by DI. */
    private val isPrivateDnsStrict: () -> Boolean = { false },
    /** Last fallback the core had to take; supplied by DI. */
    private val configWarning: StateFlow<ConfigWarning> = MutableStateFlow(ConfigWarning.NONE),
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
    private val _showAddDnsFilterDialog = MutableStateFlow(false)
    private val _inspectedScript = MutableStateFlow<String?>(null)
    private val _showAddScriptDialog = MutableStateFlow(false)
    private val _showScriptStore = MutableStateFlow(false)
    private val _inspectedApp = MutableStateFlow<AppFirewallRule?>(null)
    private val _appSearchQuery = MutableStateFlow("")
    private val _appCategoryFilter = MutableStateFlow<String?>(null)
    private val _selectedAppFilter = MutableStateFlow<String?>(null)
    private val _aiLabState = MutableStateFlow<AiLabUiState>(AiLabUiState.Idle)
    private val _showVpnPermissionPrompt = MutableStateFlow(false)
    private val _dnsProbeRunning = MutableStateFlow(false)

    /**
     * Android's Private DNS sends lookups past the tunnel resolver. The Home
     * banner explains the reduced filtering; a resume re-reads the system
     * setting because it can only be changed outside the app.
     */
    private val _privateDnsOn = MutableStateFlow(false)
    val privateDnsOn: StateFlow<Boolean> = _privateDnsOn.asStateFlow()

    /**
     * One-shot request for the Protection tab to open a specific detail page.
     * The screen consumes it, so re-selecting the tab later lands on the list.
     */
    private val _requestedProtectionSection = MutableStateFlow<ProtectionSection?>(null)
    val requestedProtectionSection: StateFlow<ProtectionSection?> =
        _requestedProtectionSection.asStateFlow()

    fun consumeProtectionSection() {
        _requestedProtectionSection.value = null
    }

    /** Android drops the status notification when permission was missing. */
    fun refreshStatusNotification() = vpnController.refreshStatusNotification()

    /** Enumerates installed apps for the firewall picker (binder work). */
    fun installedAppsForFirewall(): List<FirewallAppChoice> =
        repository.installedAppsForFirewall()

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
            combine(
                repository.logTotal,
                repository.logBlockedTotal,
                repository.logAllowedTotal,
                repository.windowTotals,
            ) { total, blocked, allowed, window -> LogTotals(total, blocked, allowed, window) },
            _searchQuery,
        ) { head, logs, totals, query ->
            val (tab, settings, stats) = head
            UiPartA(
                tab,
                settings,
                stats,
                logs,
                totals.total,
                totals.blocked,
                totals.allowed,
                totals.window,
                query,
            )
        },
        combine(
            _statusFilter,
            repository.filterLists,
            repository.appFirewallRules,
            combine(
                repository.dnsProviders,
                repository.dnsRewrites,
                repository.dnsBackup,
                repository.dnsBackupMode,
                _dnsProbeRunning,
            ) { providers, rewrites, backup, backupMode, probing ->
                UiDns(providers, rewrites, backup, backupMode, probing)
            },
            vpnController.isVpnActive,
        ) { status, filters, apps, dns, active ->
            UiPartB(
                status,
                filters,
                apps,
                dns.providers,
                dns.rewrites,
                dns.backup,
                dns.backupMode,
                dns.probing,
                active,
            )
        },
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
                _showAddDnsFilterDialog,
            ) { q, cat, app, lab, addDns -> UiPartD(q, cat, app, lab, addDns) },
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
        // The picker knows packages; a log row knows the package the core
        // attributed. A name may also arrive from a deep link, so resolve it.
        val selectedPackage = d.selectedApp?.let { selected ->
            b.apps.firstOrNull {
                it.packageName.equals(selected, true) || it.appName.equals(selected, true)
            }?.packageName ?: selected
        }
        val logs = a.logs.filter { log ->
            val query = a.query
            val matchesQuery = query.isBlank() ||
                log.domain.contains(query, true) ||
                log.matchedRule?.contains(query, true) == true ||
                log.filterListName?.contains(query, true) == true ||
                log.appPackage?.contains(query, true) == true
            val matchesStatus = b.status == null || log.status == b.status
            // Rows stored before attribution existed (or carried over from an
            // older database) still match through their `$app=` rule text.
            val matchesApp = selectedPackage == null ||
                log.appPackage.equals(selectedPackage, true) ||
                log.matchedRule?.contains(selectedPackage, true) == true
            matchesQuery && matchesStatus && matchesApp
        }

        val apps = b.apps.filter { app ->
            val matchesSearch = d.appSearch.isBlank() ||
                app.appName.contains(d.appSearch, true) ||
                app.packageName.contains(d.appSearch, true)
            val matchesCat = when (d.appCategoryFilter) {
                null -> true
                AppCategoryFilter.BLOCKED -> app.wifiAccess == FirewallAccess.BLOCK ||
                    app.wifiScreenOffAccess == FirewallAccess.BLOCK ||
                    app.cellularAccess == FirewallAccess.BLOCK ||
                    app.cellularScreenOffAccess == FirewallAccess.BLOCK ||
                    app.roamingAccess == FirewallAccess.BLOCK
                AppCategoryFilter.FILTERED -> app.isFilterRouted
                AppCategoryFilter.UNFILTERED -> !app.isFilterRouted
                else -> app.category == d.appCategoryFilter
            }
            matchesSearch && matchesCat
        }

        AdGuardUiState(
            currentTab = a.tab,
            settings = a.settings,
            stats = a.stats,
            windowTotals = a.windowTotals,
            logs = a.logs,
            filteredLogs = logs,
            logTotal = a.logTotal,
            logBlockedTotal = a.logBlockedTotal,
            logAllowedTotal = a.logAllowedTotal,
            filterLists = b.filters,
            appFirewallRules = apps,
            allAppFirewallRules = b.apps,
            // The log pane names a row's owner even when the Apps tab is
            // filtered down to something else.
            appNames = b.apps.associate { it.packageName to it.appName },
            dnsProviders = b.dns,
            dnsRewrites = b.rewrites,
            dnsBackup = b.backup,
            dnsBackupMode = b.backupMode,
            isDnsProbeRunning = b.isProbing,
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
            showAddDnsFilterDialog = d.showAddDnsFilter,
            showVpnPermissionPrompt = d.showVpnPermission,
            loadingMessage = d.loadingMessage,
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = AdGuardUiState(),
    )

    init {
        _privateDnsOn.value = isPrivateDnsStrict()
        // A fallback the user cannot see looks like a bug: say which choice
        // the core had to replace, once per change.
        viewModelScope.launch {
            configWarning.collect { warning ->
                configWarningMessage(warning)?.let { emit(AdGuardEffect.ShowSnackbar(it)) }
            }
        }
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
            is AdGuardIntent.SelectTab -> {
                _currentTab.value = intent.tab
                // Both tabs show windowed per-app totals from the persisted
                // log; load them as the tab comes into view and keep them
                // fresh while it stays there.
                repository.setAppUsageVisible(
                    intent.tab == AdGuardTab.APPS || intent.tab == AdGuardTab.STATISTICS,
                )
            }
            is AdGuardIntent.OpenProtectionSection -> {
                _currentTab.value = AdGuardTab.PROTECTION
                _requestedProtectionSection.value = intent.section
            }
            is AdGuardIntent.ToggleProtection -> toggleProtection()
            is AdGuardIntent.ToggleAdBlocking ->
                repository.toggleAdBlocking(!uiState.value.settings.isAdBlockingEnabled)

            is AdGuardIntent.ToggleAnnoyances ->
                repository.toggleAnnoyances(!uiState.value.settings.isAnnoyancesEnabled)

            is AdGuardIntent.ToggleBrowsingSecurity ->
                repository.toggleBrowsingSecurity(!uiState.value.settings.isBrowsingSecurityEnabled)

            is AdGuardIntent.ToggleTracking ->
                repository.toggleTrackingProtection(!uiState.value.settings.isTrackingProtectionEnabled)

            is AdGuardIntent.ToggleDns ->
                repository.toggleDnsProtection(!uiState.value.settings.isDnsProtectionEnabled)

            is AdGuardIntent.ToggleHttps -> {
                // Without a trusted CA the engine can only relay, so an "on"
                // switch would lie. Send the user to the module that installs
                // the certificate instead of toggling something inert.
                val enabling = !uiState.value.settings.isHttpsFilteringEnabled
                if (enabling && !coreEngine.isCaTrusted()) {
                    emit(AdGuardEffect.ShowSnackbar(UiText.Resource(R.string.home_https_needs_cert)))
                    _currentTab.value = AdGuardTab.PROTECTION
                    // Land on the page that installs the CA instead of leaving
                    // the user on the landing with no idea what to do next.
                    _requestedProtectionSection.value = ProtectionSection.HTTPS
                } else {
                    repository.toggleHttpsFiltering(enabling)
                }
            }

            is AdGuardIntent.ToggleFirewall ->
                repository.toggleFirewall(!uiState.value.settings.isFirewallEnabled)

            is AdGuardIntent.ToggleEcoMode ->
                repository.toggleEcoBatteryMode(!uiState.value.settings.isEcoBatteryModeEnabled)

            is AdGuardIntent.ToggleStealth ->
                repository.toggleStealthMode(!uiState.value.settings.isStealthModeEnabled)

            is AdGuardIntent.SetStealthPreset -> repository.applyStealthPreset(intent.preset)

            is AdGuardIntent.ToggleBlockQuic -> repository.toggleBlockQuic(intent.enabled)
            is AdGuardIntent.SetAppLanguage -> repository.setAppLanguage(intent.language)
            is AdGuardIntent.SetThemeMode -> repository.setThemeMode(intent.mode)
            is AdGuardIntent.ToggleBlockDoh -> repository.toggleBlockDoh(intent.enabled)
            is AdGuardIntent.ToggleBlockDot -> repository.toggleBlockDot(intent.enabled)
            is AdGuardIntent.ToggleSafeSearch -> repository.toggleSafeSearch(intent.enabled)
            is AdGuardIntent.ToggleCosmeticFiltering ->
                repository.toggleCosmeticFiltering(intent.enabled)
            is AdGuardIntent.ToggleFilterHttp3 ->
                repository.toggleFilterHttp3(intent.enabled)
            is AdGuardIntent.SetFilterAutoUpdate ->
                repository.setFilterAutoUpdate(intent.hours)
            is AdGuardIntent.ToggleAutoStart ->
                repository.toggleAutoStart(intent.enabled)
            is AdGuardIntent.ToggleSmartFiltering ->
                repository.toggleSmartFiltering(intent.enabled)
            is AdGuardIntent.ToggleLogAllowed -> repository.toggleLogAllowed(intent.enabled)
            is AdGuardIntent.SetBlockMode -> repository.setBlockMode(intent.mode)
            is AdGuardIntent.SearchQueryChanged -> _searchQuery.value = intent.query
            is AdGuardIntent.FilterStatusChanged -> _statusFilter.value = intent.status
            is AdGuardIntent.InspectLog -> _inspectedLog.value = intent.log
            is AdGuardIntent.AddCustomRule -> {
                repository.addCustomRule(intent.rule)
                _showCustomRuleDialog.value = false
                emit(
                    AdGuardEffect.ShowSnackbar(UiText.Formatted(R.string.rule_added, intent.rule)),
                )
            }

            is AdGuardIntent.RemoveCustomRule -> repository.removeCustomRule(intent.rule)
            is AdGuardIntent.UpdateAllCustomRules -> {
                repository.updateAllCustomRules(intent.rules)
                // Keep the sheet open: add/delete/import are incremental edits,
                // and the import notice would vanish with the sheet.
                emit(
                    AdGuardEffect.ShowSnackbar(
                        UiText.Formatted(R.string.rules_saved, intent.rules.size),
                    ),
                )
            }

            is AdGuardIntent.SelectDnsProvider -> {
                repository.selectDnsProvider(intent.id)
                emit(AdGuardEffect.ShowSnackbar(UiText.Resource(R.string.dns_upstream_changed)))
            }

            is AdGuardIntent.AddCustomDnsProvider -> {
                val message = repository.addCustomDnsProvider(
                    intent.name,
                    intent.address,
                    intent.type,
                )
                emit(AdGuardEffect.ShowSnackbar(message))
            }

            is AdGuardIntent.ProbeDnsProvider -> probeDnsProvider(intent.id)

            is AdGuardIntent.SetBackupDns ->
                repository.setBackupDns(intent.mode, intent.providerId)

            is AdGuardIntent.AddDnsRewrite -> {
                val message = repository.addDnsRewrite(intent.host, intent.answer)
                emit(AdGuardEffect.ShowSnackbar(message))
            }

            is AdGuardIntent.RemoveDnsRewrite -> {
                repository.removeDnsRewrite(intent.host)
                emit(
                    AdGuardEffect.ShowSnackbar(
                        UiText.Formatted(R.string.dns_rewrite_removed, intent.host),
                    ),
                )
            }

            is AdGuardIntent.UpdateAppFirewall -> {
                repository.updateAppFirewall(
                    packageName = intent.packageName,
                    appName = intent.appName,
                    wifi = intent.wifi,
                    wifiScreenOff = intent.wifiScreenOff,
                    cellular = intent.cellular,
                    cellularScreenOff = intent.cellularScreenOff,
                    roaming = intent.roaming,
                    isFilterRouted = intent.filtered,
                    isHttpsFiltered = intent.httpsFiltered,
                    notifyBlocked = intent.notifyBlocked,
                    proxyAccess = intent.proxyAccess,
                )
                // The sheet reads this snapshot, not the repository flow, so
                // without the copy every switch would snap back to its old
                // value on the next recomposition.
                _inspectedApp.value = _inspectedApp.value?.let { current ->
                    if (current.packageName != intent.packageName) {
                        current
                    } else {
                        current.copy(
                            wifiAccess = intent.wifi ?: current.wifiAccess,
                            wifiScreenOffAccess =
                                intent.wifiScreenOff ?: current.wifiScreenOffAccess,
                            cellularAccess = intent.cellular ?: current.cellularAccess,
                            cellularScreenOffAccess =
                                intent.cellularScreenOff ?: current.cellularScreenOffAccess,
                            roamingAccess = intent.roaming ?: current.roamingAccess,
                            isFilterRouted = intent.filtered ?: current.isFilterRouted,
                            isHttpsFiltered = intent.httpsFiltered ?: current.isHttpsFiltered,
                            notifyBlocked = intent.notifyBlocked ?: current.notifyBlocked,
                            proxyAccess = intent.proxyAccess ?: current.proxyAccess,
                        )
                    }
                }
            }
            is AdGuardIntent.UpdateFirewallSettings -> repository.updateFirewallSettings(
                globalRules = intent.globalRules,
                customRules = intent.customRules,
                notifications = intent.notifications,
                allowWifi = intent.allowWifi,
                allowWifiScreenOff = intent.allowWifiScreenOff,
                allowCellular = intent.allowCellular,
                allowCellularScreenOff = intent.allowCellularScreenOff,
                allowRoaming = intent.allowRoaming,
            )
            is AdGuardIntent.ResetFirewall -> {
                repository.resetFirewall()
                _inspectedApp.value = null
                emit(AdGuardEffect.ShowSnackbar(UiText.Resource(R.string.firewall_reset_done)))
            }
            is AdGuardIntent.EnsureFirewallApp ->
                repository.ensureFirewallApp(intent.packageName, intent.appName)
            is AdGuardIntent.OpenAppManagement -> {
                _currentTab.value = AdGuardTab.APPS
                repository.setAppUsageVisible(true)
                _inspectedApp.value = intent.app
            }
            is AdGuardIntent.RestartVpn -> {
                if (vpnController.isVpnActive.value) {
                    vpnController.restartVpnService()
                    emit(AdGuardEffect.ShowSnackbar(UiText.Resource(R.string.vpn_restarting)))
                } else {
                    emit(AdGuardEffect.ShowSnackbar(UiText.Resource(R.string.vpn_off_changes_next)))
                }
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
            is AdGuardIntent.SetAppUsageRange -> repository.setAppUsageRange(intent.range)
            is AdGuardIntent.SetAppUsageTransport -> repository.setAppUsageTransport(intent.transport)
            is AdGuardIntent.ClearLogs -> repository.clearLogs()
            is AdGuardIntent.ResetStats -> repository.resetStats()
            is AdGuardIntent.LoadMoreLogs -> repository.loadMoreLogs()
            is AdGuardIntent.ExportLogs -> viewModelScope.launch {
                val result = repository.exportLogs(intent.uri)
                emit(AdGuardEffect.ShowSnackbar(result.message))
            }
            is AdGuardIntent.SetLogTailing -> repository.setLogTailing(intent.tailing)
            is AdGuardIntent.ShowCustomRuleDialog -> _showCustomRuleDialog.value = intent.show
            is AdGuardIntent.ShowCustomRuleEditor -> _showCustomRuleEditor.value = intent.show
            is AdGuardIntent.FilterSearchQueryChanged -> _filterSearchQuery.value = intent.query
            is AdGuardIntent.ShowAddFilterDialog -> _showAddFilterDialog.value = intent.show
            is AdGuardIntent.ShowAddDnsFilterDialog -> _showAddDnsFilterDialog.value = intent.show
            is AdGuardIntent.AddCustomFilter -> {
                repository.addCustomFilter(intent.name, intent.url)
                _showAddFilterDialog.value = false
                emit(AdGuardEffect.ShowSnackbar(UiText.Resource(R.string.filter_new_loading)))
            }
            is AdGuardIntent.AddDnsFilter -> {
                repository.addCustomFilter(intent.name, intent.url, dnsOnly = true)
                _showAddDnsFilterDialog.value = false
                emit(AdGuardEffect.ShowSnackbar(UiText.Resource(R.string.filter_new_loading)))
            }

            is AdGuardIntent.ImportLocalFilter -> {
                repository.importLocalFilter(intent.uri, intent.dnsOnly)
                _showAddFilterDialog.value = false
                _showAddDnsFilterDialog.value = false
            }

            is AdGuardIntent.ExportBackup -> viewModelScope.launch {
                val result = repository.exportBackup(intent.uri)
                emit(AdGuardEffect.ShowSnackbar(result.message))
            }

            is AdGuardIntent.ImportBackup -> viewModelScope.launch {
                val result = repository.importBackup(intent.uri)
                emit(AdGuardEffect.ShowSnackbar(result.message))
            }

            is AdGuardIntent.InspectFilter -> _inspectedFilter.value = intent.id
            is AdGuardIntent.RestoreDefaultFilters -> {
                repository.restoreDefaultFilters()
                emit(AdGuardEffect.ShowSnackbar(UiText.Resource(R.string.filter_restored_defaults)))
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
                emit(
                    AdGuardEffect.ShowSnackbar(
                        UiText.Formatted(R.string.script_installing, intent.name),
                    ),
                )
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
                stripUtm = intent.stripUtm,
                blockWebRtc = intent.blockWebRtc,
                disguiseUa = intent.disguiseUa,
                blockCookies = intent.blockCookies,
                blockAllCookies = intent.blockAllCookies,
                stripEtag = intent.stripEtag,
                stripThirdPartyAuthorization = intent.stripThirdPartyAuthorization,
                hideThirdPartyReferer = intent.hideThirdPartyReferer,
                injectGpcDnt = intent.injectGpcDnt,
                hideSearchQuery = intent.hideSearchQuery,
                blockPushApi = intent.blockPushApi,
                blockGeolocationApi = intent.blockGeolocationApi,
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
    }

    /**
     * Quick Settings entry point. A tile cannot raise the system VPN consent
     * dialog itself, so it opens this Activity and the prompt flag does it.
     */
    fun enableProtectionFromShortcut() {
        if (vpnController.isVpnActive.value) return
        repository.toggleProtection(true)
        if (vpnController.prepareIfNeeded() != null) {
            _showVpnPermissionPrompt.value = true
        } else {
            vpnController.startVpnService()
        }
    }

    /** Update notification tapped: the refreshed lists live behind Protection. */
    fun openFilters() = onIntent(AdGuardIntent.SelectTab(AdGuardTab.PROTECTION))

    /** Assistant deep link: the Activity tab filtered to one app. */
    fun openLogForApp(packageName: String) {
        _selectedAppFilter.value = packageName
        _currentTab.value = AdGuardTab.ACTIVITY
    }

    /** Assistant shortcut: the Activity tab with no leftover app or domain filter. */
    fun openRecentActivity() {
        _selectedAppFilter.value = null
        _searchQuery.value = ""
        _currentTab.value = AdGuardTab.ACTIVITY
    }

    /** Assistant deep link: the Activity tab searched for one domain. */
    fun openLogForDomain(domain: String) {
        _selectedAppFilter.value = null
        _searchQuery.value = domain
        _currentTab.value = AdGuardTab.ACTIVITY
    }

    /** Assistant per-app panel: open the Apps tab on that app's management sheet. */
    fun openAppDetails(packageName: String, appName: String? = null) {
        val app = uiState.value.allAppFirewallRules.firstOrNull { it.packageName == packageName }
            ?: AppFirewallRule(packageName, appName ?: packageName)
        onIntent(AdGuardIntent.OpenAppManagement(app))
    }

    /** Initial chip selection for a freshly composed Apps screen. */
    fun currentAppUsageRange(): AppUsageRange = repository.currentAppUsageRange()

    fun currentAppUsageTransport(): AppUsageTransport = repository.currentAppUsageTransport()

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
        emit(
            AdGuardEffect.ShowSnackbar(
                if (next) UiText.Resource(R.string.protection_on)
                else UiText.Resource(R.string.protection_off),
            ),
        )
    }

    /** The rewrite editor's inline check; the repository re-runs it on save. */
    fun validateDnsRewrite(
        host: String,
        answer: String,
    ): git.shin.adfree.core.DnsRewriteValidation =
        coreEngine.validateDnsRewrite(host, answer)

    private fun probeDnsProvider(id: String) {
        if (_dnsProbeRunning.value) return
        _dnsProbeRunning.value = true
        viewModelScope.launch {
            val result = try {
                repository.probeDnsProvider(id)
            } finally {
                _dnsProbeRunning.value = false
            }
            emit(
                AdGuardEffect.ShowSnackbar(
                    result?.let { CoreText.dnsProbeResult(it) }
                        ?: UiText.Resource(R.string.dns_probe_failed),
                ),
            )
        }
    }

    private fun handleThreatScan(domain: String) {
        if (domain.isBlank()) return
        viewModelScope.launch {
            _aiLabState.value = AiLabUiState.Loading(
                UiText.Formatted(R.string.threat_analyzing, domain),
            )
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

    private fun configWarningMessage(warning: ConfigWarning): UiText? =
        CoreText.configWarning(warning)

    /**
     * Re-reads the system Private DNS switch and re-pushes the config: turning
     * it on has to stop the DoT reset right away, not at the next unrelated
     * settings change.
     */
    fun refreshPrivateDnsState() {
        _privateDnsOn.value = isPrivateDnsStrict()
        syncConfig()
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

    /** Root-mode state; reads the store and looks for su without elevating. */
    fun rootTrustStatus(): git.shin.adfree.core.RootTrustBinding? =
        coreEngine.rootTrustStatus()

    /**
     * Installs the CA into the system store so apps that ignore user CAs
     * (Cronet and friends) trust it too. Elevation can sit on a consent dialog,
     * so the call runs off the main thread.
     */
    fun installRootCa(onDone: (git.shin.adfree.core.RootTrustBinding?) -> Unit) {
        viewModelScope.launch {
            val result = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                coreEngine.installRootCa()
            }
            onDone(result)
        }
    }

    /** Removes the CA from the system store. Blocking work, off the main thread. */
    fun removeRootCa(onDone: (git.shin.adfree.core.RootTrustBinding?) -> Unit) {
        viewModelScope.launch {
            val result = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                coreEngine.removeRootCa()
            }
            onDone(result)
        }
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
        onDone(coreEngine.mitmStatus())
    }

    /**
     * Block ECH (AdGuard's low-level switch): strip the ECH config from DNS
     * answers so every host stays decryptable. Off by default; with it off an
     * ECH host is spliced and left unfiltered instead of failing. The engine
     * reads the flag per DNS answer, so this takes effect with the next lookup.
     */
    fun setEchBlocking(enabled: Boolean) {
        repository.toggleEchBlocking(enabled)
    }

    /** HTTPS allowlist: hosts the proxy must not decrypt. */
    fun addHttpsSkipHost(raw: String) {
        repository.addHttpsSkipHost(raw)
    }

    fun removeHttpsSkipHost(host: String) {
        repository.removeHttpsSkipHost(host)
    }

    /** HTTPS blocklist + inverse mode: decrypt only these hosts. */
    fun addHttpsOnlyHost(raw: String) {
        repository.addHttpsOnlyHost(raw)
    }

    fun removeHttpsOnlyHost(host: String) {
        repository.removeHttpsOnlyHost(host)
    }

    fun setHttpsOnlyMode(enabled: Boolean) {
        repository.setHttpsOnlyMode(enabled)
    }

    /**
     * Routing mode: SOCKS5 for new TCP flows or direct. The core reads the
     * binding per SYN, so a change never rewrites a flow that is already up.
     */
    fun setProxy(proxy: ProxySettings) {
        repository.updateProxy(proxy)
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
        val logBlockedTotal: Long,
        val logAllowedTotal: Long,
        val windowTotals: LogWindowTotals,
        val query: String,
    )

    /** The log-wide and windowed counters travel together. */
    private data class LogTotals(
        val total: Long,
        val blocked: Long,
        val allowed: Long,
        val window: LogWindowTotals,
    )

    private data class UiPartB(
        val status: FilterStatus?,
        val filters: List<git.shin.adfree.model.FilterList>,
        val apps: List<AppFirewallRule>,
        val dns: List<git.shin.adfree.model.DnsProvider>,
        val rewrites: List<git.shin.adfree.model.DnsRewriteRule>,
        val backup: DnsBackup?,
        val backupMode: DnsBackupMode,
        val isProbing: Boolean,
        val isVpnActive: Boolean,
    )

    private data class UiDns(
        val providers: List<git.shin.adfree.model.DnsProvider>,
        val rewrites: List<git.shin.adfree.model.DnsRewriteRule>,
        val backup: DnsBackup?,
        val backupMode: DnsBackupMode,
        val probing: Boolean,
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
        val showAddDnsFilter: Boolean,
    ) {
        var showVpnPermission: Boolean = false
        var loadingMessage: UiText? = null
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
        val loadingMessage: UiText?,
        val userscripts: List<UserScriptInfo>,
        val scriptsMasterEnabled: Boolean,
        val scriptStore: UserScriptStoreState,
    )
}
