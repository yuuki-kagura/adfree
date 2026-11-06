package git.shin.adfree.ui

import git.shin.adfree.l10n.Strings
import git.shin.adfree.core.AssetState
import git.shin.adfree.core.ConfigWarning
import git.shin.adfree.core.CoreEngine
import git.shin.adfree.data.AdGuardRepository
import git.shin.adfree.data.AutomationControl
import git.shin.adfree.data.ImportedLog
import git.shin.adfree.platform.AppUpdate
import git.shin.adfree.platform.LogSink
import git.shin.adfree.platform.PlatformHost
import git.shin.adfree.platform.TunnelControl
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
import git.shin.adfree.model.LogRuleSwitch
import git.shin.adfree.model.LogRuleSwitchKind
import git.shin.adfree.model.LogTypeTab
import git.shin.adfree.model.LogWindowTotals
import git.shin.adfree.model.NetworkRequestLog
import git.shin.adfree.model.ProtectionSettings
import git.shin.adfree.model.ProtectionStats
import git.shin.adfree.model.ProxyAccess
import git.shin.adfree.model.ProxySettings
import git.shin.adfree.model.ServiceUsage
import git.shin.adfree.model.ThreatAnalysisResult
import git.shin.adfree.model.UserScriptInfo
import git.shin.adfree.model.UserScriptStoreState
import git.shin.adfree.model.matchesLogSearch
import git.shin.adfree.model.withAllowlistRuleEnabled
import git.shin.adfree.security.ThreatAnalyzer
import git.shin.adfree.update.UpdateInfo
import git.shin.adfree.update.UpdateOutcome
import git.shin.adfree.update.UpdateUiState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
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


/**
 * MVI state holder.
 *
 * Single unidirectional state. Every number comes from [AdGuardRepository]
 * (atomics read from the Rust core) — no fake data. A plain class with its own
 * scope: the app-level container keeps the one instance, so rotation and
 * desktop window changes both keep the same state.
 */
class AdGuardViewModel(
    private val repository: AdGuardRepository,
    private val tunnel: TunnelControl,
    private val threatAnalyzer: ThreatAnalyzer,
    private val coreEngine: CoreEngine,
    /** The device prompts the certificate installer and toasts need. */
    private val platform: PlatformHost = git.shin.adfree.platform.NoopPlatformHost(),
    /** Where the core's and the tunnel's logs go; the host picks the sink. */
    private val log: LogSink = LogSink { },
    /** Callback that pushes settings down to the Rust core; supplied by DI. */
    private val onConfigChanged: () -> Unit = {},
    /** Reads the system's strict Private DNS setting; supplied by the host. */
    private val isPrivateDnsStrict: () -> Boolean = { false },
    /** Last fallback the core had to take; supplied by DI. */
    private val configWarning: StateFlow<ConfigWarning> = MutableStateFlow(ConfigWarning.NONE),
    /** The OTA question, supplied by DI; the Settings row renders its state. */
    private val appUpdate: AppUpdate,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    // ---------------------------------------------------------------- local UI

    private val _currentTab = MutableStateFlow(AdGuardTab.HOME)
    private val _searchQuery = MutableStateFlow("")
    private val _statusFilter = MutableStateFlow<FilterStatus?>(null)
    private val _logTypeFilter = MutableStateFlow(LogTypeTab.ALL)
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

    /** The downloaded services table, or null while the shipped one is used. */
    val servicesTableState: StateFlow<AssetState?> = repository.servicesState

    /**
     * Whether other apps may drive protection, and the token they must present.
     * Device-local by design, so it never travels in a backup.
     */
    val automationState: StateFlow<AutomationControl> = repository.automation.state

    /**
     * OTA state for the Settings version row. The controller lives in the
     * DI container, not here: the worker and the screen-on hook check through
     * the same instance, and this is only one more reader of it.
     */
    val appUpdateState: StateFlow<UpdateUiState> = appUpdate.state

    /** The Settings row tapped: the outcome comes back as a snackbar. */
    fun checkAppUpdateManually() = appUpdate.manualCheck()

    fun installAppUpdate(info: UpdateInfo) = appUpdate.downloadAndInstall(info)

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
    fun refreshStatusNotification() = tunnel.refreshStatusNotification()

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
                repository.importedLog,
            ) { tab, settings, stats, imported -> UiHead(tab, settings, stats, imported) },
            repository.logs,
            combine(
                repository.logTotal,
                repository.logBlockedTotal,
                repository.logAllowedTotal,
                repository.windowTotals,
                repository.serviceUsage,
            ) { total, blocked, allowed, window, services ->
                LogTotals(total, blocked, allowed, window, services)
            },
            _searchQuery,
            _logTypeFilter,
        ) { head, logs, totals, query, typeTab ->
            val (tab, settings, stats, imported) = head
            // While a file is open the screen shows the file: the rows, the
            // counter under the chips and the footer all have to agree with it,
            // or the list claims there is more to load than the file holds.
            UiPartA(
                tab,
                settings,
                stats,
                imported?.rows ?: logs,
                imported?.rows?.size?.toLong() ?: totals.total,
                imported?.blocked ?: totals.blocked,
                imported?.allowed ?: totals.allowed,
                totals.window,
                totals.services,
                query,
                typeTab,
                imported?.name,
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
            tunnel.isVpnActive,
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
            val matchesQuery = matchesLogSearch(log, a.query)
            // The type tabs come first because they are the row's own
            // classification, not a search: an unclassified row belongs to
            // `Other` rather than disappearing from every tab.
            val matchesType = a.typeTab.matches(log.requestType)
            val matchesStatus = b.status == null || log.status == b.status
            // Rows stored before attribution existed (or carried over from an
            // older database) still match through their `$app=` rule text.
            val matchesApp = selectedPackage == null ||
                log.appPackage.equals(selectedPackage, true) ||
                log.matchedRule?.contains(selectedPackage, true) == true
            matchesQuery && matchesType && matchesStatus && matchesApp
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
            serviceUsage = a.services,
            logs = a.logs,
            filteredLogs = logs,
            logTotal = a.logTotal,
            logBlockedTotal = a.logBlockedTotal,
            logAllowedTotal = a.logAllowedTotal,
            importedLogName = a.importName,
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
            logTypeFilter = a.typeTab,
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
        scope = scope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = AdGuardUiState(),
    )

    init {
        _privateDnsOn.value = isPrivateDnsStrict()
        // A fallback the user cannot see looks like a bug: say which choice
        // the core had to replace, once per change.
        scope.launch {
            configWarning.collect { warning ->
                configWarningMessage(warning)?.let { emit(AdGuardEffect.ShowSnackbar(it)) }
            }
        }
        // The OTA answer the user has to hear: a silent check that failed is
        // indistinguishable from one that never ran, so the row says which.
        scope.launch {
            appUpdate.outcomes.collect { outcome ->
                updateOutcomeMessage(outcome)?.let { emit(AdGuardEffect.ShowSnackbar(it)) }
            }
        }
        // Protection that was on when the app last ran comes back by itself;
        // a first run has nothing saved and waits for the user. The consent
        // dialog can only be raised by the Activity, hence the flag.
        if (repository.protectionWasOn()) {
            repository.toggleProtection(true)
            if (tunnel.needsConsent()) {
                _showVpnPermissionPrompt.value = true
            } else {
                tunnel.startVpnService()
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
                    emit(AdGuardEffect.ShowSnackbar(UiText.Resource(Strings.home_https_needs_cert)))
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
            is AdGuardIntent.SetLogLevel -> repository.setLogLevel(intent.level)
            is AdGuardIntent.ToggleExternalControl ->
                repository.automation.setEnabled(intent.enabled)
            AdGuardIntent.RotateControlToken -> repository.automation.rotateToken()
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
            is AdGuardIntent.FilterLogTypeChanged -> _logTypeFilter.value = intent.tab
            is AdGuardIntent.InspectLog -> _inspectedLog.value = intent.log
            is AdGuardIntent.SwitchLogRule -> switchLogRule(intent.rule, intent.enabled)
            is AdGuardIntent.AddCustomRule -> {
                repository.addCustomRule(intent.rule)
                _showCustomRuleDialog.value = false
                emit(
                    AdGuardEffect.ShowSnackbar(UiText.Formatted(Strings.rule_added, intent.rule)),
                )
            }

            is AdGuardIntent.RemoveCustomRule -> repository.removeCustomRule(intent.rule)
            is AdGuardIntent.ReplaceCustomRule ->
                repository.replaceCustomRule(intent.oldRule, intent.newRule)

            is AdGuardIntent.UpdateAllCustomRules -> {
                repository.updateAllCustomRules(intent.rules)
                // Keep the sheet open: add/delete/import are incremental edits,
                // and the import notice would vanish with the sheet.
                emit(
                    AdGuardEffect.ShowSnackbar(
                        UiText.Formatted(Strings.rules_saved, intent.rules.size),
                    ),
                )
            }

            is AdGuardIntent.SelectDnsProvider -> {
                repository.selectDnsProvider(intent.id)
                emit(AdGuardEffect.ShowSnackbar(UiText.Resource(Strings.dns_upstream_changed)))
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
                        UiText.Formatted(Strings.dns_rewrite_removed, intent.host),
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
                emit(AdGuardEffect.ShowSnackbar(UiText.Resource(Strings.firewall_reset_done)))
            }
            is AdGuardIntent.EnsureFirewallApp ->
                repository.ensureFirewallApp(intent.packageName, intent.appName)
            is AdGuardIntent.OpenAppManagement -> {
                _currentTab.value = AdGuardTab.APPS
                repository.setAppUsageVisible(true)
                _inspectedApp.value = intent.app
            }
            is AdGuardIntent.RestartVpn -> {
                if (tunnel.isVpnActive.value) {
                    tunnel.restartVpnService()
                    emit(AdGuardEffect.ShowSnackbar(UiText.Resource(Strings.vpn_restarting)))
                } else {
                    emit(AdGuardEffect.ShowSnackbar(UiText.Resource(Strings.vpn_off_changes_next)))
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
            is AdGuardIntent.ResetStats -> {
                repository.resetStats()
                emit(AdGuardEffect.ShowSnackbar(UiText.Resource(Strings.stats_cleared)))
            }
            is AdGuardIntent.LoadMoreLogs -> repository.loadMoreLogs()
            is AdGuardIntent.ExportLogs -> scope.launch {
                val result = repository.exportLogs(intent.uri)
                emit(AdGuardEffect.ShowSnackbar(result.message))
            }
            is AdGuardIntent.ImportLogs -> scope.launch {
                // Nothing to say when it works: the screen itself switches to
                // the file, and a snackbar over that would only repeat it.
                if (!repository.importLogs(intent.uri)) {
                    emit(AdGuardEffect.ShowSnackbar(UiText.Resource(Strings.log_import_failed)))
                }
            }
            is AdGuardIntent.CloseImportedLogs -> repository.closeImportedLogs()
            is AdGuardIntent.SetLogTailing -> repository.setLogTailing(intent.tailing)
            is AdGuardIntent.ShowCustomRuleDialog -> _showCustomRuleDialog.value = intent.show
            is AdGuardIntent.ShowCustomRuleEditor -> _showCustomRuleEditor.value = intent.show
            is AdGuardIntent.FilterSearchQueryChanged -> _filterSearchQuery.value = intent.query
            is AdGuardIntent.ShowAddFilterDialog -> _showAddFilterDialog.value = intent.show
            is AdGuardIntent.ShowAddDnsFilterDialog -> _showAddDnsFilterDialog.value = intent.show
            is AdGuardIntent.AddCustomFilter -> {
                repository.addCustomFilter(intent.name, intent.url)
                _showAddFilterDialog.value = false
                emit(AdGuardEffect.ShowSnackbar(UiText.Resource(Strings.filter_new_loading)))
            }
            is AdGuardIntent.AddDnsFilter -> {
                repository.addCustomFilter(intent.name, intent.url, dnsOnly = true)
                _showAddDnsFilterDialog.value = false
                emit(AdGuardEffect.ShowSnackbar(UiText.Resource(Strings.filter_new_loading)))
            }

            is AdGuardIntent.ImportLocalFilter -> {
                repository.importLocalFilter(intent.uri, intent.dnsOnly)
                _showAddFilterDialog.value = false
                _showAddDnsFilterDialog.value = false
            }

            is AdGuardIntent.ExportBackup -> scope.launch {
                val result = repository.exportBackup(intent.uri)
                emit(AdGuardEffect.ShowSnackbar(result.message))
            }

            is AdGuardIntent.ImportBackup -> scope.launch {
                val result = repository.importBackup(intent.uri)
                emit(AdGuardEffect.ShowSnackbar(result.message))
            }

            is AdGuardIntent.InspectFilter -> _inspectedFilter.value = intent.id
            is AdGuardIntent.RestoreDefaultFilters -> {
                repository.restoreDefaultFilters()
                emit(AdGuardEffect.ShowSnackbar(UiText.Resource(Strings.filter_restored_defaults)))
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
                        UiText.Formatted(Strings.script_installing, intent.name),
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
            is AdGuardIntent.SetServicesBreakdown ->
                repository.setServicesBreakdownVisible(intent.visible)
            is AdGuardIntent.SetServicesTableUrl -> repository.setServicesTableUrl(intent.url)
            AdGuardIntent.RefreshServicesTable -> repository.refreshServicesTable()
            is AdGuardIntent.ImportServicesTable -> repository.importServicesTable(intent.uri)
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
                antiDpi = intent.antiDpi,
                maskIp = intent.maskIp,
            )

            is AdGuardIntent.DismissLoading -> repository.dismissLoading()
            is AdGuardIntent.VpnPermissionResolved -> {
                // The dialog is gone either way; leaving the flag set would keep
                // the next tap from raising it again.
                _showVpnPermissionPrompt.value = false
                tunnel.onPermissionResult(intent.granted)
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
        // `isTunnelUp`, not the flag alone: a dispatched start whose establish
        // failed left the flag up, and this early return then refused every
        // following tap in silence — no log, no dialog, no tunnel.
        if (tunnel.isTunnelUp()) {
            log.line("enable-protection shortcut: tunnel already up")
            return
        }
        repository.toggleProtection(true)
        if (tunnel.needsConsent()) {
            log.line("enable-protection shortcut: VPN consent missing, raising prompt")
            _showVpnPermissionPrompt.value = true
        } else {
            log.line("enable-protection shortcut: dispatching tunnel start")
            tunnel.startVpnService()
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
        // reads true from the moment a start is dispatched, so a start whose
        // binder work failed left the first tap after it switching protection
        // *off* — turning off a tunnel that had never come up — and only the
        // tap after that brought the tunnel back.
        val next = !tunnel.isTunnelUp()
        if (next) {
            val needsPermission = tunnel.needsConsent()
            if (needsPermission) {
                _showVpnPermissionPrompt.value = true
                repository.toggleProtection(true)
            } else {
                repository.toggleProtection(true)
                tunnel.startVpnService()
            }
        } else {
            repository.toggleProtection(false)
            tunnel.stopVpnService()
        }
        emit(
            AdGuardEffect.ShowSnackbar(
                if (next) UiText.Resource(Strings.protection_on)
                else UiText.Resource(Strings.protection_off),
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
        scope.launch {
            val result = try {
                repository.probeDnsProvider(id)
            } finally {
                _dnsProbeRunning.value = false
            }
            emit(
                AdGuardEffect.ShowSnackbar(
                    result?.let { CoreText.dnsProbeResult(it) }
                        ?: UiText.Resource(Strings.dns_probe_failed),
                ),
            )
        }
    }

    private fun handleThreatScan(domain: String) {
        if (domain.isBlank()) return
        scope.launch {
            _aiLabState.value = AiLabUiState.Loading(
                UiText.Formatted(Strings.threat_analyzing, domain),
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
     * What a manual OTA check has to say for itself. The Available case is
     * silent here: the Settings row already shows the version and the install
     * button, and a snackbar on top of that would cover the thing it announces.
     */
    private fun updateOutcomeMessage(outcome: UpdateOutcome): UiText? = when (outcome) {
        UpdateOutcome.UpToDate -> UiText.Resource(Strings.update_outcome_up_to_date)
        UpdateOutcome.Available -> null
        UpdateOutcome.Failed -> UiText.Resource(Strings.update_outcome_failed)
        UpdateOutcome.InstallStarted -> UiText.Resource(Strings.update_outcome_install_started)
        UpdateOutcome.InstallFailed -> UiText.Resource(Strings.update_outcome_install_failed)
    }

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
        scope.launch {
            val result = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                coreEngine.installRootCa()
            }
            onDone(result)
        }
    }

    /** Removes the CA from the system store. Blocking work, off the main thread. */
    fun removeRootCa(onDone: (git.shin.adfree.core.RootTrustBinding?) -> Unit) {
        scope.launch {
            val result = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                coreEngine.removeRootCa()
            }
            onDone(result)
        }
    }

    /**
     * Asks the system, through its own elevation prompt, to trust the CA — the
     * desktop shape of [installRootCa], for a platform with no `su`. The dialog
     * blocks, so the ask runs off the main thread; `onDone` receives null when
     * the certificate is in the store now, and the system's own words when it
     * is not, a dismissed dialog included.
     */
    fun installSystemCa(onDone: (String?) -> Unit) {
        scope.launch {
            val reason = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                runCatching { platform.installSystemCa() }
                    .getOrElse { failure -> failure.message ?: "the trust store did not answer" }
            }
            onDone(reason)
        }
    }

    /** True when the CA is present in the device trust store. */
    fun isCaTrusted(): Boolean = coreEngine.isCaTrusted()

    /** The stored body of a user script; screens never hold the engine. */
    fun scriptText(id: String): String = coreEngine.scriptText(id).orEmpty()

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
     * Exports the CA certificate where the user can reach it and opens the
     * system screen that leads to the installer. Returns the exported file
     * name so the caller can tell the user what to pick, or null on failure.
     */
    fun installCertificate(): String? {
        val name = coreEngine.exportCaCertificate()
        platform.openCertificateInstaller()
        return name
    }

    /**
     * Switches one rule the log's detail panel lists, the way AdGuard does it:
     * a user rule parks behind a `!` rather than disappearing, a list turns off
     * whole, and both come back through the snackbar's action. The undo carries
     * what was just written, so it lands correctly even if the panel closed in
     * between and the rule is no longer on screen.
     */
    private fun switchLogRule(rule: LogRuleSwitch, enabled: Boolean) {
        when (rule.kind) {
            LogRuleSwitchKind.USER_RULE -> {
                val next = withAllowlistRuleEnabled(rule.target, enabled)
                if (next == rule.target) return
                repository.replaceCustomRule(rule.target, next)
                emit(
                    AdGuardEffect.ShowUndoSnackbar(
                        message = UiText.Formatted(
                            if (enabled) Strings.log_rule_switched_on else Strings.log_rule_switched_off,
                            next,
                        ),
                        actionLabel = UiText.Resource(Strings.common_undo),
                        undo = AdGuardIntent.SwitchLogRule(rule.copy(target = next), !enabled),
                    ),
                )
            }

            LogRuleSwitchKind.FILTER_LIST -> {
                if (rule.enabled == enabled) return
                repository.toggleFilterList(rule.target, enabled)
                emit(
                    AdGuardEffect.ShowUndoSnackbar(
                        message = UiText.Formatted(
                            if (enabled) Strings.log_list_switched_on else Strings.log_list_switched_off,
                            rule.label,
                        ),
                        actionLabel = UiText.Resource(Strings.common_undo),
                        undo = AdGuardIntent.SwitchLogRule(rule.copy(enabled = !enabled), !enabled),
                    ),
                )
            }
        }
    }

    private fun emit(effect: AdGuardEffect) {
        scope.launch { _effect.emit(effect) }
    }

    /** The tab's own state plus whatever file the user is reading instead. */
    private data class UiHead(
        val tab: AdGuardTab,
        val settings: ProtectionSettings,
        val stats: ProtectionStats,
        val imported: ImportedLog?,
    )

    private data class UiPartA(
        val tab: AdGuardTab,
        val settings: ProtectionSettings,
        val stats: ProtectionStats,
        val logs: List<NetworkRequestLog>,
        val logTotal: Long,
        val logBlockedTotal: Long,
        val logAllowedTotal: Long,
        val windowTotals: LogWindowTotals,
        val services: List<ServiceUsage>,
        val query: String,
        val typeTab: LogTypeTab,
        val importName: String?,
    )

    /** The log-wide and windowed counters travel together. */
    private data class LogTotals(
        val total: Long,
        val blocked: Long,
        val allowed: Long,
        val window: LogWindowTotals,
        val services: List<ServiceUsage>,
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
