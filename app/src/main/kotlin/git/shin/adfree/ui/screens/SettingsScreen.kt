package git.shin.adfree.ui.screens

import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Science
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import git.shin.adfree.core.MitmStatus
import git.shin.adfree.model.DnsBlockMode
import git.shin.adfree.model.DnsProvider
import git.shin.adfree.model.ProtectionSettings
import git.shin.adfree.model.caNotAfterMs
import git.shin.adfree.model.filterAutoUpdateLabel
import git.shin.adfree.model.normalizeHttpsHost
import git.shin.adfree.model.parseDnsEndpoint
import git.shin.adfree.ui.AdGuardTab
import git.shin.adfree.ui.AdGuardIntent
import git.shin.adfree.ui.AdGuardViewModel
import git.shin.adfree.ui.theme.AdGuardBlueDns
import git.shin.adfree.ui.theme.AdGuardDarkBg
import git.shin.adfree.ui.theme.AdGuardDarkOutline
import git.shin.adfree.ui.theme.AdGuardPurpleAI
import git.shin.adfree.ui.theme.AdGuardDarkSurface
import git.shin.adfree.ui.theme.AdGuardDarkSurfaceVariant
import git.shin.adfree.ui.theme.AdGuardGreenLight
import git.shin.adfree.ui.theme.AdGuardGreenPrimary
import git.shin.adfree.ui.theme.AdGuardOrangeWarning
import git.shin.adfree.ui.theme.AdGuardRedBlocked
import git.shin.adfree.ui.theme.AdGuardTextMuted
import git.shin.adfree.ui.theme.AdGuardTextPrimary
import git.shin.adfree.ui.theme.AdGuardTextSecondary

/**
 * Settings screen.
 *
 * Every switch here maps to one field the Rust core reads on the packet path;
 * there are no decorative options.
 */
@Composable
fun SettingsScreen(
    viewModel: AdGuardViewModel,
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()
    val scrollState = rememberScrollState()
    var pendingRestoreUri by remember { mutableStateOf<String?>(null) }

    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/json"),
    ) { uri ->
        uri?.let { viewModel.onIntent(AdGuardIntent.ExportBackup(it.toString())) }
    }
    val importLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        // Ask before overwriting; the actual read happens after confirmation.
        uri?.let { pendingRestoreUri = it.toString() }
    }

    // The header lives outside the scrolling column on purpose: it describes
    // where you are, and should not slide away as soon as the list moves.
    Column(
        modifier = modifier
            .fillMaxSize()
            .background(AdGuardDarkBg)
    ) {
        Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
            Text(
                text = "Cài đặt",
                fontSize = 19.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextPrimary,
            )
            Text(
                text = "Ghi log, lọc thông minh, tàng hình và sao lưu",
                fontSize = 12.sp,
                color = AdGuardTextMuted
            )
        }

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(scrollState)
                .padding(horizontal = 16.dp)
        ) {
        Spacer(modifier = Modifier.height(8.dp))

            SettingsSwitch(
                icon = Icons.Default.Visibility,
                title = "Ghi log cả request hợp lệ",
                subtitle = "Tắt để tiết kiệm CPU: chỉ ghi lại những gì bị chặn",
                checked = state.settings.logAllowedRequests,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleLogAllowed(it)) }
            )

            Spacer(modifier = Modifier.height(10.dp))

            SettingsSwitch(
                icon = Icons.Default.Refresh,
                title = "Lọc thông minh",
                subtitle = "Host bị chặn liên tục được tạm cho qua 60 giây để app ngừng retry tốn CPU",
                checked = state.settings.isSmartFilteringEnabled,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleSmartFiltering(it)) }
            )

            Spacer(modifier = Modifier.height(10.dp))

            Text(
                text = "Trả lời khi chặn",
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextSecondary,
                modifier = Modifier.padding(bottom = 6.dp)
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                git.shin.adfree.model.DnsBlockMode.entries.forEach { mode ->
                    FilterChip(
                        selected = state.settings.blockMode == mode,
                        onClick = { viewModel.onIntent(AdGuardIntent.SetBlockMode(mode)) },
                        label = { Text(mode.label, fontSize = 11.sp) },
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = AdGuardGreenPrimary,
                            selectedLabelColor = Color.Black,
                        ),
                    )
                }
            }

            Spacer(modifier = Modifier.height(18.dp))

            Text(
                text = "Tự động cập nhật bộ lọc",
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextSecondary,
            )
            Text(
                text = "Chỉ kiểm tra khi mở app — không đánh thức radio hay chạy nền. " +
                    "List bật và đã tải sẽ được làm mới khi quá hạn.",
                fontSize = 11.sp,
                color = AdGuardTextMuted,
                modifier = Modifier.padding(top = 2.dp, bottom = 6.dp),
            )
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState())
                    .testTag("filter_auto_update_chips"),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                listOf(0, 6, 12, 24, 48, 72).forEach { hours ->
                    FilterChip(
                        selected = state.settings.filterAutoUpdateHours == hours,
                        onClick = { viewModel.onIntent(AdGuardIntent.SetFilterAutoUpdate(hours)) },
                        label = { Text(filterAutoUpdateLabel(hours), fontSize = 11.sp) },
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = AdGuardGreenPrimary,
                            selectedLabelColor = Color.Black,
                        ),
                    )
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            Text(
                text = "Chế độ tàng hình",
                fontSize = 14.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextPrimary
            )
            Spacer(modifier = Modifier.height(10.dp))
            StealthToggleRow(
                title = "Xoá tham số tracking (utm_*, fbclid)",
                subtitle = "Chỉ áp dụng khi bật lọc HTTPS",
                isChecked = state.settings.stripUtmTracking,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.UpdateStealth(stripUtm = it)) }
            )
            StealthToggleRow(
                title = "Chặn rò rỉ WebRTC",
                subtitle = "Ngăn WebRTC leak IP thật",
                isChecked = state.settings.blockWebRtcLeaks,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.UpdateStealth(blockWebRtc = it)) }
            )
            StealthToggleRow(
                title = "Chặn cookie bên thứ ba",
                subtitle = "Giảm theo dõi chéo giữa các site",
                isChecked = state.settings.blockThirdPartyCookies,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.UpdateStealth(blockCookies = it)) }
            )

            Spacer(modifier = Modifier.height(24.dp))

            BackupSection(
                onExport = { exportLauncher.launch("adfree-backup.json") },
                onImport = {
                    importLauncher.launch(arrayOf("application/json", "text/plain", "*/*"))
                },
            )

            Spacer(modifier = Modifier.height(24.dp))

            EngineInfoSection(state.stats.filterBuildMs)

            Spacer(modifier = Modifier.height(24.dp))

            // A diagnostic screen rather than a daily tab: reachable from here.
            SettingsLink(
                icon = Icons.Default.Science,
                title = "Phòng thí nghiệm bảo mật",
                subtitle = "Quét một tên miền qua engine để xem luồng phân tích",
                onClick = { viewModel.onIntent(AdGuardIntent.SelectTab(AdGuardTab.AI_LAB)) }
            )

            Spacer(modifier = Modifier.height(72.dp))
    }
    }

    pendingRestoreUri?.let { uri ->
        AlertDialog(
            onDismissRequest = { pendingRestoreUri = null },
            title = { Text("Khôi phục bản sao lưu?") },
            text = {
                Text(
                    "Cài đặt, bộ lọc đang bật, bộ lọc tự thêm và quy tắc sẽ bị " +
                        "thay bằng nội dung tệp. Userscript trên máy này được giữ nguyên.",
                    fontSize = 12.sp,
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        pendingRestoreUri = null
                        viewModel.onIntent(AdGuardIntent.ImportBackup(uri))
                    },
                ) {
                    Text("Khôi phục", color = AdGuardOrangeWarning)
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingRestoreUri = null }) {
                    Text("Huỷ")
                }
            },
        )
    }
}

/** Export/restore the two core blobs without including device-local scripts. */
@Composable
private fun BackupSection(
    onExport: () -> Unit,
    onImport: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(
                text = "Sao lưu & khôi phục",
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextPrimary,
            )
            Text(
                text = "Gồm cài đặt, bộ lọc đang bật, bộ lọc tự thêm và quy tắc. " +
                    "Userscript ở lại thiết bị.",
                fontSize = 11.sp,
                color = AdGuardTextMuted,
                modifier = Modifier.padding(top = 2.dp),
            )
            Spacer(modifier = Modifier.height(10.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = onExport,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(8.dp),
                ) {
                    Text("Xuất tệp", fontSize = 11.sp, color = AdGuardGreenLight)
                }
                OutlinedButton(
                    onClick = onImport,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(8.dp),
                ) {
                    Text("Khôi phục", fontSize = 11.sp, color = AdGuardOrangeWarning)
                }
            }
        }
    }
}

/** A settings entry that navigates somewhere instead of toggling a flag. */
@Composable
private fun SettingsLink(
    icon: ImageVector,
    title: String,
    subtitle: String,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() },
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        border = CardDefaults.outlinedCardBorder().copy(
            brush = androidx.compose.ui.graphics.Brush.linearGradient(
                listOf(AdGuardDarkOutline, AdGuardPurpleAI.copy(alpha = 0.2f))
            )
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(36.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(AdGuardPurpleAI.copy(alpha = 0.15f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = AdGuardPurpleAI,
                    modifier = Modifier.size(20.dp)
                )
            }
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = AdGuardTextPrimary
                )
                Text(
                    text = subtitle,
                    fontSize = 11.sp,
                    color = AdGuardTextSecondary
                )
            }
            Icon(
                imageVector = Icons.Default.ChevronRight,
                contentDescription = null,
                tint = AdGuardTextMuted,
                modifier = Modifier.size(20.dp)
            )
        }
    }
}

/**
 * HTTPS filtering (MITM) section: shows the CA state, hands the user an install
 * button, and points at the extensions destination.
 */
@Composable
internal fun HttpsFilterSection(
    viewModel: AdGuardViewModel,
    fullEchEnabled: Boolean,
    onManageScripts: () -> Unit,
) {
    var status by remember { mutableStateOf<MitmStatus?>(null) }
    var showCert by remember { mutableStateOf(false) }
    var showCertGate by remember { mutableStateOf(false) }
    // HTTPS filtering is the persisted setting (the same one the engine config
    // is built from); `scriptsEnabled` only says whether the script set is
    // armed, which is a different thing entirely.
    var httpsEnabled by remember {
        mutableStateOf(viewModel.uiState.value.settings.isHttpsFilteringEnabled)
    }
    // Live view of the trust store: installing the CA while the app sits in
    // the background must flip this without a restart.
    var caTrusted by remember { mutableStateOf(viewModel.isCaTrusted()) }
    // Root mode: whether su is available and whether the system store already
    // carries the CA. Loading it never elevates.
    var rootTrust by remember {
        mutableStateOf<git.shin.adfree.core.RootTrustBinding?>(null)
    }
    var rootBusy by remember { mutableStateOf(false) }
    // The CA is installed by hand, outside the app: its expiry is the only
    // warning the user gets before every TLS connection starts failing.
    val caExpiryMs = remember(status?.caPem) { status?.caPem?.let(::caNotAfterMs) }
    // Set when the gate dialog sends the user off to install the certificate,
    // so coming back with it installed turns filtering on as they intended.
    var pendingEnable by remember { mutableStateOf(false) }
    // Which website list the add dialog is editing; null keeps it closed.
    var addTarget by remember { mutableStateOf<HttpsListTarget?>(null) }
    val ui by viewModel.uiState.collectAsState()

    val context = LocalContext.current

    // Lazily load the status; the core is cheap to query.
    androidx.compose.runtime.LaunchedEffect(Unit) {
        status = viewModel.readMitmStatus()
        caTrusted = viewModel.isCaTrusted()
        rootTrust = viewModel.rootTrustStatus()
    }

    // The system certificate installer lives in another activity: re-check the
    // store and honour the pending enable when we come back to the app.
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        status = viewModel.readMitmStatus()
        caTrusted = viewModel.isCaTrusted()
        rootTrust = viewModel.rootTrustStatus()
        if (pendingEnable && caTrusted && !httpsEnabled) {
            pendingEnable = false
            httpsEnabled = true
            viewModel.setHttpsFiltering(true) { status = it }
        }
    }

    Column {
        Text(
            text = "Lọc HTTPS",
            fontSize = 14.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextPrimary
        )
        Text(
            text = "Tự ký chứng chỉ để đọc và chèn script vào trang HTTPS. " +
                "Cần cài chứng chỉ CA vào hệ thống.",
            fontSize = 11.sp,
            color = AdGuardTextMuted
        )
        Spacer(modifier = Modifier.height(10.dp))

        SettingsSwitch(
            icon = Icons.Default.Lock,
            title = "Bật lọc HTTPS",
            subtitle = "Giải mã HTTPS để lọc quảng cáo và chèn script",
            checked = httpsEnabled,
            onCheckedChange = { enabled ->
                if (enabled && !caTrusted) {
                    // Without a trusted CA the engine can only fall back to a
                    // plain relay, so an "on" switch would lie: ask for the
                    // certificate first.
                    pendingEnable = true
                    showCertGate = true
                } else {
                    httpsEnabled = enabled
                    viewModel.setHttpsFiltering(enabled) { status = it }
                }
            }
        )

        Spacer(modifier = Modifier.height(10.dp))

        // The opt-in trade: ECH hides the inner name from the proxy, so a host
        // that uses it has to be spliced — unfiltered. Off by default; nothing
        // changes for clients that do not use ECH. Read straight from the
        // collected settings, not a remembered snapshot: the saved switches
        // arrive after the first composition, and a snapshot would keep
        // showing the default until the next tap.
        SettingsSwitch(
            icon = Icons.Default.Visibility,
            title = "ECH đầy đủ",
            subtitle = "Cho trình duyệt tự mã hoá ECH end-to-end. Host dùng ECH sẽ " +
                "được nối thẳng, không lọc được.",
            checked = fullEchEnabled,
            onCheckedChange = { enabled -> viewModel.setFullEch(enabled) }
        )

        Spacer(modifier = Modifier.height(12.dp))

        // AdGuard's "Filter HTTPS websites" block: an allowlist that keeps TLS
        // intact for banking/client-cert sites, plus the inverse mode that only
        // decrypts named hosts.
        HttpsWebsiteSection(
            settings = ui.settings,
            onAddSkip = { addTarget = HttpsListTarget.SKIP },
            onRemoveSkip = { viewModel.removeHttpsSkipHost(it) },
            onOnlyModeChange = { viewModel.setHttpsOnlyMode(it) },
            onAddOnly = { addTarget = HttpsListTarget.ONLY },
            onRemoveOnly = { viewModel.removeHttpsOnlyHost(it) },
        )

        Spacer(modifier = Modifier.height(10.dp))

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column {
                        Text(
                            text = if (status?.hasCa == true) "CA đã tạo" else "Chưa có CA",
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Bold,
                            color = if (status?.hasCa == true) AdGuardGreenLight else AdGuardTextSecondary,
                        )
                        Text(
                            text = status?.fingerprint?.take(23)?.let { "Vân tay: $it…" }
                                ?: "Nhấn Tạo CA để bắt đầu",
                            fontSize = 10.sp,
                            color = AdGuardTextMuted,
                            fontFamily = FontFamily.Monospace,
                        )
                        Text(
                            text = if (caTrusted) "Chứng chỉ: đã cài đặt"
                                else "Chứng chỉ: chưa cài đặt",
                            fontSize = 11.sp,
                            color = if (caTrusted) AdGuardGreenLight else AdGuardOrangeWarning,
                        )
                        if (caExpiryMs != null) {
                            val now = System.currentTimeMillis()
                            // Compare instants for "expired": integer day math
                            // would keep reporting "còn 0 ngày" for the last
                            // day before, and the first day after, expiry.
                            val expired = caExpiryMs <= now
                            val daysLeft = (caExpiryMs - now) / 86_400_000L
                            Text(
                                text = if (expired) {
                                    "Hạn CA: đã hết hạn (${formatCertDate(caExpiryMs)})"
                                } else {
                                    "Hạn CA: ${formatCertDate(caExpiryMs)} (còn $daysLeft ngày)"
                                },
                                fontSize = 11.sp,
                                color = when {
                                    expired -> AdGuardRedBlocked
                                    daysLeft < 30 -> AdGuardOrangeWarning
                                    else -> AdGuardTextMuted
                                },
                            )
                        }
                    }
                    OutlinedButton(
                        onClick = {
                            viewModel.createCa { fresh ->
                                status = fresh
                                caTrusted = viewModel.isCaTrusted()
                                rootTrust = viewModel.rootTrustStatus()
                            }
                        },
                        shape = RoundedCornerShape(8.dp),
                    ) {
                        Text(if (status?.hasCa == true) "Tạo lại" else "Tạo CA", fontSize = 11.sp)
                    }
                }

                if (status?.hasCa == true) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            onClick = {
                                // The install is a multi-step trip through
                                // Settings; show the route before leaving.
                                pendingEnable = false
                                showCertGate = true
                            },
                            shape = RoundedCornerShape(8.dp),
                        ) {
                            Text("Cài chứng chỉ", fontSize = 11.sp)
                        }
                        OutlinedButton(
                            onClick = { showCert = true },
                            shape = RoundedCornerShape(8.dp),
                        ) {
                            Text("Xem PEM", fontSize = 11.sp)
                        }
                    }

                    // Root mode: the user store is ignored by apps targeting
                    // API 24+ (Cronet in Google apps is the visible case), so
                    // offering the system store is the only way to filter
                    // them without splicing their traffic verbatim.
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        text = if (rootBusy) "Đang xử lý…"
                        else rootTrust?.detail ?: "Đang kiểm tra quyền root…",
                        fontSize = 11.sp,
                        color = when {
                            rootBusy -> AdGuardTextMuted
                            rootTrust?.installed == true -> AdGuardGreenLight
                            rootTrust?.needsReboot == true -> AdGuardOrangeWarning
                            else -> AdGuardTextMuted
                        },
                    )
                    rootTrust?.let { trust ->
                        if (trust.suPresent || trust.installed) {
                            Row(
                                modifier = Modifier.padding(top = 6.dp),
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                            ) {
                                OutlinedButton(
                                    enabled = !rootBusy,
                                    onClick = {
                                        rootBusy = true
                                        viewModel.installRootCa { result ->
                                            rootBusy = false
                                            rootTrust = result
                                            caTrusted = viewModel.isCaTrusted()
                                            result?.detail?.let {
                                                Toast.makeText(context, it, Toast.LENGTH_LONG).show()
                                            }
                                        }
                                    },
                                    shape = RoundedCornerShape(8.dp),
                                ) {
                                    Text(
                                        if (trust.installed) "Cài lại CA hệ thống"
                                        else "Cài CA hệ thống (root)",
                                        fontSize = 11.sp,
                                    )
                                }
                                if (trust.installed) {
                                    OutlinedButton(
                                        enabled = !rootBusy,
                                        onClick = {
                                            rootBusy = true
                                            viewModel.removeRootCa { result ->
                                                rootBusy = false
                                                rootTrust = result
                                                caTrusted = viewModel.isCaTrusted()
                                                result?.detail?.let {
                                                    Toast.makeText(context, it, Toast.LENGTH_LONG).show()
                                                }
                                            }
                                        },
                                        shape = RoundedCornerShape(8.dp),
                                    ) {
                                        Text("Gỡ CA hệ thống", fontSize = 11.sp)
                                    }
                                }
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "Giai đoạn: ${status?.stage ?: "—"} " +
                        "• ${status?.scriptCount ?: 0} script • " +
                        "${status?.leavesIssued ?: 0} cert đã cấp",
                    fontSize = 11.sp,
                    color = AdGuardTextMuted,
                )

                OutlinedButton(
                    onClick = onManageScripts,
                    modifier = Modifier.padding(top = 8.dp),
                    shape = RoundedCornerShape(8.dp),
                ) {
                    Text("Quản lý tiện ích", fontSize = 11.sp)
                }
            }
        }
    }

    if (showCert) {
        CertificateDialog(status?.caPem.orEmpty()) { showCert = false }
    }
    addTarget?.let { target ->
        HttpsHostDialog(
            title = if (target == HttpsListTarget.SKIP) "Bỏ qua lọc HTTPS" else "Chỉ lọc trang này",
            onDismiss = { addTarget = null },
            onAdd = { host ->
                if (target == HttpsListTarget.SKIP) {
                    viewModel.addHttpsSkipHost(host)
                } else {
                    viewModel.addHttpsOnlyHost(host)
                }
            },
        )
    }
    if (showCertGate) {
        AlertDialog(
            onDismissRequest = {
                pendingEnable = false
                showCertGate = false
            },
            title = { Text("Cần cài chứng chỉ", fontSize = 16.sp) },
            text = {
                Column {
                    Text(
                        "Lọc HTTPS cần chứng chỉ của AdFree để giải mã kết nối. " +
                            "AdFree sẽ lưu tệp chứng chỉ vào Downloads rồi mở Cài đặt.",
                        fontSize = 12.sp,
                        color = AdGuardTextSecondary,
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        "Trong Cài đặt chọn: Bảo mật & quyền riêng tư → Cài đặt bảo " +
                            "mật khác → Mã hóa & thông tin xác thực → Cài đặt chứng " +
                            "chỉ → Chứng chỉ CA,\nrồi chọn tệp AdFree-CA.crt trong Downloads.",
                        fontSize = 12.sp,
                        color = AdGuardTextSecondary,
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    showCertGate = false
                    val saved = viewModel.installCertificate()
                    Toast.makeText(
                        context,
                        if (saved != null) "Đã lưu $saved vào Downloads"
                        else "Không lưu được chứng chỉ",
                        Toast.LENGTH_SHORT,
                    ).show()
                }) {
                    Text("Mở Cài đặt")
                }
            },
            dismissButton = {
                TextButton(onClick = {
                    pendingEnable = false
                    showCertGate = false
                }) {
                    Text("Để sau")
                }
            },
        )
    }
}

@Composable
private fun CertificateDialog(pem: String, onDismiss: () -> Unit) {
    val clipboard = LocalClipboardManager.current
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("CA của AdFree", fontSize = 16.sp) },
        text = {
            Column {
                Text(
                    text = "Lưu thành ca.pem rồi cài qua Cài đặt → Bảo mật → " +
                        "Mã hóa & thông tin xác thực → Cài chứng chỉ.",
                    fontSize = 12.sp,
                    color = AdGuardTextSecondary,
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = pem,
                    fontSize = 9.sp,
                    fontFamily = FontFamily.Monospace,
                    color = AdGuardTextMuted,
                    modifier = Modifier
                        .heightIn(max = 220.dp)
                        .verticalScroll(rememberScrollState()),
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                clipboard.setText(AnnotatedString(pem))
                onDismiss()
            }) { Text("Copy") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Đóng") } },
    )
}

/**
 * Resolver selection. The list is real state from the repository, including
 * custom resolvers restored from the settings blob; before this section it
 * existed only as an orphan intent with no screen.
 */
@Composable
internal fun DnsProviderSection(
    providers: List<DnsProvider>,
    selectedId: String,
    onSelect: (String) -> Unit,
    onAdd: (String, String) -> Unit,
) {
    var showDialog by remember { mutableStateOf(false) }
    val selected = providers.firstOrNull { it.id == selectedId } ?: providers.firstOrNull()

    Column {
        Text(
            text = "Máy chủ DNS",
            fontSize = 14.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextPrimary,
        )
        Text(
            text = "Resolver AdFree dùng để phân giải tên miền trước khi lọc.",
            fontSize = 11.sp,
            color = AdGuardTextMuted,
        )
        Spacer(modifier = Modifier.height(10.dp))
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { showDialog = true },
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 14.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(
                    imageVector = Icons.Default.Dns,
                    contentDescription = null,
                    tint = AdGuardBlueDns,
                    modifier = Modifier.size(20.dp),
                )
                Spacer(modifier = Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = selected?.name ?: "Chưa chọn resolver",
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardTextPrimary,
                    )
                    Text(
                        text = selected?.address ?: "Nhấn để chọn máy chủ DNS",
                        fontSize = 11.sp,
                        color = AdGuardTextMuted,
                    )
                    if (selected?.isCustom == true) {
                        Text("Tùy chỉnh", fontSize = 10.sp, color = AdGuardBlueDns)
                    }
                }
                Text("Đổi", fontSize = 12.sp, color = AdGuardBlueDns)
            }
        }
    }

    if (showDialog) {
        DnsProviderDialog(
            providers = providers,
            selectedId = selectedId,
            onDismiss = { showDialog = false },
            onSelect = {
                onSelect(it)
                showDialog = false
            },
            onAdd = { name, address ->
                onAdd(name, address)
                showDialog = false
            },
        )
    }
}

@Composable
private fun DnsProviderDialog(
    providers: List<DnsProvider>,
    selectedId: String,
    onDismiss: () -> Unit,
    onSelect: (String) -> Unit,
    onAdd: (String, String) -> Unit,
) {
    var name by remember { mutableStateOf("") }
    var address by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Máy chủ DNS", fontSize = 16.sp) },
        text = {
            Column(
                modifier = Modifier
                    .heightIn(max = 430.dp)
                    .verticalScroll(rememberScrollState()),
            ) {
                providers.forEach { provider ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onSelect(provider.id) }
                            .padding(vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(
                            selected = provider.id == selectedId,
                            onClick = { onSelect(provider.id) },
                        )
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = provider.name,
                                fontSize = 13.sp,
                                color = AdGuardTextPrimary,
                            )
                            Text(
                                text = provider.address,
                                fontSize = 11.sp,
                                color = AdGuardTextMuted,
                                fontFamily = FontFamily.Monospace,
                            )
                            if (provider.isCustom) {
                                Text("Tùy chỉnh", fontSize = 10.sp, color = AdGuardBlueDns)
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = "Thêm resolver",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextSecondary,
                )
                Spacer(modifier = Modifier.height(6.dp))
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Tên", fontSize = 11.sp) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(modifier = Modifier.height(6.dp))
                OutlinedTextField(
                    value = address,
                    onValueChange = {
                        address = it
                        error = null
                    },
                    label = { Text("Địa chỉ IPv4/IPv6", fontSize = 11.sp) },
                    placeholder = { Text("1.1.1.1 hoặc 1.1.1.1:53", fontSize = 11.sp) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                error?.let {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(it, fontSize = 11.sp, color = AdGuardRedBlocked)
                }
                Spacer(modifier = Modifier.height(8.dp))
                Button(
                    onClick = {
                        if (parseDnsEndpoint(address) == null) {
                            error = "Chỉ hỗ trợ DNS UDP dạng IP (ví dụ 1.1.1.1)"
                        } else {
                            onAdd(name, address)
                        }
                    },
                    enabled = address.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Thêm và chọn", fontSize = 12.sp)
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("Đóng") }
        },
    )
}

/** Engine build time, i.e. how long compiling the filter lists took. */
@Composable
private fun EngineInfoSection(buildMs: Long) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(
                text = "Trạng thái engine",
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextSecondary,
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = "Biên dịch bộ lọc: $buildMs ms",
                fontSize = 12.sp,
                color = AdGuardTextPrimary,
            )
        }
    }
}

/** A settings row with an icon and description. */
@Composable
fun SettingsSwitch(
    icon: ImageVector,
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Row(
                modifier = Modifier.weight(1f),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = AdGuardBlueDns,
                    modifier = Modifier.size(20.dp),
                )
                Spacer(modifier = Modifier.size(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = title,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardTextPrimary,
                    )
                    Text(
                        text = subtitle,
                        fontSize = 11.sp,
                        color = AdGuardTextMuted,
                    )
                }
            }
            Switch(
                checked = checked,
                onCheckedChange = onCheckedChange,
                colors = SwitchDefaults.colors(
                    checkedThumbColor = Color.White,
                    checkedTrackColor = AdGuardGreenPrimary,
                    uncheckedThumbColor = AdGuardTextMuted,
                    uncheckedTrackColor = AdGuardDarkSurfaceVariant,
                ),
            )
        }
    }
}

@Composable
fun StealthToggleRow(
    title: String,
    subtitle: String,
    isChecked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold,
                color = AdGuardTextPrimary
            )
            Text(
                text = subtitle,
                fontSize = 11.sp,
                color = AdGuardTextSecondary
            )
        }

        Switch(
            checked = isChecked,
            onCheckedChange = onCheckedChange,
            colors = SwitchDefaults.colors(
                checkedThumbColor = Color.White,
                checkedTrackColor = AdGuardGreenPrimary,
                uncheckedThumbColor = AdGuardTextMuted,
                uncheckedTrackColor = AdGuardDarkSurfaceVariant
            )
        )
    }
}

// ------------------------------------------------------- HTTPS website rules

private enum class HttpsListTarget { SKIP, ONLY }

/**
 * The two website lists behind "Lọc HTTPS".
 *
 * AdGuard calls them the website allowlist and blocklist; here the first is
 * always "leave these alone" and the second only applies when the inverse
 * switch is on, which the copy says instead of relying on a label.
 */
@Composable
private fun HttpsWebsiteSection(
    settings: ProtectionSettings,
    onAddSkip: () -> Unit,
    onRemoveSkip: (String) -> Unit,
    onOnlyModeChange: (Boolean) -> Unit,
    onAddOnly: () -> Unit,
    onRemoveOnly: (String) -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("https_website_rules"),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(
                text = "Trang web & HTTPS",
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextPrimary,
            )
            Text(
                text = "Chọn trang không bị giải mã, hoặc chỉ giải mã một số trang. " +
                    "Trang bị bỏ qua sẽ không lọc được quảng cáo và script.",
                fontSize = 11.sp,
                color = AdGuardTextMuted,
            )

            Spacer(modifier = Modifier.height(10.dp))

            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Chỉ lọc các trang trong danh sách",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardTextPrimary,
                    )
                    Text(
                        text = "Mọi trang khác được nối thẳng, không giải mã.",
                        fontSize = 11.sp,
                        color = AdGuardTextMuted,
                    )
                }
                Switch(
                    checked = settings.httpsOnlyMode,
                    onCheckedChange = onOnlyModeChange,
                    colors = SwitchDefaults.colors(checkedTrackColor = AdGuardGreenPrimary),
                )
            }

            HttpsHostList(
                label = if (settings.httpsOnlyMode) "Chỉ giải mã các trang này" else "Trang bỏ qua lọc",
                hint = if (settings.httpsOnlyMode) {
                    "Danh sách trắng của chế độ chỉ lọc."
                } else {
                    "Ngân hàng, trang dùng chứng chỉ riêng…"
                },
                hosts = if (settings.httpsOnlyMode) settings.httpsOnlyHosts else settings.httpsSkipHosts,
                onAdd = if (settings.httpsOnlyMode) onAddOnly else onAddSkip,
                onRemove = if (settings.httpsOnlyMode) onRemoveOnly else onRemoveSkip,
            )

            if (settings.httpsOnlyMode) {
                HttpsHostList(
                    label = "Luôn bỏ qua",
                    hint = "Các trang này không bao giờ bị giải mã, kể cả khi nằm trong danh sách trên.",
                    hosts = settings.httpsSkipHosts,
                    onAdd = onAddSkip,
                    onRemove = onRemoveSkip,
                )
            } else if (settings.httpsOnlyHosts.isNotEmpty()) {
                Text(
                    text = "${settings.httpsOnlyHosts.size} trang đang chờ trong danh sách " +
                        "\"chỉ lọc\" — bật công tắc trên để dùng.",
                    fontSize = 11.sp,
                    color = AdGuardTextMuted,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
        }
    }
}

@Composable
private fun HttpsHostList(
    label: String,
    hint: String,
    hosts: List<String>,
    onAdd: () -> Unit,
    onRemove: (String) -> Unit,
) {
    Column(modifier = Modifier.padding(top = 10.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = "$label (${hosts.size})",
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextSecondary,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = onAdd) {
                Text("Thêm", fontSize = 11.sp, color = AdGuardGreenLight)
            }
        }
        Text(hint, fontSize = 11.sp, color = AdGuardTextMuted)
        if (hosts.isEmpty()) {
            Text(
                text = "Chưa có trang nào.",
                fontSize = 11.sp,
                color = AdGuardTextMuted,
                modifier = Modifier.padding(top = 4.dp),
            )
        } else {
            hosts.forEach { host ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = host,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        color = AdGuardTextPrimary,
                        modifier = Modifier.weight(1f),
                    )
                    IconButton(onClick = { onRemove(host) }, modifier = Modifier.size(28.dp)) {
                        Icon(
                            Icons.Default.Close,
                            contentDescription = "Xóa $host",
                            tint = AdGuardTextMuted,
                            modifier = Modifier.size(14.dp),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun HttpsHostDialog(
    title: String,
    onDismiss: () -> Unit,
    onAdd: (String) -> Unit,
) {
    var value by remember { mutableStateOf("") }
    val normalized = normalizeHttpsHost(value)
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title, fontSize = 16.sp, fontWeight = FontWeight.Bold) },
        text = {
            Column {
                Text(
                    text = "Nhập tên miền, ví dụ example.com, *.example.com hoặc dán URL.",
                    fontSize = 12.sp,
                    color = AdGuardTextSecondary,
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = value,
                    onValueChange = { value = it },
                    singleLine = true,
                    isError = value.isNotBlank() && normalized == null,
                    placeholder = { Text("example.com", fontSize = 12.sp, color = AdGuardTextMuted) },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    colors = androidx.compose.material3.OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = AdGuardGreenPrimary,
                        unfocusedBorderColor = AdGuardDarkOutline,
                        focusedTextColor = AdGuardTextPrimary,
                        unfocusedTextColor = AdGuardTextPrimary,
                    ),
                )
                if (value.isNotBlank() && normalized == null) {
                    Text(
                        text = "Tên miền không hợp lệ (chỉ hỗ trợ ký tự ASCII; dùng dạng xn-- cho tên quốc tế).",
                        fontSize = 11.sp,
                        color = AdGuardOrangeWarning,
                        modifier = Modifier.padding(top = 4.dp),
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    normalized?.let {
                        onAdd(it)
                        onDismiss()
                    }
                },
                enabled = normalized != null,
            ) {
                Text("Thêm", color = AdGuardGreenLight)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Hủy", color = AdGuardTextSecondary) }
        },
    )
}

/** `dd/MM/yyyy` for the certificate line; the device locale decides digits. */
private fun formatCertDate(ms: Long): String =
    java.text.SimpleDateFormat("dd/MM/yyyy", java.util.Locale.getDefault())
        .format(java.util.Date(ms))
