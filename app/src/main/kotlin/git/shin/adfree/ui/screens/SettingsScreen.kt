package git.shin.adfree.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Science
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.core.MitmStatus
import git.shin.adfree.core.ScriptBinding
import git.shin.adfree.model.DnsBlockMode
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

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(AdGuardDarkBg)
            .verticalScroll(scrollState)
            .padding(horizontal = 16.dp, vertical = 12.dp)
    ) {
        Text(
            text = "CÀI ĐẶT & TỐI ƯU PIN",
            fontSize = 18.sp,
            fontWeight = FontWeight.Black,
            color = AdGuardTextPrimary,
            letterSpacing = 1.sp
        )
        Text(
            text = "DNS mã hóa, Chế độ tàng hình & Bộ lọc tiết kiệm năng lượng",
            fontSize = 12.sp,
            color = AdGuardTextMuted
        )

        Spacer(modifier = Modifier.height(20.dp))

        SettingsSwitch(
            icon = Icons.Default.Bolt,
            title = "Chặn QUIC / UDP 443",
            subtitle = "Buộc client quay về TCP để engine thấy được hostname",
            checked = state.settings.blockQuic,
            onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleBlockQuic(it)) }
        )

        Spacer(modifier = Modifier.height(10.dp))

        SettingsSwitch(
            icon = Icons.Default.Lock,
            title = "Chặn DNS mã hóa (DoH/DoT)",
            subtitle = "Chặn IP của nhà cung cấp encrypted DNS để tránh bypass filter",
            checked = state.settings.blockDoh,
            onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleBlockDoh(it)) }
        )

        Spacer(modifier = Modifier.height(10.dp))

        SettingsSwitch(
            icon = Icons.Default.Visibility,
            title = "Ghi log cả request hợp lệ",
            subtitle = "Tắt để tiết kiệm CPU: chỉ ghi lại những gì bị chặn",
            checked = state.settings.logAllowedRequests,
            onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleLogAllowed(it)) }
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

        Spacer(modifier = Modifier.height(24.dp))

        HttpsFilterSection(viewModel)

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
 * button, and opens the script editor.
 */
@Composable
private fun HttpsFilterSection(viewModel: AdGuardViewModel) {
    var status by remember { mutableStateOf<MitmStatus?>(null) }
    var showCert by remember { mutableStateOf(false) }
    var showEditor by remember { mutableStateOf(false) }

    // Lazily load the status; the core is cheap to query.
    androidx.compose.runtime.LaunchedEffect(Unit) {
        status = viewModel.readMitmStatus()
    }

    Column {
        Text(
            text = "LỌC HTTPS (MITM)",
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
            subtitle = "Chèn script tùy chỉnh vào trang web",
            checked = status?.scriptsEnabled == true,
            onCheckedChange = { enabled -> viewModel.setMitmEnabled(enabled) { status = it } }
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
                    }
                    OutlinedButton(
                        onClick = { viewModel.createCa { status = it } },
                        shape = RoundedCornerShape(8.dp),
                    ) {
                        Text(if (status?.hasCa == true) "Tạo lại" else "Tạo CA", fontSize = 11.sp)
                    }
                }

                if (status?.hasCa == true) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            onClick = { viewModel.installCertificate() },
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
                }

                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "Giai đoạn: ${status?.stage ?: "—"} " +
                        "• ${status?.scriptCount ?: 0} script • " +
                        "${status?.leavesIssued ?: 0} cert đã cấp",
                    fontSize = 10.sp,
                    color = AdGuardTextMuted,
                )

                OutlinedButton(
                    onClick = { showEditor = true },
                    modifier = Modifier.padding(top = 8.dp),
                    shape = RoundedCornerShape(8.dp),
                ) {
                    Text("Sửa script tùy chỉnh", fontSize = 11.sp)
                }
            }
        }
    }

    if (showCert) {
        CertificateDialog(status?.caPem.orEmpty()) { showCert = false }
    }
    if (showEditor) {
        ScriptEditorDialog(
            initial = emptyList(),
            onDismiss = { showEditor = false },
            onSave = { scripts, enabled -> viewModel.setScripts(scripts, enabled) },
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

@Composable
private fun ScriptEditorDialog(
    initial: List<ScriptBinding>,
    onDismiss: () -> Unit,
    onSave: (List<ScriptBinding>, Boolean) -> Unit,
) {
    var enabled by remember { mutableStateOf(true) }
    var body by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Script tùy chỉnh", fontSize = 16.sp) },
        text = {
            Column {
                Text(
                    text = "JS chạy trên mọi trang HTTPS. Hết lỗi sẽ bị bỏ qua.",
                    fontSize = 11.sp,
                    color = AdGuardTextMuted,
                )
                Spacer(modifier = Modifier.height(8.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Bật", fontSize = 12.sp, color = AdGuardTextPrimary)
                    Spacer(modifier = Modifier.size(8.dp))
                    Switch(
                        checked = enabled,
                        onCheckedChange = { enabled = it },
                        colors = SwitchDefaults.colors(
                            checkedTrackColor = AdGuardGreenPrimary,
                        ),
                    )
                }
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = body,
                    onValueChange = { body = it },
                    modifier = Modifier.height(180.dp),
                    label = { Text("Mã JS", fontSize = 11.sp) },
                    textStyle = androidx.compose.ui.text.TextStyle(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                    ),
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                val scripts = if (body.isBlank()) {
                    emptyList()
                } else {
                    listOf(ScriptBinding("user", body, enabled = true))
                }
                onSave(scripts, enabled)
                onDismiss()
            }) { Text("Lưu") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Huỷ") } },
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
                text = "ENGINE",
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextSecondary,
                letterSpacing = 1.sp
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
                        fontSize = 10.sp,
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
