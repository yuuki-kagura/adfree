package git.shin.adfree.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Public
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.model.ProxySettings
import git.shin.adfree.model.normalizeProxyHost
import git.shin.adfree.ui.AdGuardIntent
import git.shin.adfree.ui.AdGuardViewModel
import git.shin.adfree.ui.theme.AdGuardBlueDns
import git.shin.adfree.ui.theme.AdGuardDarkBg
import git.shin.adfree.ui.theme.AdGuardDarkOutline
import git.shin.adfree.ui.theme.AdGuardDarkSurface
import git.shin.adfree.ui.theme.AdGuardGreenPrimary
import git.shin.adfree.ui.theme.AdGuardOrangeWarning
import git.shin.adfree.ui.theme.AdGuardRedBlocked
import git.shin.adfree.ui.theme.AdGuardTextMuted
import git.shin.adfree.ui.theme.AdGuardTextPrimary
import git.shin.adfree.ui.theme.AdGuardTextSecondary

/**
 * Full-screen network destination: what leaves the tunnel, which resolver sees
 * the names, and whether TLS is decrypted for filtering.
 */
@Composable
fun NetworkScreen(
    viewModel: AdGuardViewModel,
    onBack: () -> Unit,
    onManageScripts: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsState()

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(AdGuardDarkBg),
    ) {
        Column(modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)) {
            HubDestinationHeader(
                title = "Mạng",
                subtitle = "DNS, lọc HTTPS và đường ra của lưu lượng",
                onBack = onBack,
            )
        }

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp),
        ) {
            Spacer(modifier = Modifier.height(8.dp))

            SettingsSwitch(
                icon = Icons.Default.Bolt,
                title = "Chặn QUIC / UDP 443",
                subtitle = "Buộc client quay về TCP để engine thấy được hostname",
                checked = state.settings.blockQuic,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleBlockQuic(it)) },
            )

            Spacer(modifier = Modifier.height(10.dp))

            SettingsSwitch(
                icon = Icons.Default.Lock,
                title = "Chặn DNS mã hóa (DoH/DoT)",
                subtitle = "Chặn IP của nhà cung cấp encrypted DNS để tránh bypass filter",
                checked = state.settings.blockDoh,
                onCheckedChange = { viewModel.onIntent(AdGuardIntent.ToggleBlockDoh(it)) },
            )

            Spacer(modifier = Modifier.height(24.dp))

            ProxySection(
                viewModel = viewModel,
                saved = state.settings.proxy,
            )

            Spacer(modifier = Modifier.height(24.dp))

            DnsProviderSection(
                providers = state.dnsProviders,
                selectedId = state.settings.selectedDnsProviderId,
                onSelect = { viewModel.onIntent(AdGuardIntent.SelectDnsProvider(it)) },
                onAdd = { name, address ->
                    viewModel.onIntent(AdGuardIntent.AddCustomDnsProvider(name, address))
                },
            )

            Spacer(modifier = Modifier.height(24.dp))

            HttpsFilterSection(
                viewModel = viewModel,
                fullEchEnabled = state.settings.isFullEchEnabled,
                onManageScripts = onManageScripts,
            )

            Spacer(modifier = Modifier.height(72.dp))
        }
    }
}

/**
 * Routing mode: outbound SOCKS5 for TCP flows.
 *
 * The fields edit a local draft; nothing reaches the core until Save, so a
 * half-typed address never becomes a binding whose failure is only visible in
 * the log. A disabled proxy is saved as-is, which lets the user fill the
 * endpoint first and switch it on later.
 */
@Composable
private fun ProxySection(
    viewModel: AdGuardViewModel,
    saved: ProxySettings,
) {
    var draft by remember(saved) { mutableStateOf(saved) }
    var portText by remember(saved) { mutableStateOf(saved.port.toString()) }
    var error by remember(saved) { mutableStateOf<String?>(null) }

    val host = normalizeProxyHost(draft.host)
    val port = portText.toIntOrNull()

    fun save() {
        if (draft.enabled) {
            if (host == null) {
                error = "Chỉ hỗ trợ địa chỉ IPv4/IPv6, không dùng tên miền"
                return
            }
            if (port == null || port !in 1..65535) {
                error = "Cổng phải trong khoảng 1–65535"
                return
            }
        }
        error = null
        viewModel.setProxy(
            draft.copy(
                host = host ?: draft.host.trim(),
                port = port ?: draft.port,
                username = draft.username.trim(),
            ),
        )
    }

    Column {
        Text(
            text = "Đường ra của lưu lượng",
            fontSize = 14.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextPrimary,
        )
        Text(
            text = "Gửi luồng TCP qua một proxy SOCKS5 thay vì kết nối trực tiếp.",
            fontSize = 11.sp,
            color = AdGuardTextMuted,
        )
        Spacer(modifier = Modifier.height(10.dp))

        SettingsSwitch(
            icon = Icons.Default.Public,
            title = "SOCKS5 proxy",
            subtitle = "Chỉ TCP đi qua proxy; DNS và UDP vẫn đi trực tiếp",
            checked = draft.enabled,
            onCheckedChange = { enabled ->
                draft = draft.copy(enabled = enabled)
                error = null
            },
        )

        Spacer(modifier = Modifier.height(10.dp))

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                OutlinedTextField(
                    value = draft.host,
                    onValueChange = {
                        draft = draft.copy(host = it)
                        error = null
                    },
                    label = { Text("Địa chỉ IP proxy", fontSize = 11.sp) },
                    placeholder = { Text("192.168.1.10 hoặc [::1]", fontSize = 11.sp) },
                    singleLine = true,
                    isError = error != null,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    colors = proxyFieldColors(),
                )
                Spacer(modifier = Modifier.height(6.dp))
                OutlinedTextField(
                    value = portText,
                    onValueChange = {
                        portText = it.filter(Char::isDigit).take(5)
                        error = null
                    },
                    label = { Text("Cổng", fontSize = 11.sp) },
                    placeholder = { Text("1080", fontSize = 11.sp) },
                    singleLine = true,
                    isError = error != null,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    colors = proxyFieldColors(),
                )
                Spacer(modifier = Modifier.height(6.dp))
                OutlinedTextField(
                    value = draft.username,
                    onValueChange = {
                        draft = draft.copy(username = it)
                        error = null
                    },
                    label = { Text("Tên đăng nhập (tuỳ chọn)", fontSize = 11.sp) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    colors = proxyFieldColors(),
                )
                Spacer(modifier = Modifier.height(6.dp))
                OutlinedTextField(
                    value = draft.password,
                    onValueChange = {
                        draft = draft.copy(password = it)
                        error = null
                    },
                    label = { Text("Mật khẩu (tuỳ chọn)", fontSize = 11.sp) },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    colors = proxyFieldColors(),
                )
                error?.let {
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(it, fontSize = 11.sp, color = AdGuardRedBlocked)
                }
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "Tên đăng nhập và mật khẩu chỉ được gửi khi cả hai được nhập. " +
                        "Proxy phải hỗ trợ CONNECT tới địa chỉ IP.",
                    fontSize = 10.sp,
                    color = AdGuardTextMuted,
                )
                Spacer(modifier = Modifier.height(10.dp))
                Button(
                    onClick = { save() },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(8.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = AdGuardBlueDns),
                ) {
                    Text("Lưu cấu hình proxy", color = Color.Black, fontWeight = FontWeight.Bold)
                }
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = when {
                        !saved.enabled -> "Đang tắt: mọi kết nối đi trực tiếp."
                        saved.isUsable -> "Đang áp dụng cho kết nối mới: ${saved.host}:${saved.port}"
                        else -> "Cấu hình đã lưu chưa hợp lệ, engine đang kết nối trực tiếp."
                    },
                    fontSize = 10.sp,
                    color = when {
                        !saved.enabled -> AdGuardTextMuted
                        saved.isUsable -> AdGuardGreenPrimary
                        else -> AdGuardOrangeWarning
                    },
                )
            }
        }
    }
}

@Composable
private fun proxyFieldColors() = OutlinedTextFieldDefaults.colors(
    focusedBorderColor = AdGuardBlueDns,
    unfocusedBorderColor = AdGuardDarkOutline,
    focusedTextColor = AdGuardTextPrimary,
    unfocusedTextColor = AdGuardTextPrimary,
    focusedLabelColor = AdGuardBlueDns,
    unfocusedLabelColor = AdGuardTextSecondary,
)
