package git.shin.adfree.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Lock
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import git.shin.adfree.ui.AdGuardIntent
import git.shin.adfree.ui.AdGuardViewModel
import git.shin.adfree.ui.theme.AdGuardDarkBg

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
