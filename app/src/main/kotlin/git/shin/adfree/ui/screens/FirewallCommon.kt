package git.shin.adfree.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.R
import git.shin.adfree.model.FirewallAccess
import git.shin.adfree.model.ProxyAccess
import git.shin.adfree.ui.theme.AdGuardGreenPrimary
import git.shin.adfree.ui.theme.AdGuardOrangeWarning
import git.shin.adfree.ui.theme.AdGuardRedBlocked
import git.shin.adfree.ui.theme.AdGuardTextMuted
import git.shin.adfree.ui.theme.AdGuardTextPrimary
import git.shin.adfree.ui.theme.AdGuardTextSecondary

/** Label for one tri-state answer; the state is a word, not an icon. */
@Composable
internal fun firewallAccessLabel(access: FirewallAccess): String = stringResource(
    when (access) {
        FirewallAccess.INHERIT -> R.string.firewall_access_inherit
        FirewallAccess.ALLOW -> R.string.firewall_access_allow
        FirewallAccess.BLOCK -> R.string.firewall_access_block
    },
)

@Composable
internal fun firewallAccessColor(access: FirewallAccess): Color = when (access) {
    FirewallAccess.INHERIT -> AdGuardTextMuted
    FirewallAccess.ALLOW -> AdGuardGreenPrimary
    FirewallAccess.BLOCK -> AdGuardRedBlocked
}

/**
 * One firewall dimension as three chips. Both the per-app sheet and the
 * standalone rule screen edit the same model, so the wording lives here.
 */
@Composable
internal fun FirewallAccessRow(
    title: String,
    subtitle: String,
    access: FirewallAccess,
    onSelect: (FirewallAccess) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier.fillMaxWidth()) {
        Text(
            text = title,
            fontSize = 13.sp,
            fontWeight = FontWeight.SemiBold,
            color = AdGuardTextPrimary,
        )
        Text(
            text = subtitle,
            fontSize = 11.sp,
            color = AdGuardTextSecondary,
            modifier = Modifier.padding(top = 1.dp),
        )
        Row(
            modifier = Modifier.padding(top = 6.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            FirewallAccess.entries.forEach { option ->
                FilterChip(
                    selected = access == option,
                    onClick = { onSelect(option) },
                    label = {
                        Text(stringResource(option.labelRes()), fontSize = 10.sp)
                    },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = option.chipColor(),
                        selectedLabelColor = Color.White,
                        containerColor = Color(0x222F3A46),
                        labelColor = AdGuardTextMuted,
                    ),
                )
            }
        }
    }
}

private fun FirewallAccess.labelRes(): Int = when (this) {
    FirewallAccess.INHERIT -> R.string.firewall_access_inherit
    FirewallAccess.ALLOW -> R.string.firewall_access_allow
    FirewallAccess.BLOCK -> R.string.firewall_access_block
}

@Composable
private fun FirewallAccess.chipColor(): Color = when (this) {
    FirewallAccess.INHERIT -> Color(0xFF3A4653)
    FirewallAccess.ALLOW -> AdGuardGreenPrimary
    FirewallAccess.BLOCK -> AdGuardRedBlocked
}

/**
 * One app's SOCKS5 routing answer as three chips. The core enforces it on
 * new TCP and UDP flows; `DIRECT` also overrides a global proxy switch.
 */
@Composable
internal fun ProxyAccessRow(
    subtitle: String,
    access: ProxyAccess,
    onSelect: (ProxyAccess) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier.fillMaxWidth()) {
        Text(
            text = stringResource(R.string.apps_detail_proxy_title),
            fontSize = 13.sp,
            fontWeight = FontWeight.SemiBold,
            color = AdGuardTextPrimary,
        )
        Text(
            text = subtitle,
            fontSize = 11.sp,
            color = AdGuardTextSecondary,
            modifier = Modifier.padding(top = 1.dp),
        )
        Row(
            modifier = Modifier.padding(top = 6.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            ProxyAccess.entries.forEach { option ->
                FilterChip(
                    selected = access == option,
                    onClick = { onSelect(option) },
                    label = {
                        Text(stringResource(option.labelRes()), fontSize = 10.sp)
                    },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = option.chipColor(),
                        selectedLabelColor = Color.White,
                        containerColor = Color(0x222F3A46),
                        labelColor = AdGuardTextMuted,
                    ),
                )
            }
        }
    }
}

private fun ProxyAccess.labelRes(): Int = when (this) {
    ProxyAccess.INHERIT -> R.string.proxy_access_inherit
    ProxyAccess.THROUGH -> R.string.proxy_access_through
    ProxyAccess.DIRECT -> R.string.proxy_access_direct
}

@Composable
private fun ProxyAccess.chipColor(): Color = when (this) {
    ProxyAccess.INHERIT -> Color(0xFF3A4653)
    ProxyAccess.THROUGH -> AdGuardGreenPrimary
    ProxyAccess.DIRECT -> AdGuardOrangeWarning
}
