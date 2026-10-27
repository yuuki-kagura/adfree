package git.shin.adfree.ui.screens

import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Extension
import androidx.compose.material.icons.filled.Layers
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.ui.AdGuardViewModel
import git.shin.adfree.ui.theme.AdGuardBlueDns
import git.shin.adfree.ui.theme.AdGuardDarkBg
import git.shin.adfree.ui.theme.AdGuardDarkOutline
import git.shin.adfree.ui.theme.AdGuardDarkSurface
import git.shin.adfree.ui.theme.AdGuardGreenLight
import git.shin.adfree.ui.theme.AdGuardPurpleAI
import git.shin.adfree.ui.theme.AdGuardTextMuted
import git.shin.adfree.ui.theme.AdGuardTextPrimary
import git.shin.adfree.ui.theme.AdGuardTextSecondary

private enum class FilteringSection { ROOT, FILTERS, EXTENSIONS, NETWORK }

/**
 * The "Bộ lọc" tab landing.
 *
 * The tab used to be one long screen holding the catalogue, userscripts and a
 * scatter of network switches from Settings. AdGuard splits these by intent, so
 * the tab now opens a hub with three full-screen destinations: the filter
 * lists, the userscripts, and the network path (DNS + HTTPS filtering).
 */
@Composable
fun FilteringHubScreen(
    viewModel: AdGuardViewModel,
    modifier: Modifier = Modifier,
) {
    var section by rememberSaveable { mutableStateOf(FilteringSection.ROOT) }

    // Back first returns to the hub; the activity-level BackHandler only sees
    // it from the landing itself.
    BackHandler(enabled = section != FilteringSection.ROOT) {
        section = FilteringSection.ROOT
    }

    AnimatedContent(
        targetState = section,
        transitionSpec = {
            val direction =
                if (targetState.ordinal > initialState.ordinal) 1 else -1
            (fadeIn(tween(200)) +
                slideInHorizontally(tween(260)) { direction * it / 8 })
                .togetherWith(
                    fadeOut(tween(150)) +
                        slideOutHorizontally(tween(260)) { -direction * it / 8 }
                )
        },
        label = "filters-section",
    ) { current ->
        when (current) {
            FilteringSection.ROOT -> FilteringHubLanding(
                viewModel = viewModel,
                onOpen = { section = it },
                modifier = modifier,
            )
            FilteringSection.FILTERS -> FiltersScreen(
                viewModel = viewModel,
                onBack = { section = FilteringSection.ROOT },
                modifier = modifier,
            )
            FilteringSection.EXTENSIONS -> ExtensionsScreen(
                viewModel = viewModel,
                onBack = { section = FilteringSection.ROOT },
                modifier = modifier,
            )
            FilteringSection.NETWORK -> NetworkScreen(
                viewModel = viewModel,
                onBack = { section = FilteringSection.ROOT },
                onManageScripts = { section = FilteringSection.EXTENSIONS },
                modifier = modifier,
            )
        }
    }
}

@Composable
private fun FilteringHubLanding(
    viewModel: AdGuardViewModel,
    onOpen: (FilteringSection) -> Unit,
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsState()
    val settings = state.settings

    val enabledFilters = state.filterLists.count { it.isEnabled && !it.isCustom }
    val enabledRules = state.filterLists
        .filter { it.isEnabled && !it.isCustom }
        .sumOf { it.ruleCount }
    val scriptsOn = state.userscripts.count { it.isEnabled }
    val dnsName = state.dnsProviders
        .firstOrNull { it.id == settings.selectedDnsProviderId }
        ?.name
        ?: "Chưa chọn DNS"

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(AdGuardDarkBg),
    ) {
        Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
            Text(
                text = "Bộ lọc",
                fontSize = 19.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextPrimary,
            )
            Text(
                text = "Danh sách lọc, tiện ích trang và đường mạng",
                fontSize = 12.sp,
                color = AdGuardTextMuted,
            )
        }

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp),
        ) {
            Spacer(modifier = Modifier.height(8.dp))

            HubCard(
                icon = Icons.Default.Layers,
                tint = AdGuardGreenLight,
                title = "Bộ lọc",
                subtitle = "$enabledFilters bộ lọc đang bật • ${"%,d".format(enabledRules)} quy tắc",
                tag = "filtering_hub_filters",
                onClick = { onOpen(FilteringSection.FILTERS) },
            )

            Spacer(modifier = Modifier.height(10.dp))

            HubCard(
                icon = Icons.Default.Extension,
                tint = AdGuardPurpleAI,
                title = "Tiện ích",
                subtitle = when {
                    state.userscripts.isEmpty() -> "Chưa có userscript nào"
                    !state.scriptsMasterEnabled -> "Đang tắt tổng — không script nào chạy"
                    else -> "Bật $scriptsOn/${state.userscripts.size} script"
                },
                tag = "filtering_hub_extensions",
                onClick = { onOpen(FilteringSection.EXTENSIONS) },
            )

            Spacer(modifier = Modifier.height(10.dp))

            HubCard(
                icon = Icons.Default.Dns,
                tint = AdGuardBlueDns,
                title = "Mạng",
                subtitle = "$dnsName • HTTPS ${if (settings.isHttpsFilteringEnabled) "bật" else "tắt"}",
                tag = "filtering_hub_network",
                onClick = { onOpen(FilteringSection.NETWORK) },
            )

            Spacer(modifier = Modifier.height(72.dp))
        }
    }
}

@Composable
private fun HubCard(
    icon: ImageVector,
    tint: Color,
    title: String,
    subtitle: String,
    tag: String,
    onClick: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .testTag(tag),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        border = BorderStroke(1.dp, AdGuardDarkOutline),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(38.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(tint.copy(alpha = 0.12f)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(20.dp))
            }
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = AdGuardTextPrimary,
                )
                Text(
                    text = subtitle,
                    fontSize = 11.sp,
                    color = AdGuardTextSecondary,
                )
            }
            Icon(
                imageVector = Icons.Default.ChevronRight,
                contentDescription = null,
                tint = AdGuardTextMuted,
                modifier = Modifier.size(20.dp),
            )
        }
    }
}

/** Header shared by the hub destinations; the root uses its own title block. */
@Composable
internal fun HubDestinationHeader(
    title: String,
    subtitle: String,
    onBack: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconButton(onClick = onBack) {
            Icon(
                imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                contentDescription = "Quay lại",
                tint = AdGuardTextPrimary,
            )
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                fontSize = 19.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextPrimary,
            )
            Text(
                text = subtitle,
                fontSize = 12.sp,
                color = AdGuardTextMuted,
            )
        }
    }
}
