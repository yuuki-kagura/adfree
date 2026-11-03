package git.shin.adfree.ui.screens

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
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
import androidx.compose.material.icons.automirrored.filled.ListAlt
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.PieChart
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.R
import git.shin.adfree.data.serviceSubtitle
import git.shin.adfree.data.servicesKnownByCompany
import git.shin.adfree.model.AppFirewallRule
import git.shin.adfree.model.AppUsageRange
import git.shin.adfree.model.AppUsageTransport
import git.shin.adfree.model.ServiceUsage
import git.shin.adfree.ui.AdGuardIntent
import git.shin.adfree.ui.AdGuardTab
import git.shin.adfree.ui.AdGuardViewModel
import git.shin.adfree.ui.rememberAppIcon
import git.shin.adfree.ui.theme.AdGuardBlueDns
import git.shin.adfree.ui.theme.AdGuardDarkBg
import git.shin.adfree.ui.theme.AdGuardDarkSurface
import git.shin.adfree.ui.theme.AdGuardDarkSurfaceVariant
import git.shin.adfree.ui.theme.AdGuardGreenLight
import git.shin.adfree.ui.theme.AdGuardGreenPrimary
import git.shin.adfree.ui.theme.AdGuardOnAccent
import git.shin.adfree.ui.theme.AdGuardOrangeWarning
import git.shin.adfree.ui.theme.AdGuardPurpleAI
import git.shin.adfree.ui.theme.AdGuardTextMuted
import git.shin.adfree.ui.theme.AdGuardTextPrimary
import git.shin.adfree.ui.theme.AdGuardTextSecondary
import java.util.Locale

/** AdGuard's three ways to order the per-app statistics. */
private enum class StatsAppSort { ADS, TRACKERS, REQUESTS }

/** Tracker segments use an amber tone next to the ad orange. */
private val TrackerAmber = Color(0xFFFFB300)

/**
 * The Statistics tab: windowed request/data totals, a shortcut into the full
 * log, and the busiest apps. The same range and network selection drives the
 * Apps tab, so switching between the two never resets the window.
 */
@Composable
fun StatisticsScreen(
    viewModel: AdGuardViewModel,
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsState()
    var range by rememberSaveable { mutableStateOf(viewModel.currentAppUsageRange()) }
    var transport by rememberSaveable { mutableStateOf(viewModel.currentAppUsageTransport()) }
    var sort by rememberSaveable { mutableStateOf(StatsAppSort.ADS) }

    val totals = state.windowTotals
    val topApps = remember(state.allAppFirewallRules, sort) {
        val rows = when (sort) {
            StatsAppSort.ADS -> state.allAppFirewallRules.sortedByDescending { it.blockedAdsToday }
            StatsAppSort.TRACKERS ->
                state.allAppFirewallRules.sortedByDescending { it.blockedTrackersToday }
            StatsAppSort.REQUESTS ->
                state.allAppFirewallRules.sortedByDescending { it.requestsToday }
        }
        rows.filter { it.requestsToday > 0 }.take(6)
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(AdGuardDarkBg)
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag("statistics_screen"),
    ) {
        // Pinned title: the scrollable body below owns its own verticalScroll.
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                imageVector = Icons.Default.PieChart,
                contentDescription = null,
                tint = AdGuardGreenPrimary,
                modifier = Modifier.size(24.dp),
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = stringResource(R.string.nav_statistics),
                fontSize = 19.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextPrimary,
            )
        }

        Spacer(modifier = Modifier.height(12.dp))

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .verticalScroll(rememberScrollState()),
        ) {
            FilterChipsRow {
                listOf(
                    AppUsageRange.TODAY to R.string.apps_range_today,
                    AppUsageRange.WEEK to R.string.apps_range_week,
                    AppUsageRange.MONTH to R.string.apps_range_month,
                    AppUsageRange.ALL to R.string.apps_range_all,
                ).forEach { (option, labelRes) ->
                    FilterChip(
                        selected = range == option,
                        onClick = {
                            range = option
                            viewModel.onIntent(AdGuardIntent.SetAppUsageRange(option))
                        },
                        label = { Text(stringResource(labelRes), fontSize = 11.sp) },
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = AdGuardBlueDns,
                            selectedLabelColor = AdGuardOnAccent,
                            containerColor = AdGuardDarkSurface,
                            labelColor = AdGuardTextSecondary,
                        ),
                        modifier = Modifier.testTag("stats_range_${option.name}"),
                    )
                }
            }

            Spacer(modifier = Modifier.height(6.dp))

            FilterChipsRow {
                listOf(
                    AppUsageTransport.ALL to R.string.apps_transport_all,
                    AppUsageTransport.CELLULAR to R.string.apps_transport_cellular,
                    AppUsageTransport.WIFI to R.string.apps_transport_wifi,
                ).forEach { (option, labelRes) ->
                    FilterChip(
                        selected = transport == option,
                        onClick = {
                            transport = option
                            viewModel.onIntent(AdGuardIntent.SetAppUsageTransport(option))
                        },
                        label = { Text(stringResource(labelRes), fontSize = 11.sp) },
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = AdGuardGreenPrimary,
                            selectedLabelColor = AdGuardOnAccent,
                            containerColor = AdGuardDarkSurface,
                            labelColor = AdGuardTextSecondary,
                        ),
                        modifier = Modifier.testTag("stats_transport_${option.name}"),
                    )
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            SectionCard {
                Text(
                    text = stringResource(R.string.stats_requests_title),
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextPrimary,
                )
                Spacer(modifier = Modifier.height(10.dp))
                Row(modifier = Modifier.fillMaxWidth()) {
                    StatFigure(
                        value = totals.ads,
                        label = stringResource(R.string.stats_ads),
                        color = AdGuardOrangeWarning,
                        modifier = Modifier.weight(1f),
                    )
                    StatFigure(
                        value = totals.trackers,
                        label = stringResource(R.string.stats_trackers),
                        color = TrackerAmber,
                        modifier = Modifier.weight(1f),
                    )
                    StatFigure(
                        value = totals.requests,
                        label = stringResource(R.string.stats_requests),
                        color = AdGuardTextPrimary,
                        modifier = Modifier.weight(1f),
                    )
                }
                Spacer(modifier = Modifier.height(10.dp))
                RatioBar(
                    segments = listOf(
                        totals.ads to AdGuardOrangeWarning,
                        totals.trackers to TrackerAmber,
                        (totals.requests - totals.ads - totals.trackers).coerceAtLeast(0L) to
                            AdGuardTextMuted,
                    ),
                    total = totals.requests,
                )
            }

            Spacer(modifier = Modifier.height(10.dp))

            NavigationRow(
                title = stringResource(R.string.stats_recent_activity),
                icon = Icons.AutoMirrored.Filled.ListAlt,
                testTag = "stats_recent_activity",
                onClick = { viewModel.onIntent(AdGuardIntent.SelectTab(AdGuardTab.ACTIVITY)) },
            )

            Spacer(modifier = Modifier.height(14.dp))

            SectionCard {
                Text(
                    text = stringResource(R.string.stats_data_title),
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextPrimary,
                )
                Spacer(modifier = Modifier.height(10.dp))
                Row(modifier = Modifier.fillMaxWidth()) {
                    DataFigure(
                        bytes = totals.bytesSaved,
                        label = stringResource(R.string.stats_data_saved),
                        color = AdGuardGreenPrimary,
                        modifier = Modifier.weight(1f),
                    )
                    DataFigure(
                        bytes = totals.bytesSent,
                        label = stringResource(R.string.stats_data_uploaded),
                        color = AdGuardPurpleAI,
                        modifier = Modifier.weight(1f),
                    )
                    DataFigure(
                        bytes = totals.bytesReceived,
                        label = stringResource(R.string.stats_data_downloaded),
                        color = AdGuardBlueDns,
                        modifier = Modifier.weight(1f),
                    )
                }
                Spacer(modifier = Modifier.height(10.dp))
                RatioBar(
                    segments = listOf(
                        totals.bytesSaved to AdGuardGreenPrimary,
                        totals.bytesSent to AdGuardPurpleAI,
                        totals.bytesReceived to AdGuardBlueDns,
                    ),
                    total = totals.bytesSaved + totals.bytesSent + totals.bytesReceived,
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            Text(
                text = stringResource(R.string.stats_apps_title),
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextPrimary,
            )
            Spacer(modifier = Modifier.height(6.dp))

            FilterChipsRow {
                listOf(
                    StatsAppSort.ADS to R.string.apps_sort_ads,
                    StatsAppSort.TRACKERS to R.string.apps_sort_trackers,
                    StatsAppSort.REQUESTS to R.string.apps_sort_requests,
                ).forEach { (option, labelRes) ->
                    FilterChip(
                        selected = sort == option,
                        onClick = { sort = option },
                        label = { Text(stringResource(labelRes), fontSize = 11.sp) },
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = AdGuardPurpleAI,
                            selectedLabelColor = AdGuardOnAccent,
                            containerColor = AdGuardDarkSurface,
                            labelColor = AdGuardTextSecondary,
                        ),
                        modifier = Modifier.testTag("stats_sort_${option.name}"),
                    )
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            if (topApps.isEmpty()) {
                Text(
                    text = stringResource(R.string.stats_no_activity),
                    fontSize = 12.sp,
                    color = AdGuardTextMuted,
                    modifier = Modifier.padding(vertical = 10.dp),
                )
            } else {
                topApps.forEach { app ->
                    AppStatRow(
                        app = app,
                        onClick = { viewModel.onIntent(AdGuardIntent.OpenAppManagement(app)) },
                    )
                }
            }

            Spacer(modifier = Modifier.height(4.dp))

            NavigationRow(
                title = stringResource(R.string.stats_view_all_apps),
                icon = Icons.Default.Apps,
                testTag = "stats_view_all_apps",
                onClick = { viewModel.onIntent(AdGuardIntent.SelectTab(AdGuardTab.APPS)) },
            )

            // The services breakdown ships off: it is a second aggregation over
            // the window, so the section appears only for a user who turned it
            // on and the log has something to group.
            if (state.settings.showServicesBreakdown && state.serviceUsage.isNotEmpty()) {
                Spacer(modifier = Modifier.height(16.dp))
                val known = servicesKnownByCompany(state.serviceUsage)
                Text(
                    text = stringResource(
                        if (known) R.string.stats_services_title else R.string.stats_domains_title,
                    ),
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextPrimary,
                )
                Spacer(modifier = Modifier.height(6.dp))
                // Ten names on screen and the rest behind a tap, as AdGuard's
                // breakdown does; here the tab is already a scroll, so ten rows
                // is the same figure without a second route.
                state.serviceUsage.take(10).forEach { row ->
                    ServiceStatRow(row = row)
                }
                Text(
                    text = stringResource(
                        if (known) R.string.stats_services_note else R.string.stats_domains_note,
                    ),
                    fontSize = 11.sp,
                    color = AdGuardTextMuted,
                    modifier = Modifier.padding(top = 6.dp),
                )
            }

            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}

@Composable
private fun FilterChipsRow(content: @Composable () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        content()
    }
}

@Composable
private fun SectionCard(content: @Composable () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
    ) {
        Column(modifier = Modifier.padding(14.dp)) { content() }
    }
}

@Composable
private fun StatFigure(
    value: Long,
    label: String,
    color: Color,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier, horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            text = compactCount(value),
            fontSize = 22.sp,
            fontWeight = FontWeight.Bold,
            color = color,
            maxLines = 1,
        )
        Text(
            text = label,
            fontSize = 11.sp,
            color = AdGuardTextMuted,
            maxLines = 1,
        )
    }
}

@Composable
private fun DataFigure(
    bytes: Long,
    label: String,
    color: Color,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier, horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            text = formatBytes(bytes),
            fontSize = 17.sp,
            fontWeight = FontWeight.Bold,
            color = color,
            maxLines = 1,
        )
        Text(
            text = label,
            fontSize = 11.sp,
            color = AdGuardTextMuted,
            maxLines = 1,
        )
    }
}

/** Segments keep their proportions; the leftover width is the bar's track. */
@Composable
private fun RatioBar(segments: List<Pair<Long, Color>>, total: Long) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(6.dp)
            .clip(RoundedCornerShape(3.dp))
            .background(AdGuardDarkSurfaceVariant),
    ) {
        if (total > 0L) {
            Row(modifier = Modifier.fillMaxSize()) {
                segments.forEach { (value, color) ->
                    if (value > 0L) {
                        Box(
                            modifier = Modifier
                                .weight(value.toFloat())
                                .fillMaxHeight()
                                .background(color),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun NavigationRow(
    title: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    testTag: String,
    onClick: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .testTag(testTag),
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
                imageVector = icon,
                contentDescription = null,
                tint = AdGuardGreenLight,
                modifier = Modifier.size(18.dp),
            )
            Spacer(modifier = Modifier.width(10.dp))
            Text(
                text = title,
                fontSize = 13.sp,
                color = AdGuardTextPrimary,
                modifier = Modifier.weight(1f),
            )
            Icon(
                imageVector = Icons.Default.ChevronRight,
                contentDescription = null,
                tint = AdGuardTextMuted,
                modifier = Modifier.size(18.dp),
            )
        }
    }
}

@Composable
private fun AppStatRow(app: AppFirewallRule, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .testTag("stats_app_${app.packageName}")
            .padding(vertical = 9.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            modifier = Modifier
                .size(32.dp)
                .clip(RoundedCornerShape(8.dp))
                .background(AdGuardDarkSurfaceVariant),
            contentAlignment = Alignment.Center,
        ) {
            val icon = rememberAppIcon(app.packageName)
            if (icon != null) {
                Image(bitmap = icon, contentDescription = null, modifier = Modifier.size(24.dp))
            } else {
                Icon(
                    imageVector = Icons.Default.Apps,
                    contentDescription = null,
                    tint = AdGuardGreenPrimary,
                    modifier = Modifier.size(18.dp),
                )
            }
        }
        Spacer(modifier = Modifier.width(10.dp))
        Text(
            text = app.appName,
            fontSize = 13.sp,
            color = AdGuardTextPrimary,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f),
        )
        Text(
            text = stringResource(
                R.string.stats_app_counts,
                compactCount(app.blockedAdsToday.toLong()),
                compactCount(app.blockedTrackersToday.toLong()),
                compactCount(app.requestsToday.toLong()),
            ),
            fontSize = 11.sp,
            fontFamily = FontFamily.Monospace,
            color = AdGuardTextMuted,
            maxLines = 1,
        )
    }
}

/**
 * One domain in the services breakdown. AdGuard's rows read "company" over
 * "domain"; the name is kept under it whenever the table supplied a company, so
 * a row the table does not know shows only the name and claims nothing else.
 * The category the dataset carries goes on the same line when it has one.
 */
@Composable
private fun ServiceStatRow(row: ServiceUsage) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("stats_service_${row.domain}")
            .padding(vertical = 7.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            modifier = Modifier
                .size(28.dp)
                .clip(RoundedCornerShape(8.dp))
                .background(AdGuardDarkSurfaceVariant),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = Icons.AutoMirrored.Filled.ListAlt,
                contentDescription = null,
                tint = AdGuardGreenPrimary,
                modifier = Modifier.size(16.dp),
            )
        }
        Spacer(modifier = Modifier.width(10.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = row.label,
                fontSize = 13.sp,
                color = AdGuardTextPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (row.company.isNotBlank()) {
                Text(
                    text = serviceSubtitle(row),
                    fontSize = 11.sp,
                    color = AdGuardTextMuted,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        Text(
            text = stringResource(
                R.string.stats_service_counts,
                compactCount(row.blocked.toLong()),
                compactCount(row.requests.toLong()),
            ),
            fontSize = 11.sp,
            fontFamily = FontFamily.Monospace,
            color = AdGuardTextMuted,
            maxLines = 1,
        )
    }
}

/** AdGuard's compact header numbers: 999, 5,6K, 13,3K, 1,2M. */
private fun compactCount(value: Long): String {
    if (value < 1_000L) return value.toString()
    val (unit, suffix) = if (value >= 1_000_000L) 1_000_000.0 to "M" else 1_000.0 to "K"
    val scaled = value / unit
    val text = if (scaled >= 100.0) {
        scaled.toInt().toString()
    } else {
        String.format(Locale.getDefault(), "%.1f", scaled)
            .trimEnd('0')
            .trimEnd('.', ',')
    }
    return text + suffix
}

private fun formatBytes(bytes: Long): String {
    if (bytes <= 0L) return "0 MB"
    val kb = 1024.0
    val mb = kb * 1024.0
    val gb = mb * 1024.0
    return when {
        bytes >= gb -> String.format(Locale.getDefault(), "%.1f GB", bytes / gb)
        bytes >= mb -> String.format(Locale.getDefault(), "%.1f MB", bytes / mb)
        bytes >= kb -> String.format(Locale.getDefault(), "%.0f KB", bytes / kb)
        else -> "$bytes B"
    }
}
