package git.shin.adfree

import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.outlined.Language
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.data.AdGuardRepository
import git.shin.adfree.model.FilterStatus
import git.shin.adfree.model.NetworkRequestLog
import git.shin.adfree.model.ThemeMode
import git.shin.adfree.ui.rememberAppIcon
import git.shin.adfree.ui.theme.MyApplicationTheme
import git.shin.adfree.vpn.VpnController
import kotlinx.coroutines.delay
import java.util.concurrent.TimeUnit

/**
 * The notification's "Assistant" action: a bottom sheet over whatever the
 * user was doing, listing the apps and websites seen recently so a filtering
 * decision is one tap away. Shortcuts hand the full screens to MainActivity.
 */
class AssistantActivity : AppCompatActivity() {

    private val container get() = AdGuardApplication.instance.container

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val settings by container.repository.settings.collectAsState()
            val darkTheme = when (settings.themeMode) {
                ThemeMode.SYSTEM -> isSystemInDarkTheme()
                ThemeMode.DARK -> true
                ThemeMode.LIGHT -> false
            }
            MyApplicationTheme(darkTheme) {
                LaunchedEffect(Unit) {
                    // The overlay is short-lived: pull the log on demand
                    // instead of driving the Activity's visibility poller.
                    while (true) {
                        container.repository.refreshLogsNow()
                        delay(2_000)
                    }
                }
                AssistantSheet(
                    repository = container.repository,
                    vpnController = container.vpnController,
                    onOpenLog = ::openLog,
                    onOpenApps = ::openApps,
                    onOpenAppDetails = ::openAppDetails,
                    onDismiss = ::finish,
                )
            }
        }
    }

    private fun openLog(appPackage: String? = null, domain: String? = null) {
        startActivity(
            Intent(this, MainActivity::class.java).apply {
                action = MainActivity.ACTION_OPEN_ACTIVITY
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or
                    Intent.FLAG_ACTIVITY_CLEAR_TOP or
                    Intent.FLAG_ACTIVITY_SINGLE_TOP
                appPackage?.let { putExtra(MainActivity.EXTRA_LOG_APP, it) }
                domain?.let { putExtra(MainActivity.EXTRA_LOG_DOMAIN, it) }
            },
        )
        finish()
    }

    private fun openApps() {
        startActivity(
            Intent(this, MainActivity::class.java).apply {
                action = MainActivity.ACTION_OPEN_APPS
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or
                    Intent.FLAG_ACTIVITY_CLEAR_TOP or
                    Intent.FLAG_ACTIVITY_SINGLE_TOP
            },
        )
        finish()
    }

    private fun openAppDetails(packageName: String, label: String) {
        startActivity(
            Intent(this, MainActivity::class.java).apply {
                action = MainActivity.ACTION_OPEN_APP_DETAILS
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or
                    Intent.FLAG_ACTIVITY_CLEAR_TOP or
                    Intent.FLAG_ACTIVITY_SINGLE_TOP
                putExtra(MainActivity.EXTRA_APP_PACKAGE, packageName)
                putExtra(MainActivity.EXTRA_APP_NAME, label)
            },
        )
        finish()
    }
}

private data class RecentApp(
    val packageName: String,
    val label: String,
    val lastSeenMs: Long,
    val blocked: Int,
    val total: Int,
    val savedBytes: Long,
)

private data class RecentDomain(
    val domain: String,
    val lastSeenMs: Long,
    val blocked: Int,
)

private const val RECENT_LIMIT = 8

@Composable
private fun AssistantSheet(
    repository: AdGuardRepository,
    vpnController: VpnController,
    onOpenLog: (String?, String?) -> Unit,
    onOpenApps: () -> Unit,
    onOpenAppDetails: (String, String) -> Unit,
    onDismiss: () -> Unit,
) {
    val logs by repository.logs.collectAsState()
    val apps by repository.appFirewallRules.collectAsState()
    val vpnActive by vpnController.isVpnActive.collectAsState()
    var paused by remember { mutableStateOf(vpnController.isPaused()) }
    var tab by rememberSaveable { mutableStateOf(0) }
    var selectedApp by remember { mutableStateOf<RecentApp?>(null) }

    val recentApps = remember(logs, apps) {
        buildRecentApps(logs, apps.associate { it.packageName to it.appName })
    }
    val recentDomains = remember(logs) { buildRecentDomains(logs) }

    Box(
        Modifier
            .fillMaxSize()
            .background(Color.Black.copy(alpha = 0.45f))
            .clickable(
                interactionSource = remember { MutableInteractionSource() },
                indication = null,
                onClick = onDismiss,
            ),
    ) {
        Surface(
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .fillMaxWidth()
                .navigationBarsPadding()
                // Taps on the sheet must not fall through to the scrim.
                .clickable(
                    interactionSource = remember { MutableInteractionSource() },
                    indication = null,
                    onClick = {},
                ),
            shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp),
            color = MaterialTheme.colorScheme.surface,
            tonalElevation = 3.dp,
        ) {
            Column(
                Modifier
                    .heightIn(max = 620.dp)
                    .padding(horizontal = 20.dp, vertical = 16.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(
                            stringResource(R.string.assistant_title),
                            fontSize = 20.sp,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(
                            stringResource(R.string.assistant_subtitle),
                            fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    IconButton(onClick = onDismiss) {
                        Icon(
                            Icons.Default.Close,
                            contentDescription = stringResource(R.string.assistant_close),
                        )
                    }
                }

                Row(
                    Modifier
                        .fillMaxWidth()
                        .padding(top = 12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        stringResource(
                            when {
                                !vpnActive -> R.string.assistant_vpn_off
                                paused -> R.string.vpn_notification_paused_title
                                else -> R.string.vpn_notification_title
                            },
                        ),
                        fontSize = 13.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    if (vpnActive) {
                        TextButton(
                            onClick = {
                                val next = !paused
                                vpnController.setPaused(next)
                                paused = next
                            },
                        ) {
                            Text(
                                stringResource(
                                    if (paused) R.string.assistant_resume
                                    else R.string.assistant_pause,
                                ),
                            )
                        }
                    }
                }

                TabRow(
                    selectedTabIndex = tab,
                    containerColor = Color.Transparent,
                    modifier = Modifier.padding(top = 8.dp),
                ) {
                    Tab(
                        selected = tab == 0,
                        onClick = {
                            tab = 0
                            selectedApp = null
                        },
                        text = { Text(stringResource(R.string.assistant_tab_apps)) },
                    )
                    Tab(
                        selected = tab == 1,
                        onClick = {
                            tab = 1
                            selectedApp = null
                        },
                        text = { Text(stringResource(R.string.assistant_tab_websites)) },
                    )
                }

                val selected = selectedApp
                if (tab == 0 && selected != null) {
                    AssistantAppPanel(
                        entry = selected,
                        onOpenActivity = { onOpenLog(selected.packageName, null) },
                        onManage = { onOpenAppDetails(selected.packageName, selected.label) },
                        onBack = { selectedApp = null },
                        modifier = Modifier.weight(1f, fill = false),
                    )
                } else {
                    LazyColumn(Modifier.weight(1f, fill = false).fillMaxWidth()) {
                        if (tab == 0) {
                            if (recentApps.isEmpty()) {
                                item { EmptyState() }
                            } else {
                                items(recentApps, key = { it.packageName }) { entry ->
                                    RecentAppRow(entry) { selectedApp = entry }
                                }
                            }
                        } else {
                            if (recentDomains.isEmpty()) {
                                item { EmptyState() }
                            } else {
                                items(recentDomains, key = { it.domain }) { entry ->
                                    RecentDomainRow(entry) { onOpenLog(null, entry.domain) }
                                }
                            }
                        }
                    }
                }

                HorizontalDivider(Modifier.padding(top = 4.dp))
                Row(Modifier.fillMaxWidth()) {
                    TextButton(
                        onClick = { onOpenLog(null, null) },
                        modifier = Modifier.weight(1f),
                    ) {
                        Text(stringResource(R.string.assistant_shortcut_recent))
                    }
                    TextButton(
                        onClick = onOpenApps,
                        modifier = Modifier.weight(1f),
                    ) {
                        Text(stringResource(R.string.assistant_shortcut_apps))
                    }
                }
            }
        }
    }
}

@Composable
private fun EmptyState() {
    Box(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 40.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            stringResource(R.string.assistant_empty),
            fontSize = 13.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun RecentAppRow(entry: RecentApp, onClick: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        AssistantAppIcon(entry.packageName)
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(entry.label, fontSize = 14.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(
                stringResource(
                    R.string.assistant_row_subtitle,
                    entry.blocked,
                    relativeTime(entry.lastSeenMs),
                ),
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun AssistantAppIcon(packageName: String, size: Int = 36) {
    val icon = rememberAppIcon(packageName)
    if (icon != null) {
        Image(
            bitmap = icon,
            contentDescription = null,
            modifier = Modifier.size(size.dp),
        )
    } else {
        Box(
            Modifier
                .size(size.dp)
                .background(MaterialTheme.colorScheme.surfaceVariant, CircleShape),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                Icons.Filled.Apps,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size((size * 0.55f).dp),
            )
        }
    }
}

/** The app's recent numbers and the shortcuts that leave the assistant. */
@Composable
private fun AssistantAppPanel(
    entry: RecentApp,
    onOpenActivity: () -> Unit,
    onManage: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        // The sheet caps its height, so the panel scrolls instead of cutting the
        // shortcuts off the bottom; the divider and the shortcut row below it sit
        // outside this region and stay pinned.
        modifier
            .verticalScroll(rememberScrollState())
            .fillMaxWidth()
            .padding(top = 6.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            AssistantAppIcon(entry.packageName)
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    entry.label,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    stringResource(R.string.assistant_app_used, relativeTime(entry.lastSeenMs)),
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        Surface(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 12.dp),
            shape = RoundedCornerShape(12.dp),
            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f),
        ) {
            Column(Modifier.padding(horizontal = 14.dp, vertical = 12.dp)) {
                Row(
                    Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    AssistantStat(
                        label = stringResource(R.string.assistant_stats_requests),
                        value = entry.total.toString(),
                        modifier = Modifier.weight(1f),
                    )
                    AssistantStat(
                        label = stringResource(R.string.assistant_stats_blocked),
                        value = entry.blocked.toString(),
                        modifier = Modifier.weight(1f),
                    )
                    AssistantStat(
                        label = stringResource(R.string.assistant_stats_saved),
                        value = stringResource(R.string.log_saved_value, entry.savedBytes / 1024),
                        modifier = Modifier.weight(1f),
                    )
                }
                Text(
                    stringResource(R.string.assistant_stats_window),
                    fontSize = 10.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 6.dp),
                )
            }
        }

        HorizontalDivider(Modifier.padding(top = 10.dp))
        AssistantActionRow(
            icon = Icons.Default.History,
            label = stringResource(R.string.assistant_app_recent_activity),
            onClick = onOpenActivity,
        )
        AssistantActionRow(
            icon = Icons.Default.Apps,
            label = stringResource(R.string.assistant_app_manage),
            onClick = onManage,
        )
        AssistantActionRow(
            icon = Icons.AutoMirrored.Filled.ArrowBack,
            label = stringResource(R.string.assistant_app_back),
            onClick = onBack,
        )
    }
}

@Composable
private fun AssistantStat(label: String, value: String, modifier: Modifier = Modifier) {
    Column(modifier) {
        Text(value, fontSize = 16.sp, fontWeight = FontWeight.SemiBold, maxLines = 1)
        Text(
            label,
            fontSize = 10.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
private fun AssistantActionRow(icon: ImageVector, label: String, onClick: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(20.dp),
        )
        Spacer(Modifier.width(16.dp))
        Text(label, fontSize = 14.sp)
    }
}

@Composable
private fun RecentDomainRow(entry: RecentDomain, onClick: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier
                .size(36.dp)
                .background(MaterialTheme.colorScheme.surfaceVariant, CircleShape),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                Icons.Outlined.Language,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(20.dp),
            )
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(entry.domain, fontSize = 14.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(
                stringResource(
                    R.string.assistant_row_subtitle,
                    entry.blocked,
                    relativeTime(entry.lastSeenMs),
                ),
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun relativeTime(timestampMs: Long): String {
    val minutes = TimeUnit.MILLISECONDS.toMinutes(
        (System.currentTimeMillis() - timestampMs).coerceAtLeast(0L),
    )
    return when {
        minutes < 1 -> stringResource(R.string.assistant_used_now)
        minutes < 60 -> stringResource(R.string.assistant_used_minutes, minutes.toInt())
        minutes < 24 * 60 -> stringResource(R.string.assistant_used_hours, (minutes / 60).toInt())
        else -> stringResource(R.string.assistant_used_days, (minutes / (24 * 60)).toInt())
    }
}

private fun buildRecentApps(
    logs: List<NetworkRequestLog>,
    names: Map<String, String>,
): List<RecentApp> = logs
    .mapNotNull { log -> log.appPackage?.let { it to log } }
    .groupBy({ it.first }, { it.second })
    .map { (packageName, rows) ->
        RecentApp(
            packageName = packageName,
            label = names[packageName] ?: packageName,
            lastSeenMs = rows.maxOf { it.timestampMs },
            blocked = rows.count { it.status == FilterStatus.BLOCKED },
            total = rows.size,
            savedBytes = rows.sumOf { it.dataSavedBytes },
        )
    }
    .sortedByDescending { it.lastSeenMs }
    .take(RECENT_LIMIT)

private fun buildRecentDomains(logs: List<NetworkRequestLog>): List<RecentDomain> = logs
    .groupBy { it.domain }
    .map { (domain, rows) ->
        RecentDomain(
            domain = domain,
            lastSeenMs = rows.maxOf { it.timestampMs },
            blocked = rows.count { it.status == FilterStatus.BLOCKED },
        )
    }
    .sortedByDescending { it.lastSeenMs }
    .take(RECENT_LIMIT)
