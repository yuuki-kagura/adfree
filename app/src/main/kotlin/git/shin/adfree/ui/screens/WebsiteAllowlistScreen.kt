package git.shin.adfree.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
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
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.R
import git.shin.adfree.model.allowlistHost
import git.shin.adfree.model.allowlistRuleBody
import git.shin.adfree.model.allowlistRuleEnabled
import git.shin.adfree.model.allowlistRules
import git.shin.adfree.model.isAllowlistRule
import git.shin.adfree.model.userWhitelistRule
import git.shin.adfree.model.withAllowlistRuleEnabled
import git.shin.adfree.ui.AdGuardIntent
import git.shin.adfree.ui.AdGuardViewModel
import git.shin.adfree.ui.theme.AdGuardDarkBg
import git.shin.adfree.ui.theme.AdGuardDarkOutline
import git.shin.adfree.ui.theme.AdGuardDarkSurface
import git.shin.adfree.ui.theme.AdGuardDarkSurfaceVariant
import git.shin.adfree.ui.theme.AdGuardGreenLight
import git.shin.adfree.ui.theme.AdGuardGreenPrimary
import git.shin.adfree.ui.theme.AdGuardOnAccent
import git.shin.adfree.ui.theme.AdGuardRedBlocked
import git.shin.adfree.ui.theme.AdGuardTextMuted
import git.shin.adfree.ui.theme.AdGuardTextPrimary

/**
 * The websites the user has excepted from filtering, as a list of domains
 * rather than a text file.
 *
 * This is a front door over the same `@@` rules the raw editor writes, so both
 * views stay true. Each row has its own switch: switching off rewrites the rule
 * as `!@@…`, the spelling AdGuard uses to park a rule. The core reads that line
 * as an inert comment, so the exception waits in the list instead of being
 * deleted and retyped.
 */
@Composable
fun WebsiteAllowlistScreen(
    viewModel: AdGuardViewModel,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsState()
    var query by rememberSaveable { mutableStateOf("") }
    var draft by rememberSaveable { mutableStateOf("") }
    var problem by rememberSaveable { mutableStateOf(0) }

    val rules = state.filterLists.firstOrNull { it.isCustom }?.customRules.orEmpty()
    val exceptions = rules.filter { isAllowlistRule(it) }
    val switchedOn = exceptions.count { allowlistRuleEnabled(it) }
    val parked = exceptions.size - switchedOn
    val shown = allowlistRules(rules, query)

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(AdGuardDarkBg),
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp, vertical = 12.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                IconButton(onClick = onBack) {
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                        contentDescription = stringResource(R.string.hub_back),
                        tint = AdGuardTextPrimary,
                    )
                }
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.allowlist_title),
                        fontSize = 19.sp,
                        fontWeight = FontWeight.Bold,
                        color = AdGuardTextPrimary,
                    )
                    // Only the switched-on rules bypass anything, so that is the
                    // number the subtitle carries; parked ones are counted apart.
                    val parkedNote = if (parked > 0) {
                        " · " + stringResource(R.string.allowlist_parked_count, parked)
                    } else {
                        ""
                    }
                    Text(
                        text = stringResource(R.string.allowlist_subtitle, switchedOn) + parkedNote,
                        fontSize = 12.sp,
                        color = AdGuardTextMuted,
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            OutlinedTextField(
                value = draft,
                onValueChange = {
                    draft = it
                    problem = 0
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("allowlist_add_field"),
                singleLine = true,
                placeholder = {
                    Text(
                        stringResource(R.string.rules_allow_hint),
                        color = AdGuardTextMuted,
                        fontSize = 13.sp,
                    )
                },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                isError = problem != 0,
                supportingText = if (problem == 0) null else {
                    {
                        Text(
                            stringResource(problem),
                            fontSize = 11.sp,
                            color = AdGuardRedBlocked,
                        )
                    }
                },
                shape = RoundedCornerShape(10.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedContainerColor = AdGuardDarkSurface,
                    unfocusedContainerColor = AdGuardDarkSurface,
                    focusedBorderColor = AdGuardGreenPrimary,
                    unfocusedBorderColor = AdGuardDarkOutline,
                    focusedTextColor = AdGuardTextPrimary,
                    unfocusedTextColor = AdGuardTextPrimary,
                ),
            )

            Spacer(modifier = Modifier.height(8.dp))

            Button(
                onClick = {
                    val rule = userWhitelistRule(draft)
                    // Adding a host the switch parked turns it back on instead
                    // of storing the same exception twice.
                    val parkedRule = exceptions.firstOrNull {
                        !allowlistRuleEnabled(it) && allowlistRuleBody(it) == rule
                    }
                    when {
                        rule == null -> problem = R.string.rules_invalid_domain
                        parkedRule != null -> {
                            viewModel.onIntent(AdGuardIntent.ReplaceCustomRule(parkedRule, rule))
                            draft = ""
                            problem = 0
                        }

                        rule in exceptions -> problem = R.string.rules_exception_exists
                        else -> {
                            viewModel.onIntent(AdGuardIntent.AddCustomRule(rule))
                            // The new row appears from the store, so the field is
                            // cleared rather than left showing what was just added.
                            draft = ""
                            problem = 0
                        }
                    }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("allowlist_add_button"),
                colors = ButtonDefaults.buttonColors(containerColor = AdGuardGreenPrimary),
                shape = RoundedCornerShape(10.dp),
            ) {
                Icon(
                    Icons.Default.Add,
                    contentDescription = null,
                    tint = AdGuardOnAccent,
                    modifier = Modifier.size(18.dp),
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    stringResource(R.string.allowlist_add_action),
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("allowlist_search_field"),
                singleLine = true,
                placeholder = {
                    Text(
                        stringResource(R.string.allowlist_search_hint),
                        color = AdGuardTextMuted,
                        fontSize = 13.sp,
                    )
                },
                leadingIcon = {
                    Icon(
                        Icons.Default.Search,
                        contentDescription = null,
                        tint = AdGuardTextMuted,
                        modifier = Modifier.size(18.dp),
                    )
                },
                trailingIcon = if (query.isBlank()) {
                    null
                } else {
                    {
                        IconButton(
                            onClick = { query = "" },
                            modifier = Modifier.size(32.dp),
                        ) {
                            Icon(
                                Icons.Default.Close,
                                contentDescription = stringResource(R.string.filters_clear_search),
                                tint = AdGuardTextMuted,
                                modifier = Modifier.size(16.dp),
                            )
                        }
                    }
                },
                shape = RoundedCornerShape(10.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedContainerColor = AdGuardDarkSurface,
                    unfocusedContainerColor = AdGuardDarkSurface,
                    focusedBorderColor = AdGuardGreenPrimary,
                    unfocusedBorderColor = AdGuardDarkOutline,
                    focusedTextColor = AdGuardTextPrimary,
                    unfocusedTextColor = AdGuardTextPrimary,
                ),
            )

            Spacer(modifier = Modifier.height(12.dp))

            if (shown.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = stringResource(
                            if (exceptions.isEmpty()) R.string.rules_allow_empty
                            else R.string.allowlist_no_match,
                        ),
                        fontSize = 12.sp,
                        color = AdGuardTextMuted,
                    )
                }
            } else {
                LazyColumn(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    items(shown, key = { it }) { rule ->
                        AllowlistRow(
                            rule = rule,
                            enabled = allowlistRuleEnabled(rule),
                            onToggle = { wanted ->
                                viewModel.onIntent(
                                    AdGuardIntent.ReplaceCustomRule(
                                        rule,
                                        withAllowlistRuleEnabled(rule, wanted),
                                    ),
                                )
                            },
                            onDelete = { viewModel.onIntent(AdGuardIntent.RemoveCustomRule(rule)) },
                        )
                    }
                }
            }

            Text(
                text = stringResource(R.string.allowlist_https_note),
                fontSize = 11.sp,
                color = AdGuardTextMuted,
                modifier = Modifier.padding(top = 10.dp),
            )
        }
    }
}

@Composable
private fun AllowlistRow(
    rule: String,
    enabled: Boolean,
    onToggle: (Boolean) -> Unit,
    onDelete: () -> Unit,
) {
    val host = allowlistHost(rule)
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("allowlist_row"),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurfaceVariant),
        border = BorderStroke(1.dp, AdGuardDarkOutline),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 12.dp, end = 4.dp, top = 8.dp, bottom = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .background(
                        if (enabled) AdGuardGreenLight.copy(alpha = 0.15f)
                        else AdGuardTextMuted.copy(alpha = 0.15f),
                    )
                    .padding(horizontal = 6.dp, vertical = 2.dp),
            ) {
                Text(
                    text = stringResource(
                        if (enabled) R.string.rules_badge_allow else R.string.allowlist_off_badge,
                    ),
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    color = if (enabled) AdGuardGreenLight else AdGuardTextMuted,
                )
            }
            Spacer(modifier = Modifier.width(10.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = host.ifEmpty { rule },
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    color = if (enabled) AdGuardTextPrimary else AdGuardTextMuted,
                    textDecoration = if (enabled) null else TextDecoration.LineThrough,
                )
                // The raw rule explains the row whenever it is not the plain
                // `@@||host^` form — including the `!` that parks it.
                if (host.isNotEmpty() && rule != "@@||$host^") {
                    Text(
                        text = rule,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        color = AdGuardTextMuted,
                    )
                }
            }
            Switch(
                checked = enabled,
                onCheckedChange = onToggle,
                modifier = Modifier.testTag("allowlist_toggle_${host.ifEmpty { rule }}"),
                colors = SwitchDefaults.colors(
                    checkedThumbColor = Color.White,
                    checkedTrackColor = AdGuardGreenPrimary,
                    uncheckedThumbColor = AdGuardTextMuted,
                    uncheckedTrackColor = AdGuardDarkSurface,
                ),
            )
            IconButton(
                onClick = onDelete,
                modifier = Modifier.testTag("allowlist_delete_${host.ifEmpty { rule }}"),
            ) {
                Icon(
                    Icons.Default.Delete,
                    contentDescription = stringResource(R.string.allowlist_delete_action),
                    tint = AdGuardRedBlocked,
                    modifier = Modifier.size(18.dp),
                )
            }
        }
    }
}
