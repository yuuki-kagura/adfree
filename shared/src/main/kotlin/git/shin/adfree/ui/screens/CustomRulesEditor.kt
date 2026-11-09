package git.shin.adfree.ui.screens

import git.shin.adfree.l10n.Strings
import git.shin.adfree.l10n.L10n
import git.shin.adfree.platform.currentFileHost
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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.AutoFixHigh
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.TabRowDefaults
import androidx.compose.material3.TabRowDefaults.tabIndicatorOffset
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.ui.theme.AdGuardDarkOutline
import kotlinx.coroutines.launch
import git.shin.adfree.ui.theme.AdGuardDarkSurfaceVariant
import git.shin.adfree.ui.theme.AdGuardGreenLight
import git.shin.adfree.ui.theme.AdGuardGreenPrimary
import git.shin.adfree.ui.theme.AdGuardPurpleAI
import git.shin.adfree.ui.theme.AdGuardRedBlocked
import git.shin.adfree.ui.theme.AdGuardTextMuted
import git.shin.adfree.ui.theme.AdGuardTextPrimary
import git.shin.adfree.ui.theme.AdGuardOnAccent
import git.shin.adfree.ui.theme.AdGuardTextSecondary
import git.shin.adfree.model.allowlistRuleBody
import git.shin.adfree.model.isAllowlistRule
import git.shin.adfree.model.parseUserRulesText
import git.shin.adfree.model.userBlockRule
import git.shin.adfree.model.userWhitelistRule

/**
 * Full-featured user-rules editor, opened from the "Quy tắc của bạn" row.
 *
 * Two modes: a visual card manager (search, badges, delete) and a raw
 * multi-line editor with syntax chips. Both push the whole rule list back with
 * `onSaveAll`, because the core recompiles from the complete set.
 */
@Composable
fun FriendlyCustomRuleEditorSheet(
    initialRules: List<String>,
    onSaveAll: (List<String>) -> Unit,
    onClose: () -> Unit,
) {
    var selectedTab by remember { mutableIntStateOf(0) } // 0: visual cards, 1: raw editor
    var rulesList by remember { mutableStateOf(initialRules) }
    var rawText by remember { mutableStateOf(initialRules.joinToString("\n")) }
    var newSingleRule by remember { mutableStateOf("") }
    var searchQuery by remember { mutableStateOf("") }
    var newWhitelistDomain by remember { mutableStateOf("") }

    val files = currentFileHost()
    val pickerScope = rememberCoroutineScope()
    var notice by remember { mutableStateOf<String?>(null) }
    var noticeIsError by remember { mutableStateOf(false) }
    var exportText by remember { mutableStateOf("") }
    // The rule builder: null while closed, "" for a new rule, or the text of
    // the rule being edited.
    var builderFor by remember { mutableStateOf<String?>(null) }

    // Files come from anywhere: AdGuard's export, a hosts file, or a plain
    // editor. Parse on import so comments and duplicates never reach the core.
    fun importRules() {
        pickerScope.launch {
            val uriText = files.openText() ?: return@launch
            val text = files.readText(uriText)
            if (text == null) {
                notice = L10n.get(Strings.filter_file_unreadable)
                noticeIsError = true
                return@launch
            }
            val imported = parseUserRulesText(text)
            if (imported.isEmpty()) {
                notice = L10n.get(Strings.rules_import_invalid)
                noticeIsError = true
                return@launch
            }
            val before = rulesList.toSet()
            val merged = (rulesList + imported).distinct()
            val added = merged.count { it !in before }
            rulesList = merged
            rawText = merged.joinToString("\n")
            onSaveAll(merged)
            notice = if (added == 0) {
                L10n.get(Strings.rules_import_duplicate)
            } else {
                L10n.format(Strings.rules_imported, added)
            }
            noticeIsError = added == 0
        }
    }

    // Creating the document writes the current rules, including unsaved edits
    // in the raw tab, so an export never silently drops what the user just typed.
    fun exportRules() {
        pickerScope.launch {
            val uriText = files.createDocument("adfree-user-rules.txt", "text/plain")
                ?: return@launch
            val written = files.writeText(uriText, exportText)
            notice = if (written) {
                L10n.format(Strings.rules_export_done, parseUserRulesText(exportText).size)
            } else {
                L10n.get(Strings.rules_export_failed)
            }
            noticeIsError = !written
        }
    }

    val whitelistCount = rulesList.count { it.startsWith("@@") }

    val editing = builderFor
    if (editing != null) {
        RuleBuilderSheet(
            title = L10n.get(
                if (editing.isEmpty()) Strings.rule_builder_add_title else Strings.rule_builder_edit_title,
            ),
            initialRule = editing,
            existingRules = rulesList,
            onSave = { rule ->
                rulesList = if (editing.isEmpty()) {
                    listOf(rule) + rulesList
                } else {
                    rulesList.map { if (it == editing) rule else it }
                }
                rawText = rulesList.joinToString("\n")
                onSaveAll(rulesList)
                builderFor = null
                notice = L10n.format(
                    if (editing.isEmpty()) Strings.rules_added else Strings.rules_edited,
                    rule,
                )
                noticeIsError = false
            },
            onCancel = { builderFor = null },
        )
        return
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp, vertical = 14.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column {
                Text(
                    text = L10n.get(Strings.filters_user_rules_title),
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Black,
                    color = AdGuardTextPrimary,
                )
                Text(
                    text = L10n.format(Strings.filters_user_rules_meta,
                        rulesList.size,
                        whitelistCount,
                    ),
                    fontSize = 12.sp,
                    color = AdGuardTextMuted,
                )
            }

            IconButton(onClick = onClose) {
                Icon(
                    Icons.Default.Close,
                    contentDescription = L10n.get(Strings.rules_close),
                    tint = AdGuardTextSecondary,
                )
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(2.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            TextButton(
                onClick = {
                    notice = null
                    importRules()
                },
            ) {
                Text(
                    L10n.get(Strings.rules_import),
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardGreenLight,
                )
            }
            TextButton(
                onClick = {
                    notice = null
                    exportText = if (selectedTab == 0) {
                        rulesList.joinToString("\n")
                    } else {
                        parseUserRulesText(rawText).joinToString("\n")
                    }
                    if (exportText.isBlank()) {
                        notice = L10n.get(Strings.rules_export_empty)
                        noticeIsError = true
                    } else {
                        exportRules()
                    }
                },
            ) {
                Text(
                    L10n.get(Strings.rules_export),
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardGreenLight,
                )
            }
            Spacer(modifier = Modifier.weight(1f))
            notice?.let {
                Text(
                    text = it,
                    fontSize = 11.sp,
                    color = if (noticeIsError) AdGuardRedBlocked else AdGuardGreenLight,
                    maxLines = 2,
                )
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        TabRow(
            selectedTabIndex = selectedTab,
            containerColor = AdGuardDarkSurfaceVariant,
            contentColor = AdGuardGreenPrimary,
            indicator = { tabPositions ->
                TabRowDefaults.SecondaryIndicator(
                    modifier = Modifier.tabIndicatorOffset(tabPositions[selectedTab]),
                    color = AdGuardGreenPrimary,
                )
            },
            modifier = Modifier.clip(RoundedCornerShape(10.dp)),
        ) {
            Tab(
                selected = selectedTab == 0,
                onClick = {
                    selectedTab = 0
                    notice = null
                    // Pull in whatever was typed in the raw editor.
                    rulesList = parseUserRulesText(rawText)
                    rawText = rulesList.joinToString("\n")
                },
                text = {
                    Text(
                        L10n.get(Strings.rules_tab_visual),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                    )
                },
            )
            Tab(
                selected = selectedTab == 1,
                onClick = {
                    selectedTab = 1
                    notice = null
                    rawText = rulesList.joinToString("\n")
                },
                text = {
                    Text(
                        L10n.get(Strings.rules_tab_raw),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                    )
                },
            )
            Tab(
                selected = selectedTab == 2,
                onClick = {
                    selectedTab = 2
                    notice = null
                    // Include raw-tab edits before showing the filtered list.
                    rulesList = parseUserRulesText(rawText)
                    rawText = rulesList.joinToString("\n")
                },
                text = {
                    Text(
                        L10n.format(Strings.rules_tab_allow, whitelistCount),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                    )
                },
            )
        }

        Spacer(modifier = Modifier.height(14.dp))

        if (selectedTab == 0) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OutlinedTextField(
                    value = newSingleRule,
                    onValueChange = {
                        newSingleRule = it
                        notice = null
                    },
                    placeholder = {
                        Text(
                            L10n.get(Strings.rules_input_hint),
                            color = AdGuardTextMuted,
                            fontSize = 12.sp,
                        )
                    },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(10.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedContainerColor = AdGuardDarkSurfaceVariant,
                        unfocusedContainerColor = AdGuardDarkSurfaceVariant,
                        focusedBorderColor = AdGuardGreenPrimary,
                        unfocusedBorderColor = AdGuardDarkOutline,
                        focusedTextColor = AdGuardTextPrimary,
                        unfocusedTextColor = AdGuardTextPrimary,
                    ),
                )

                Spacer(modifier = Modifier.width(8.dp))

                Button(
                    onClick = {
                        val rule = userBlockRule(newSingleRule)
                        when {
                            rule == null -> {
                                notice = if (newSingleRule.isBlank()) {
                                    L10n.get(Strings.rules_blank_rule)
                                } else {
                                    L10n.get(Strings.rules_invalid_rule)
                                }
                                noticeIsError = true
                            }
                            rule in rulesList -> {
                                notice = L10n.get(Strings.rules_exists)
                                noticeIsError = true
                            }
                            else -> {
                                rulesList = listOf(rule) + rulesList
                                rawText = rulesList.joinToString("\n")
                                newSingleRule = ""
                                onSaveAll(rulesList)
                                notice = L10n.format(Strings.rules_added, rule)
                                noticeIsError = false
                            }
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = AdGuardGreenPrimary),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.height(52.dp),
                ) {
                    Icon(Icons.Default.Add, contentDescription = null, tint = AdGuardOnAccent)
                }
            }

            TextButton(
                onClick = {
                    builderFor = ""
                    notice = null
                },
                modifier = Modifier.testTag("open_rule_builder"),
            ) {
                Icon(
                    Icons.Default.AutoFixHigh,
                    contentDescription = null,
                    tint = AdGuardGreenLight,
                    modifier = Modifier.size(16.dp),
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    L10n.get(Strings.rules_add_open),
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardGreenLight,
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                placeholder = {
                    Text(
                        L10n.get(Strings.rules_search_hint),
                        color = AdGuardTextMuted,
                        fontSize = 12.sp,
                    )
                },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = AdGuardTextMuted) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(10.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedContainerColor = AdGuardDarkSurfaceVariant,
                    unfocusedContainerColor = AdGuardDarkSurfaceVariant,
                    focusedBorderColor = AdGuardGreenPrimary,
                    unfocusedBorderColor = AdGuardDarkOutline,
                    focusedTextColor = AdGuardTextPrimary,
                    unfocusedTextColor = AdGuardTextPrimary,
                ),
            )

            Spacer(modifier = Modifier.height(10.dp))

            val filteredRules = rulesList.filter {
                searchQuery.isBlank() || it.contains(searchQuery, ignoreCase = true)
            }

            LazyColumn(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                items(filteredRules) { rule ->
                    val isWhitelist = allowlistRuleBody(rule).startsWith("@@")
                    val isRegex = rule.startsWith("/") && rule.endsWith("/")
                    val badgeColor = if (isWhitelist) AdGuardGreenLight else if (isRegex) AdGuardPurpleAI else AdGuardRedBlocked
                    val badgeText = when {
                        isWhitelist -> L10n.get(Strings.rules_badge_allow)
                        isRegex -> L10n.get(Strings.rules_badge_regex)
                        else -> L10n.get(Strings.rules_badge_block)
                    }

                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(10.dp),
                        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurfaceVariant),
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 12.dp, vertical = 10.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Row(
                                modifier = Modifier.weight(1f),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Box(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(6.dp))
                                        .background(badgeColor.copy(alpha = 0.15f))
                                        .padding(horizontal = 6.dp, vertical = 2.dp),
                                ) {
                                    Text(badgeText, fontSize = 10.sp, fontWeight = FontWeight.Bold, color = badgeColor)
                                }
                                Spacer(modifier = Modifier.width(10.dp))
                                Text(
                                    text = rule,
                                    fontSize = 13.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = AdGuardTextPrimary,
                                )
                            }

                            IconButton(
                                onClick = {
                                    builderFor = rule
                                    notice = null
                                },
                                modifier = Modifier.size(28.dp),
                            ) {
                                Icon(
                                    Icons.Default.Edit,
                                    contentDescription = L10n.get(Strings.rules_edit),
                                    tint = AdGuardTextMuted,
                                    modifier = Modifier.size(16.dp),
                                )
                            }

                            IconButton(
                                onClick = {
                                    rulesList = rulesList.filter { it != rule }
                                    rawText = rulesList.joinToString("\n")
                                    onSaveAll(rulesList)
                                    notice = L10n.format(Strings.rules_deleted, rule)
                                    noticeIsError = false
                                },
                                modifier = Modifier.size(28.dp),
                            ) {
                                Icon(
                                    Icons.Default.Delete,
                                    contentDescription = L10n.get(Strings.ext_delete),
                                    tint = AdGuardTextMuted,
                                    modifier = Modifier.size(16.dp),
                                )
                            }
                        }
                    }
                }
            }
        } else if (selectedTab == 1) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                QuickSyntaxChip("+ ||domain^") { rawText += (if (rawText.isNotEmpty() && !rawText.endsWith("\n")) "\n" else "") + "||example.com^" }
                QuickSyntaxChip("+ @@||whitelist^") { rawText += (if (rawText.isNotEmpty() && !rawText.endsWith("\n")) "\n" else "") + "@@||safe.com^" }
                QuickSyntaxChip("+ /regex/") { rawText += (if (rawText.isNotEmpty() && !rawText.endsWith("\n")) "\n" else "") + "/.*[-_]telemetry\\..*/" }
            }

            Spacer(modifier = Modifier.height(10.dp))

            OutlinedTextField(
                value = rawText,
                onValueChange = { rawText = it },
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth(),
                shape = RoundedCornerShape(10.dp),
                textStyle = androidx.compose.ui.text.TextStyle(
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    color = AdGuardTextPrimary,
                ),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedContainerColor = AdGuardDarkSurfaceVariant,
                    unfocusedContainerColor = AdGuardDarkSurfaceVariant,
                    focusedBorderColor = AdGuardGreenPrimary,
                    unfocusedBorderColor = AdGuardDarkOutline,
                ),
            )

            Spacer(modifier = Modifier.height(10.dp))

            val linesCount = parseUserRulesText(rawText).size

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Button(
                    onClick = {
                        val cleaned = parseUserRulesText(rawText)
                        rawText = cleaned.joinToString("\n")
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = AdGuardDarkSurfaceVariant),
                    shape = RoundedCornerShape(8.dp),
                ) {
                    Icon(Icons.Default.AutoFixHigh, contentDescription = null, tint = AdGuardTextSecondary, modifier = Modifier.size(14.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        L10n.get(Strings.rules_dedupe),
                        fontSize = 11.sp,
                        color = AdGuardTextSecondary,
                    )
                }

                Button(
                    onClick = {
                        val newRules = parseUserRulesText(rawText)
                        rulesList = newRules
                        rawText = newRules.joinToString("\n")
                        onSaveAll(newRules)
                        notice = L10n.format(Strings.rules_saved, newRules.size)
                        noticeIsError = false
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = AdGuardGreenPrimary),
                    shape = RoundedCornerShape(8.dp),
                ) {
                    Icon(Icons.Default.Check, contentDescription = null, tint = AdGuardOnAccent, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        L10n.format(Strings.rules_save_count, linesCount),
                        color = AdGuardOnAccent,
                        fontWeight = FontWeight.Bold,
                        fontSize = 12.sp,
                    )
                }
            }
        } else {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OutlinedTextField(
                    value = newWhitelistDomain,
                    onValueChange = {
                        newWhitelistDomain = it
                        notice = null
                    },
                    placeholder = {
                        Text(
                            L10n.get(Strings.rules_allow_hint),
                            color = AdGuardTextMuted,
                            fontSize = 12.sp,
                        )
                    },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(10.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedContainerColor = AdGuardDarkSurfaceVariant,
                        unfocusedContainerColor = AdGuardDarkSurfaceVariant,
                        focusedBorderColor = AdGuardGreenPrimary,
                        unfocusedBorderColor = AdGuardDarkOutline,
                        focusedTextColor = AdGuardTextPrimary,
                        unfocusedTextColor = AdGuardTextPrimary,
                    ),
                )
                Spacer(modifier = Modifier.width(8.dp))
                Button(
                    onClick = {
                        val rule = userWhitelistRule(newWhitelistDomain)
                        if (rule == null) {
                            notice = L10n.get(Strings.rules_invalid_domain)
                            noticeIsError = true
                        } else if (rule in rulesList) {
                            notice = L10n.get(Strings.rules_exception_exists)
                            noticeIsError = true
                        } else {
                            val merged = rulesList + rule
                            rulesList = merged
                            rawText = merged.joinToString("\n")
                            newWhitelistDomain = ""
                            onSaveAll(merged)
                            notice = L10n.format(Strings.rules_exception_added, rule)
                            noticeIsError = false
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = AdGuardGreenPrimary),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.height(52.dp),
                ) {
                    Icon(Icons.Default.Add, contentDescription = null, tint = AdGuardOnAccent)
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            Text(
                text = L10n.get(Strings.rules_allow_note),
                fontSize = 11.sp,
                color = AdGuardTextMuted,
            )

            Spacer(modifier = Modifier.height(10.dp))

            val whitelistRules = rulesList.filter { isAllowlistRule(it) }
            if (whitelistRules.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = L10n.get(Strings.rules_allow_empty),
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
                    items(whitelistRules) { rule ->
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(10.dp),
                            colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurfaceVariant),
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 12.dp, vertical = 8.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Box(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(6.dp))
                                        .background(AdGuardGreenLight.copy(alpha = 0.15f))
                                        .padding(horizontal = 6.dp, vertical = 2.dp),
                                ) {
                                    Text(
                                        text = L10n.get(Strings.rules_badge_allow),
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = AdGuardGreenLight,
                                    )
                                }
                                Spacer(modifier = Modifier.width(10.dp))
                                Text(
                                    text = rule,
                                    modifier = Modifier.weight(1f),
                                    fontSize = 13.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = AdGuardTextPrimary,
                                )
                                IconButton(
                                    onClick = {
                                        rulesList = rulesList.filterNot { it == rule }
                                        rawText = rulesList.joinToString("\n")
                                        onSaveAll(rulesList)
                                        notice = L10n.format(Strings.rules_exception_deleted,
                                            rule,
                                        )
                                        noticeIsError = false
                                    },
                                    modifier = Modifier.size(28.dp),
                                ) {
                                    Icon(
                                        Icons.Default.Delete,
                                        contentDescription = L10n.format(Strings.rules_delete_exception,
                                        ),
                                        tint = AdGuardTextMuted,
                                        modifier = Modifier.size(16.dp),
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))
    }
}

@Composable
fun QuickSyntaxChip(label: String, onClick: () -> Unit) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(6.dp))
            .background(AdGuardDarkSurfaceVariant)
            .clickable { onClick() }
            .padding(horizontal = 8.dp, vertical = 4.dp),
    ) {
        Text(text = label, fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = AdGuardGreenLight, fontWeight = FontWeight.SemiBold)
    }
}
