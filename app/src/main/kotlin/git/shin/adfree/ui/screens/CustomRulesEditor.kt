package git.shin.adfree.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.AutoFixHigh
import androidx.compose.material.icons.filled.Check
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
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.ui.theme.AdGuardDarkOutline
import git.shin.adfree.ui.theme.AdGuardDarkSurfaceVariant
import git.shin.adfree.ui.theme.AdGuardGreenLight
import git.shin.adfree.ui.theme.AdGuardGreenPrimary
import git.shin.adfree.ui.theme.AdGuardPurpleAI
import git.shin.adfree.ui.theme.AdGuardRedBlocked
import git.shin.adfree.ui.theme.AdGuardTextMuted
import git.shin.adfree.ui.theme.AdGuardTextPrimary
import git.shin.adfree.ui.theme.AdGuardTextSecondary
import git.shin.adfree.model.parseUserRulesText
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

    val context = LocalContext.current
    var notice by remember { mutableStateOf<String?>(null) }
    var exportText by remember { mutableStateOf("") }

    // Files come from anywhere: AdGuard's export, a hosts file, or a plain
    // editor. Parse on import so comments and duplicates never reach the core.
    val importPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        val text = runCatching {
            context.contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
        }.getOrNull()
        if (text == null) {
            notice = "Không đọc được tệp"
            return@rememberLauncherForActivityResult
        }
        val imported = parseUserRulesText(text)
        if (imported.isEmpty()) {
            notice = "Tệp không có quy tắc hợp lệ"
            return@rememberLauncherForActivityResult
        }
        val before = rulesList.toSet()
        val merged = (rulesList + imported).distinct()
        val added = merged.count { it !in before }
        rulesList = merged
        rawText = merged.joinToString("\n")
        onSaveAll(merged)
        notice = if (added == 0) "Tệp chỉ chứa quy tắc đã có" else "Đã nhập $added quy tắc"
    }

    // CreateDocument writes the current rules, including unsaved edits in the
    // raw tab, so an export never silently drops what the user just typed.
    val exportPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain"),
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        val written = runCatching {
            context.contentResolver.openOutputStream(uri)?.bufferedWriter()?.use { it.write(exportText) }
                ?: error("no output stream")
        }.isSuccess
        notice = if (written) {
            "Đã xuất ${parseUserRulesText(exportText).size} quy tắc"
        } else {
            "Không ghi được tệp"
        }
    }

    val whitelistCount = rulesList.count { it.startsWith("@@") }

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
                    text = "Quy tắc của bạn",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Black,
                    color = AdGuardTextPrimary,
                )
                Text(
                    text = "${rulesList.size} quy tắc • $whitelistCount ngoại lệ",
                    fontSize = 12.sp,
                    color = AdGuardTextMuted,
                )
            }

            IconButton(onClick = onClose) {
                Icon(Icons.Default.Close, contentDescription = "Đóng", tint = AdGuardTextSecondary)
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
                    importPicker.launch(arrayOf("text/plain", "text/*", "*/*"))
                },
            ) {
                Text("Nhập tệp", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = AdGuardGreenLight)
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
                        notice = "Chưa có quy tắc để xuất"
                    } else {
                        exportPicker.launch("adfree-user-rules.txt")
                    }
                },
            ) {
                Text("Xuất tệp", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = AdGuardGreenLight)
            }
            Spacer(modifier = Modifier.weight(1f))
            notice?.let {
                Text(
                    text = it,
                    fontSize = 11.sp,
                    color = AdGuardGreenLight,
                    maxLines = 1,
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
                    // Pull in whatever was typed in the raw editor.
                    rulesList = parseUserRulesText(rawText)
                    rawText = rulesList.joinToString("\n")
                },
                text = { Text("Trực quan", fontSize = 12.sp, fontWeight = FontWeight.Bold) },
            )
            Tab(
                selected = selectedTab == 1,
                onClick = {
                    selectedTab = 1
                    rawText = rulesList.joinToString("\n")
                },
                text = { Text("Toàn văn", fontSize = 12.sp, fontWeight = FontWeight.Bold) },
            )
            Tab(
                selected = selectedTab == 2,
                onClick = {
                    selectedTab = 2
                    // Include raw-tab edits before showing the filtered list.
                    rulesList = parseUserRulesText(rawText)
                    rawText = rulesList.joinToString("\n")
                },
                text = { Text("Cho phép ($whitelistCount)", fontSize = 12.sp, fontWeight = FontWeight.Bold) },
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
                    onValueChange = { newSingleRule = it },
                    placeholder = {
                        Text("Nhập quy tắc: ||domain.com^ hoặc @@||cho-phep.com^", color = AdGuardTextMuted, fontSize = 12.sp)
                    },
                    singleLine = true,
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
                        val trimmed = newSingleRule.trim()
                        val parsed = parseUserRulesText(trimmed)
                        if (parsed.isEmpty()) {
                            if (trimmed.isNotEmpty()) notice = "Chú thích không phải là quy tắc"
                        } else {
                            val rule = parsed.first()
                            rulesList = (listOf(rule) + rulesList).distinct()
                            rawText = rulesList.joinToString("\n")
                            newSingleRule = ""
                            onSaveAll(rulesList)
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = AdGuardGreenPrimary),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.height(52.dp),
                ) {
                    Icon(Icons.Default.Add, contentDescription = null, tint = Color.Black)
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                placeholder = { Text("Lọc tìm quy tắc...", color = AdGuardTextMuted, fontSize = 12.sp) },
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
                    val isWhitelist = rule.startsWith("@@")
                    val isRegex = rule.startsWith("/") && rule.endsWith("/")
                    val badgeColor = if (isWhitelist) AdGuardGreenLight else if (isRegex) AdGuardPurpleAI else AdGuardRedBlocked
                    val badgeText = if (isWhitelist) "CHO PHÉP" else if (isRegex) "REGEX" else "CHẶN"

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
                                    Text(badgeText, fontSize = 9.sp, fontWeight = FontWeight.Bold, color = badgeColor)
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
                                    rulesList = rulesList.filter { it != rule }
                                    rawText = rulesList.joinToString("\n")
                                    onSaveAll(rulesList)
                                },
                                modifier = Modifier.size(28.dp),
                            ) {
                                Icon(Icons.Default.Delete, contentDescription = "Xóa", tint = AdGuardTextMuted, modifier = Modifier.size(16.dp))
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
                    Text("Dọn trùng lặp", fontSize = 11.sp, color = AdGuardTextSecondary)
                }

                Button(
                    onClick = {
                        val newRules = parseUserRulesText(rawText)
                        rulesList = newRules
                        rawText = newRules.joinToString("\n")
                        onSaveAll(newRules)
                        notice = "Đã lưu ${newRules.size} quy tắc"
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = AdGuardGreenPrimary),
                    shape = RoundedCornerShape(8.dp),
                ) {
                    Icon(Icons.Default.Check, contentDescription = null, tint = Color.Black, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Lưu $linesCount quy tắc", color = Color.Black, fontWeight = FontWeight.Bold, fontSize = 12.sp)
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
                        Text("domain được phép, vd: example.com", color = AdGuardTextMuted, fontSize = 12.sp)
                    },
                    singleLine = true,
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
                            notice = "Domain không hợp lệ"
                        } else {
                            val merged = (rulesList + rule).distinct()
                            rulesList = merged
                            rawText = merged.joinToString("\n")
                            newWhitelistDomain = ""
                            onSaveAll(merged)
                            notice = "Đã thêm ngoại lệ"
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = AdGuardGreenPrimary),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.height(52.dp),
                ) {
                    Icon(Icons.Default.Add, contentDescription = null, tint = Color.Black)
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            Text(
                text = "Quy tắc @@ cho phép domain bỏ qua mọi bộ lọc. " +
                    "Thêm domain ở trên hoặc sửa trực tiếp trong tab Toàn văn.",
                fontSize = 11.sp,
                color = AdGuardTextMuted,
            )

            Spacer(modifier = Modifier.height(10.dp))

            val whitelistRules = rulesList.filter { it.startsWith("@@") }
            if (whitelistRules.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = "Chưa có ngoại lệ nào",
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
                                        text = "CHO PHÉP",
                                        fontSize = 9.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = AdGuardGreenLight,
                                    )
                                }
                                Spacer(modifier = Modifier.width(10.dp))
                                Text(
                                    text = rule,
                                    modifier = Modifier.weight(1f),
                                    fontSize = 12.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = AdGuardTextPrimary,
                                )
                                IconButton(
                                    onClick = {
                                        rulesList = rulesList.filterNot { it == rule }
                                        rawText = rulesList.joinToString("\n")
                                        onSaveAll(rulesList)
                                        notice = "Đã xoá ngoại lệ"
                                    },
                                    modifier = Modifier.size(28.dp),
                                ) {
                                    Icon(
                                        Icons.Default.Delete,
                                        contentDescription = "Xoá ngoại lệ",
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
