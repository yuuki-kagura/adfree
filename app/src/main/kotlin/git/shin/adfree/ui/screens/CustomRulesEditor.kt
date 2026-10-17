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
                    text = "${rulesList.size} quy tắc đang áp dụng cho mọi trang",
                    fontSize = 12.sp,
                    color = AdGuardTextMuted,
                )
            }

            IconButton(onClick = onClose) {
                Icon(Icons.Default.Close, contentDescription = "Đóng", tint = AdGuardTextSecondary)
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
                    rulesList = rawText.lines().map { it.trim() }.filter { it.isNotEmpty() }
                },
                text = { Text("Quản lý trực quan (${rulesList.size})", fontSize = 12.sp, fontWeight = FontWeight.Bold) },
            )
            Tab(
                selected = selectedTab == 1,
                onClick = {
                    selectedTab = 1
                    rawText = rulesList.joinToString("\n")
                },
                text = { Text("Soạn thảo toàn văn (Raw)", fontSize = 12.sp, fontWeight = FontWeight.Bold) },
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
                        if (trimmed.isNotEmpty()) {
                            rulesList = listOf(trimmed) + rulesList
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
        } else {
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

            val linesCount = rawText.lines().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("!") }.size

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Button(
                    onClick = {
                        val cleaned = rawText.lines()
                            .map { it.trim() }
                            .filter { it.isNotEmpty() }
                            .distinct()
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
                        val newRules = rawText.lines().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("!") }
                        rulesList = newRules
                        onSaveAll(newRules)
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = AdGuardGreenPrimary),
                    shape = RoundedCornerShape(8.dp),
                ) {
                    Icon(Icons.Default.Check, contentDescription = null, tint = Color.Black, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Lưu $linesCount quy tắc", color = Color.Black, fontWeight = FontWeight.Bold, fontSize = 12.sp)
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
