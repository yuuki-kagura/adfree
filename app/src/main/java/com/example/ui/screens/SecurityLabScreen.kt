package com.example.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Lightbulb
import androidx.compose.material.icons.filled.Psychology
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Science
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.model.ThreatAnalysisResult
import com.example.ui.AdGuardIntent
import com.example.ui.AdGuardViewModel
import com.example.ui.AiAnalysisMode
import com.example.ui.AiLabUiState
import com.example.ui.theme.AdGuardBlueDns
import com.example.ui.theme.AdGuardDarkBg
import com.example.ui.theme.AdGuardDarkOutline
import com.example.ui.theme.AdGuardDarkSurface
import com.example.ui.theme.AdGuardDarkSurfaceVariant
import com.example.ui.theme.AdGuardGreenLight
import com.example.ui.theme.AdGuardGreenPrimary
import com.example.ui.theme.AdGuardOrangeWarning
import com.example.ui.theme.AdGuardPurpleAI
import com.example.ui.theme.AdGuardRedBlocked
import com.example.ui.theme.AdGuardTextMuted
import com.example.ui.theme.AdGuardTextPrimary
import com.example.ui.theme.AdGuardTextSecondary

@Composable
fun SecurityLabScreen(
    viewModel: AdGuardViewModel,
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()
    var domainInput by remember { mutableStateOf("googleads.g.doubleclick.net") }
    val scrollState = rememberScrollState()

    val quickExamples = listOf(
        "doubleclick.net",
        "tiktok-telemetry.com",
        "phishing-bank-fake.xyz",
        "pixel.facebook.com"
    )

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(AdGuardDarkBg)
            .verticalScroll(scrollState)
            .padding(horizontal = 16.dp, vertical = 12.dp)
    ) {
        // Title
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                imageVector = Icons.Default.Science,
                contentDescription = null,
                tint = AdGuardPurpleAI,
                modifier = Modifier.size(24.dp)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Column {
                Text(
                    text = "AI THREAT & SCIENCE LAB",
                    fontSize = 17.sp,
                    fontWeight = FontWeight.Black,
                    color = AdGuardTextPrimary,
                    letterSpacing = 1.sp
                )
                Text(
                    text = "Phân tích mối đe dọa mạng & Tối ưu hóa regex tiết kiệm pin",
                    fontSize = 11.sp,
                    color = AdGuardTextMuted
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // AI Engine Mode Selector Chips
        Text(
            text = "CHỌN MÔ HÌNH AI",
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextSecondary,
            letterSpacing = 0.5.sp
        )

        Spacer(modifier = Modifier.height(8.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            FilterChip(
                selected = state.aiMode == AiAnalysisMode.SEARCH_GROUNDING,
                onClick = { viewModel.onIntent(AdGuardIntent.SetAiMode(AiAnalysisMode.SEARCH_GROUNDING)) },
                label = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Public, contentDescription = null, modifier = Modifier.size(14.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Search (gemini-3.5-flash)", fontSize = 11.sp)
                    }
                },
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = AdGuardBlueDns,
                    selectedLabelColor = Color.Black,
                    containerColor = AdGuardDarkSurface,
                    labelColor = AdGuardTextSecondary
                ),
                modifier = Modifier.weight(1f)
            )

            FilterChip(
                selected = state.aiMode == AiAnalysisMode.HIGH_THINKING,
                onClick = { viewModel.onIntent(AdGuardIntent.SetAiMode(AiAnalysisMode.HIGH_THINKING)) },
                label = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Psychology, contentDescription = null, modifier = Modifier.size(14.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("High Thinking (gemini-3.1-pro)", fontSize = 11.sp)
                    }
                },
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = AdGuardPurpleAI,
                    selectedLabelColor = Color.Black,
                    containerColor = AdGuardDarkSurface,
                    labelColor = AdGuardTextSecondary
                ),
                modifier = Modifier.weight(1f)
            )
        }

        Spacer(modifier = Modifier.height(14.dp))

        // Input Box & Scan Button
        OutlinedTextField(
            value = domainInput,
            onValueChange = { domainInput = it },
            label = { Text("Tên miền, URL hoặc thông số mạng") },
            placeholder = { Text("Ví dụ: tracking.app.com") },
            singleLine = true,
            modifier = Modifier
                .fillMaxWidth()
                .testTag("ai_threat_input"),
            shape = RoundedCornerShape(12.dp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedContainerColor = AdGuardDarkSurface,
                unfocusedContainerColor = AdGuardDarkSurface,
                focusedBorderColor = AdGuardPurpleAI,
                unfocusedBorderColor = AdGuardDarkOutline,
                focusedTextColor = AdGuardTextPrimary,
                unfocusedTextColor = AdGuardTextPrimary
            )
        )

        Spacer(modifier = Modifier.height(8.dp))

        // Quick Examples row
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            quickExamples.forEach { ex ->
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(AdGuardDarkSurfaceVariant)
                        .clickable { domainInput = ex }
                        .padding(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = ex,
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        color = AdGuardTextSecondary
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        Button(
            onClick = { viewModel.onIntent(AdGuardIntent.RunThreatScan(domainInput)) },
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp)
                .testTag("run_analysis_button"),
            shape = RoundedCornerShape(12.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = if (state.aiMode == AiAnalysisMode.SEARCH_GROUNDING) AdGuardBlueDns else AdGuardPurpleAI
            )
        ) {
            Icon(
                imageVector = if (state.aiMode == AiAnalysisMode.SEARCH_GROUNDING) Icons.Default.Search else Icons.Default.Psychology,
                contentDescription = null,
                tint = Color.Black
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = if (state.aiMode == AiAnalysisMode.SEARCH_GROUNDING) "Tra cứu dữ liệu mối đe dọa Google" else "Phân tích suy luận sâu (High Thinking)",
                fontWeight = FontWeight.Bold,
                color = Color.Black
            )
        }

        Spacer(modifier = Modifier.height(20.dp))

        // Analysis Result State Handler
        when (val labState = state.aiLabState) {
            is AiLabUiState.Idle -> {
                ScienceLabIntroCard()
            }
            is AiLabUiState.Loading -> {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(28.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        CircularProgressIndicator(
                            color = AdGuardPurpleAI,
                            modifier = Modifier.size(40.dp)
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Text(
                            text = labState.message,
                            fontSize = 13.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = AdGuardTextPrimary
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = "Đang tính toán độ phức tạp Regex & trạng thái ngủ modem radio...",
                            fontSize = 11.sp,
                            color = AdGuardTextMuted
                        )
                    }
                }
            }
            is AiLabUiState.Success -> {
                ThreatResultCard(
                    result = labState.result,
                    onAddRule = { rule ->
                        viewModel.onIntent(AdGuardIntent.AddCustomRule(rule))
                    }
                )
            }
            is AiLabUiState.Error -> {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0x22FF435A))
                ) {
                    Row(
                        modifier = Modifier.padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Default.Warning, contentDescription = null, tint = AdGuardRedBlocked)
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(text = labState.message, color = AdGuardRedBlocked, fontSize = 13.sp)
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))
    }
}

@Composable
fun ScienceLabIntroCard() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        border = CardDefaults.outlinedCardBorder().copy(brush = androidx.compose.ui.graphics.SolidColor(AdGuardDarkOutline))
    ) {
        Column(modifier = Modifier.padding(18.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Lightbulb, contentDescription = null, tint = AdGuardGreenLight, modifier = Modifier.size(20.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "Khả năng phân tích khoa học mạng",
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextPrimary
                )
            }

            Spacer(modifier = Modifier.height(10.dp))

            Text(
                text = "• Google Search Grounding: Tra cứu trực tiếp cơ sở dữ liệu mối đe dọa toàn cầu, danh sách CVE và báo cáo theo dõi quyền riêng tư qua gemini-3.5-flash.\n\n" +
                    "• High Thinking Forensics: Kiểm tra nguy cơ Catastrophic Backtracking của biểu thức chính quy (Regex), tính toán độ trễ bộ nhớ Rust Trie vi giây và tự động tạo quy tắc tiết kiệm pin qua gemini-3.1-pro-preview với thinkingLevel HIGH.",
                fontSize = 12.sp,
                color = AdGuardTextSecondary,
                lineHeight = 18.sp
            )
        }
    }
}

@Composable
fun ThreatResultCard(
    result: ThreatAnalysisResult,
    onAddRule: (String) -> Unit
) {
    val riskColor = when {
        result.riskScore > 75 -> AdGuardRedBlocked
        result.riskScore > 40 -> AdGuardOrangeWarning
        else -> AdGuardGreenPrimary
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        border = CardDefaults.outlinedCardBorder().copy(brush = Brush.horizontalGradient(listOf(AdGuardDarkOutline, riskColor.copy(alpha = 0.4f))))
    ) {
        Column(modifier = Modifier.padding(18.dp)) {
            // Header with Risk Score Meter
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = result.domain,
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace,
                        color = AdGuardTextPrimary
                    )
                    Text(
                        text = result.category,
                        fontSize = 12.sp,
                        color = AdGuardTextSecondary
                    )
                }

                // Risk Score Badge
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(8.dp))
                        .background(riskColor.copy(alpha = 0.15f))
                        .border(1.dp, riskColor, RoundedCornerShape(8.dp))
                        .padding(horizontal = 10.dp, vertical = 6.dp)
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(
                            text = "${result.riskScore}/100",
                            fontSize = 14.sp,
                            fontWeight = FontWeight.ExtraBold,
                            color = riskColor
                        )
                        Text(
                            text = result.riskLevel.uppercase(),
                            fontSize = 9.sp,
                            fontWeight = FontWeight.Bold,
                            color = riskColor
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Summary Explanation
            Text(
                text = "ĐÁNH GIÁ KHOA HỌC & TÁC ĐỘNG TIÊU THỤ PIN",
                fontSize = 10.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextMuted,
                letterSpacing = 0.5.sp
            )

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = result.summary,
                fontSize = 13.sp,
                color = AdGuardTextPrimary,
                lineHeight = 18.sp
            )

            // Thinking trace summary if present
            if (result.thinkingTraceSummary != null) {
                Spacer(modifier = Modifier.height(12.dp))
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .background(AdGuardDarkSurfaceVariant)
                        .padding(10.dp)
                ) {
                    Column {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Psychology, contentDescription = null, tint = AdGuardPurpleAI, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Dấu vết suy luận chuyên sâu (High Thinking Trace)", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = AdGuardPurpleAI)
                        }
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(text = result.thinkingTraceSummary, fontSize = 11.sp, color = AdGuardTextSecondary)
                    }
                }
            }

            // Synthesized Rules section
            if (result.suggestedRules.isNotEmpty()) {
                Spacer(modifier = Modifier.height(14.dp))
                Text(
                    text = "QUY TẮC ĐƯỢC TỔNG HỢP (ZERO-OVERHEAD)",
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextMuted,
                    letterSpacing = 0.5.sp
                )

                Spacer(modifier = Modifier.height(6.dp))

                result.suggestedRules.forEach { rule ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .background(AdGuardDarkSurfaceVariant)
                            .padding(horizontal = 10.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = rule,
                            fontSize = 12.sp,
                            fontFamily = FontFamily.Monospace,
                            color = AdGuardGreenLight,
                            modifier = Modifier.weight(1f)
                        )

                        Button(
                            onClick = { onAddRule(rule) },
                            colors = ButtonDefaults.buttonColors(containerColor = AdGuardGreenPrimary),
                            shape = RoundedCornerShape(6.dp),
                            modifier = Modifier.height(32.dp)
                        ) {
                            Icon(Icons.Default.Add, contentDescription = null, tint = Color.Black, modifier = Modifier.size(14.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Thêm", fontSize = 11.sp, color = Color.Black, fontWeight = FontWeight.Bold)
                        }
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                }
            }

            // Search Grounding sources
            if (result.searchGroundedSources.isNotEmpty()) {
                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = "Nguồn dữ liệu xác thực: " + result.searchGroundedSources.joinToString(", "),
                    fontSize = 10.sp,
                    color = AdGuardTextMuted
                )
            }
        }
    }
}
