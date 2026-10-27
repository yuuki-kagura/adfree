package git.shin.adfree.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Lightbulb
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Science
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Memory
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.R
import git.shin.adfree.model.ThreatAnalysisResult
import git.shin.adfree.ui.AdGuardIntent
import git.shin.adfree.ui.AdGuardViewModel
import git.shin.adfree.ui.AiLabUiState
import git.shin.adfree.ui.theme.AdGuardBlueDns
import git.shin.adfree.ui.theme.AdGuardDarkBg
import git.shin.adfree.ui.theme.AdGuardDarkOutline
import git.shin.adfree.ui.theme.AdGuardDarkSurface
import git.shin.adfree.ui.theme.AdGuardDarkSurfaceVariant
import git.shin.adfree.ui.theme.AdGuardGreenLight
import git.shin.adfree.ui.theme.AdGuardGreenPrimary
import git.shin.adfree.ui.theme.AdGuardOrangeWarning
import git.shin.adfree.ui.theme.AdGuardPurpleAI
import git.shin.adfree.ui.theme.AdGuardRedBlocked
import git.shin.adfree.ui.theme.AdGuardTextMuted
import git.shin.adfree.ui.theme.AdGuardTextPrimary
import git.shin.adfree.ui.theme.AdGuardOnAccent
import git.shin.adfree.ui.theme.AdGuardTextSecondary

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

    // The header stays outside the scroll: it says where you are, it should not
    // slide away the moment the content moves.
    Column(
        modifier = modifier
            .fillMaxSize()
            .background(AdGuardDarkBg)
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Default.Science,
                contentDescription = null,
                tint = AdGuardPurpleAI,
                modifier = Modifier.size(24.dp)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Column {
                Text(
                    text = stringResource(R.string.lab_title),
                    fontSize = 19.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextPrimary
                )
                Text(
                    text = stringResource(R.string.lab_subtitle),
                    fontSize = 12.sp,
                    color = AdGuardTextMuted
                )
            }
        }

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(scrollState)
                .padding(horizontal = 16.dp)
        ) {

            Spacer(modifier = Modifier.height(16.dp))

            // Engine explanation: everything runs on device.
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
            ) {
                Row(
                    modifier = Modifier.padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Icon(
                        imageVector = Icons.Default.Memory,
                        contentDescription = null,
                        tint = AdGuardGreenLight,
                        modifier = Modifier.size(18.dp),
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Column {
                        Text(
                            text = stringResource(R.string.lab_on_device_title),
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            color = AdGuardTextPrimary,
                        )
                        Text(
                            text = stringResource(R.string.lab_on_device_body),
                            fontSize = 11.sp,
                            color = AdGuardTextMuted,
                        )
                    }
                }
            }

        // Input Box & Scan Button
        OutlinedTextField(
            value = domainInput,
            onValueChange = { domainInput = it },
            label = { Text(stringResource(R.string.lab_input_label)) },
            placeholder = { Text(stringResource(R.string.lab_input_hint)) },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
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
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
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
                        fontSize = 11.sp,
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
            colors = ButtonDefaults.buttonColors(containerColor = AdGuardGreenPrimary)
        ) {
            Icon(
                imageVector = Icons.Default.Shield,
                contentDescription = null,
                tint = AdGuardOnAccent,
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = stringResource(R.string.lab_scan),
                fontWeight = FontWeight.Bold,
                color = AdGuardOnAccent,
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
                            text = labState.message.asString(),
                            fontSize = 13.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = AdGuardTextPrimary
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = stringResource(R.string.lab_analyzing),
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
                        Text(
                            text = labState.message.asString(),
                            color = AdGuardRedBlocked,
                            fontSize = 13.sp,
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))
    }
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
                    text = stringResource(R.string.lab_how_title),
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextPrimary
                )
            }

            Spacer(modifier = Modifier.height(10.dp))

            Text(
                text = stringResource(R.string.lab_how_body),
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
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            color = riskColor
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Summary Explanation
            Text(
                text = stringResource(R.string.lab_assessment),
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextMuted,
            )

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = result.summary,
                fontSize = 13.sp,
                color = AdGuardTextPrimary,
                lineHeight = 18.sp
            )

            // Synthesized Rules section
            if (result.suggestedRules.isNotEmpty()) {
                Spacer(modifier = Modifier.height(14.dp))
                Text(
                    text = stringResource(R.string.lab_suggested_rules),
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = AdGuardTextMuted,
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
                            Icon(Icons.Default.Add, contentDescription = null, tint = AdGuardOnAccent, modifier = Modifier.size(14.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(
                                stringResource(R.string.lab_add),
                                fontSize = 12.sp,
                                color = AdGuardOnAccent,
                                fontWeight = FontWeight.Bold,
                            )
                        }
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                }
            }

            // Suggested rules are produced offline, so the data-source block is gone; just state that analysis runs on device.
            Text(
                text = stringResource(R.string.lab_offline),
                fontSize = 11.sp,
                color = AdGuardTextMuted,
            )
        }
    }
}
