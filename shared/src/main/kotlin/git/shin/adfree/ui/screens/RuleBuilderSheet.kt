package git.shin.adfree.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.l10n.L10n
import git.shin.adfree.l10n.Strings
import git.shin.adfree.model.RULE_FLAG_MODIFIERS
import git.shin.adfree.model.RULE_TYPE_MODIFIERS
import git.shin.adfree.model.RuleDecision
import git.shin.adfree.model.RuleError
import git.shin.adfree.model.buildRule
import git.shin.adfree.model.ParsedRule
import git.shin.adfree.model.describeRule
import git.shin.adfree.model.parseRule
import git.shin.adfree.model.ruleMatchesRequest
import git.shin.adfree.ui.theme.AdGuardDarkOutline
import git.shin.adfree.ui.theme.AdGuardDarkSurface
import git.shin.adfree.ui.theme.AdGuardDarkSurfaceVariant
import git.shin.adfree.ui.theme.AdGuardGreenLight
import git.shin.adfree.ui.theme.AdGuardGreenPrimary
import git.shin.adfree.ui.theme.AdGuardOnAccent
import git.shin.adfree.ui.theme.AdGuardRedBlocked
import git.shin.adfree.ui.theme.AdGuardTextMuted
import git.shin.adfree.ui.theme.AdGuardTextPrimary
import git.shin.adfree.ui.theme.AdGuardTextSecondary

/**
 * AdGuard for Windows' "add rule" dialog, in this app's clothes: choose what
 * the rule does, say what it matches, hang conditions off it, and read the
 * finished line before saving.
 *
 * The line is assembled, not typed — the controls own the modifiers, so a rule
 * cannot come out half-written — but anything the builder has no control for
 * (a `$redirect`, an imported `$removeparam`) rides along as a token instead of
 * being dropped on save. That is what makes editing an existing rule safe.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun RuleBuilderSheet(
    title: String,
    initialRule: String = "",
    existingRules: List<String> = emptyList(),
    /** The request the log has open, when this was opened from one. */
    previewHost: String? = null,
    previewUrl: String? = null,
    previewType: String? = null,
    onSave: (String) -> Unit,
    onCancel: () -> Unit,
) {
    val parsedInitial = remember(initialRule) { parseRule(initialRule) }
    val controlled = remember(initialRule) {
        RULE_FLAG_MODIFIERS.map { it.token } + RULE_TYPE_MODIFIERS.map { it.token }
    }
    // Modifiers this sheet does not draw stay in the line verbatim.
    val leftover = remember(initialRule) {
        parsedInitial.modifiers.filter { token ->
            val name = token.substringBefore('=').removePrefix("~").lowercase()
            name !in controlled && name !in setOf("app", "domain")
        }
    }

    var decision by remember(initialRule) { mutableStateOf(parsedInitial.decision) }
    var pattern by remember(initialRule) { mutableStateOf(parsedInitial.pattern) }
    var flags by remember(initialRule) {
        mutableStateOf(RULE_FLAG_MODIFIERS.map { it.token }.filter { parsedInitial.has(it) }.toSet())
    }
    var types by remember(initialRule) {
        mutableStateOf(RULE_TYPE_MODIFIERS.map { it.token }.filter { parsedInitial.has(it) }.toSet())
    }
    var app by remember(initialRule) { mutableStateOf(parsedInitial.appScope.orEmpty()) }
    var domain by remember(initialRule) { mutableStateOf(parsedInitial.domainScope.orEmpty()) }
    var notice by remember { mutableStateOf<String?>(null) }

    val rule = buildRule(
        decision = decision,
        pattern = pattern,
        flags = flags,
        types = types,
        app = app.takeIf { it.isNotBlank() },
        domainScope = domain.takeIf { it.isNotBlank() },
        extraTokens = leftover,
    )
    val parsed = parseRule(rule)
    val matchesOpenRequest = remember(rule, previewHost, previewUrl, previewType) {
        previewHost != null && parsed.valid && ruleMatchesRequest(
            rule = rule,
            host = previewHost,
            url = previewUrl,
            requestType = previewType,
        )
    }

    fun errorText(error: RuleError): String = when (error) {
        RuleError.Empty -> L10n.get(Strings.rule_error_empty)
        RuleError.Pattern -> L10n.get(Strings.rule_error_pattern)
        RuleError.Regex -> L10n.get(Strings.rule_error_regex)
        RuleError.Cosmetic -> L10n.get(Strings.rule_error_cosmetic)
        is RuleError.UnknownModifier -> L10n.format(Strings.rule_error_unknown_modifier, error.argument)
        is RuleError.MissingValue -> L10n.format(Strings.rule_error_missing_value, error.argument)
    }

    fun save() {
        val error = parsed.error
        notice = when {
            error != null -> errorText(error)
            rule in existingRules && rule != initialRule -> L10n.get(Strings.rules_exists)
            else -> null
        }
        if (notice == null) onSave(rule)
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 14.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = title,
                fontSize = 16.sp,
                fontWeight = FontWeight.Black,
                color = AdGuardTextPrimary,
            )
            IconButton(onClick = onCancel) {
                Icon(
                    Icons.Default.Close,
                    contentDescription = L10n.get(Strings.common_close),
                    tint = AdGuardTextSecondary,
                )
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        SectionLabel(L10n.get(Strings.rule_builder_decision))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            DecisionChip(
                label = L10n.get(Strings.rule_builder_decision_block),
                selected = decision == RuleDecision.BLOCK,
                tint = AdGuardRedBlocked,
                onClick = {
                    decision = RuleDecision.BLOCK
                    notice = null
                },
            )
            DecisionChip(
                label = L10n.get(Strings.rule_builder_decision_allow),
                selected = decision == RuleDecision.ALLOW,
                tint = AdGuardGreenLight,
                onClick = {
                    decision = RuleDecision.ALLOW
                    notice = null
                },
            )
        }

        Spacer(modifier = Modifier.height(14.dp))

        SectionLabel(L10n.get(Strings.rule_builder_pattern))
        OutlinedTextField(
            value = pattern,
            onValueChange = {
                pattern = it
                notice = null
            },
            singleLine = true,
            placeholder = {
                Text(
                    text = L10n.get(Strings.rule_builder_pattern_hint),
                    color = AdGuardTextMuted,
                    fontSize = 12.sp,
                )
            },
            modifier = Modifier
                .fillMaxWidth()
                .testTag("rule_builder_pattern"),
            shape = RoundedCornerShape(10.dp),
            textStyle = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 13.sp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedContainerColor = AdGuardDarkSurfaceVariant,
                unfocusedContainerColor = AdGuardDarkSurfaceVariant,
                focusedBorderColor = AdGuardGreenPrimary,
                unfocusedBorderColor = AdGuardDarkOutline,
                focusedTextColor = AdGuardTextPrimary,
                unfocusedTextColor = AdGuardTextPrimary,
            ),
        )

        if (pattern.isBlank()) {
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = L10n.get(Strings.rule_builder_templates),
                fontSize = 11.sp,
                color = AdGuardTextMuted,
            )
            Spacer(modifier = Modifier.height(4.dp))
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                TemplateButton(L10n.get(Strings.rule_builder_template_domain)) {
                    decision = RuleDecision.BLOCK
                    types = emptySet()
                    flags = flags - "third-party"
                    pattern = "example.com"
                }
                TemplateButton(L10n.get(Strings.rule_builder_template_path)) {
                    decision = RuleDecision.BLOCK
                    pattern = "||example.com/ads/*"
                }
                TemplateButton(L10n.get(Strings.rule_builder_template_allow)) {
                    decision = RuleDecision.ALLOW
                    pattern = "example.com"
                }
                TemplateButton(L10n.get(Strings.rule_builder_template_third_party)) {
                    decision = RuleDecision.BLOCK
                    flags = flags + "third-party"
                    pattern = "||example.com^"
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        SectionLabel(L10n.get(Strings.rule_builder_flags))
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            for (flag in RULE_FLAG_MODIFIERS) {
                ToggleChip(
                    label = L10n.get(flag.labelKey),
                    selected = flag.token in flags,
                    tint = AdGuardGreenLight,
                    tag = "rule_builder_flag_${flag.token}",
                ) {
                    flags = if (flag.token in flags) flags - flag.token else flags + flag.token
                    notice = null
                }
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        SectionLabel(L10n.get(Strings.rule_builder_types))
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            for (type in RULE_TYPE_MODIFIERS) {
                ToggleChip(
                    label = L10n.get(type.labelKey),
                    selected = type.token in types,
                    tint = AdGuardGreenLight,
                    tag = "rule_builder_type_${type.token}",
                ) {
                    types = if (type.token in types) types - type.token else types + type.token
                    notice = null
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        SectionLabel(L10n.get(Strings.rule_builder_scope))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ScopeField(
                value = app,
                label = L10n.get(Strings.rule_builder_app_label),
                hint = L10n.get(Strings.rule_builder_app_hint),
                tag = "rule_builder_app",
                modifier = Modifier.weight(1f),
            ) {
                app = it
                notice = null
            }
            ScopeField(
                value = domain,
                label = L10n.get(Strings.rule_builder_domain_label),
                hint = L10n.get(Strings.rule_builder_domain_hint),
                tag = "rule_builder_domain",
                modifier = Modifier.weight(1f),
            ) {
                domain = it
                notice = null
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        SectionLabel(L10n.get(Strings.rule_builder_preview))
        RulePreview(rule = rule, valid = parsed.valid)

        if (parsed.valid) {
            // The line itself is for reading once; this is the sentence that
            // says what it will do, the way AdGuard's dialog does above its
            // rule field.
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = describeInWords(parsed),
                fontSize = 11.sp,
                color = AdGuardTextSecondary,
                modifier = Modifier.testTag("rule_builder_summary"),
            )
        }

        val message = notice ?: parsed.error?.let { errorText(it) }
        if (message != null) {
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = message,
                fontSize = 12.sp,
                color = AdGuardRedBlocked,
                modifier = Modifier.testTag("rule_builder_error"),
            )
        }

        if (previewHost != null && parsed.valid) {
            Spacer(modifier = Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = if (matchesOpenRequest) Icons.Default.Check else Icons.Default.Close,
                    contentDescription = null,
                    tint = if (matchesOpenRequest) AdGuardGreenLight else AdGuardTextMuted,
                    modifier = Modifier.size(14.dp),
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = if (matchesOpenRequest) {
                        L10n.get(Strings.rule_builder_matches)
                    } else {
                        L10n.get(Strings.rule_builder_no_match)
                    },
                    fontSize = 11.sp,
                    color = if (matchesOpenRequest) AdGuardGreenLight else AdGuardTextMuted,
                )
            }
        }

        Spacer(modifier = Modifier.height(18.dp))

        Button(
            onClick = { save() },
            enabled = parsed.valid && pattern.isNotBlank(),
            colors = ButtonDefaults.buttonColors(
                containerColor = AdGuardGreenPrimary,
                disabledContainerColor = AdGuardDarkSurfaceVariant,
            ),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 48.dp)
                .testTag("rule_builder_save"),
        ) {
            Icon(Icons.Default.Add, contentDescription = null, tint = AdGuardOnAccent)
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = L10n.get(Strings.rule_builder_save),
                color = AdGuardOnAccent,
                fontWeight = FontWeight.Bold,
                fontSize = 14.sp,
            )
        }

        TextButton(onClick = onCancel, modifier = Modifier.fillMaxWidth()) {
            Text(L10n.get(Strings.common_cancel), color = AdGuardTextSecondary, fontSize = 13.sp)
        }
    }
}

/**
 * What the assembled rule will do, in a sentence: "Block • third party only •
 * Image, Script only • in chrome".
 */
private fun describeInWords(parsed: ParsedRule): String {
    val described = describeRule(parsed)
    val typeLabels = described.types.map { token ->
        RULE_TYPE_MODIFIERS.firstOrNull { it.token.equals(token, ignoreCase = true) }
            ?.let { L10n.get(it.labelKey) } ?: token
    }
    return buildList {
        add(
            L10n.get(
                if (described.blocked) Strings.rule_builder_decision_block else Strings.rule_builder_decision_allow,
            ),
        )
        if (described.thirdParty) add(L10n.get(Strings.rule_flag_third_party))
        if (described.matchCase) add(L10n.get(Strings.rule_flag_match_case))
        if (typeLabels.isNotEmpty()) {
            add(L10n.format(Strings.rule_builder_summary_types, typeLabels.joinToString(", ")))
        }
        described.app?.let { add(L10n.format(Strings.rule_builder_summary_app, it)) }
        described.domainScope?.let { add(L10n.format(Strings.rule_builder_summary_sites, it)) }
    }.joinToString(" • ")
}

@Composable
private fun SectionLabel(text: String) {
    Text(
        text = text,
        fontSize = 11.sp,
        fontWeight = FontWeight.Bold,
        color = AdGuardTextMuted,
        letterSpacing = 0.06.sp,
        modifier = Modifier.padding(bottom = 6.dp),
    )
}

@Composable
private fun DecisionChip(
    label: String,
    selected: Boolean,
    tint: androidx.compose.ui.graphics.Color,
    onClick: () -> Unit,
) {
    Text(
        text = label,
        fontSize = 12.sp,
        fontWeight = FontWeight.Bold,
        color = if (selected) AdGuardOnAccent else AdGuardTextSecondary,
        modifier = Modifier
            .clip(RoundedCornerShape(8.dp))
            .background(if (selected) tint else AdGuardDarkSurfaceVariant)
            .border(1.dp, if (selected) tint else AdGuardDarkOutline, RoundedCornerShape(8.dp))
            .clickable { onClick() }
            .padding(horizontal = 14.dp, vertical = 7.dp),
    )
}

@Composable
private fun ToggleChip(
    label: String,
    selected: Boolean,
    tint: androidx.compose.ui.graphics.Color,
    tag: String,
    onClick: () -> Unit,
) {
    Text(
        text = label,
        fontSize = 11.sp,
        fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium,
        color = if (selected) tint else AdGuardTextMuted,
        modifier = Modifier
            .clip(RoundedCornerShape(7.dp))
            .background(if (selected) AdGuardDarkSurface else AdGuardDarkSurfaceVariant)
            .border(1.dp, if (selected) tint.copy(alpha = 0.6f) else AdGuardDarkOutline, RoundedCornerShape(7.dp))
            .clickable { onClick() }
            .padding(horizontal = 9.dp, vertical = 5.dp)
            .testTag(tag),
    )
}

@Composable
private fun TemplateButton(label: String, onClick: () -> Unit) {
    Text(
        text = label,
        fontSize = 11.sp,
        color = AdGuardGreenLight,
        modifier = Modifier
            .clip(RoundedCornerShape(7.dp))
            .border(1.dp, AdGuardDarkOutline, RoundedCornerShape(7.dp))
            .clickable { onClick() }
            .padding(horizontal = 9.dp, vertical = 5.dp),
    )
}

@Composable
private fun ScopeField(
    value: String,
    label: String,
    hint: String,
    tag: String,
    modifier: Modifier = Modifier,
    onChange: (String) -> Unit,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        singleLine = true,
        placeholder = { Text(hint, color = AdGuardTextMuted, fontSize = 11.sp) },
        label = { Text(label, color = AdGuardTextMuted, fontSize = 11.sp) },
        modifier = modifier.testTag(tag),
        shape = RoundedCornerShape(10.dp),
        textStyle = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 12.sp),
        colors = OutlinedTextFieldDefaults.colors(
            focusedContainerColor = AdGuardDarkSurfaceVariant,
            unfocusedContainerColor = AdGuardDarkSurfaceVariant,
            focusedBorderColor = AdGuardGreenPrimary,
            unfocusedBorderColor = AdGuardDarkOutline,
            focusedTextColor = AdGuardTextPrimary,
            unfocusedTextColor = AdGuardTextPrimary,
        ),
    )
}

/**
 * The finished line, with its modifiers in the accent colour: the point of the
 * preview is that the user can see which half of the rule each control wrote.
 */
@Composable
private fun RulePreview(rule: String, valid: Boolean) {
    val separator = rule.indexOf('$')
    val base = if (separator < 0) rule else rule.substring(0, separator)
    val options = if (separator < 0) "" else rule.substring(separator)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(AdGuardDarkSurface)
            .border(1.dp, AdGuardDarkOutline, RoundedCornerShape(10.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp)
            .testTag("rule_builder_preview"),
    ) {
        Text(
            text = base.ifEmpty { "…" },
            fontSize = 12.sp,
            fontFamily = FontFamily.Monospace,
            color = if (valid) AdGuardTextPrimary else AdGuardTextMuted,
        )
        if (options.isNotEmpty()) {
            Text(
                text = options,
                fontSize = 12.sp,
                fontFamily = FontFamily.Monospace,
                color = AdGuardGreenLight,
            )
        }
    }
}