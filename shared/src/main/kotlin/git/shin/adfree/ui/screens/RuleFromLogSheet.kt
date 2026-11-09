package git.shin.adfree.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
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
import androidx.compose.material.icons.filled.AutoFixHigh
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.RadioButton
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
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.l10n.L10n
import git.shin.adfree.l10n.Strings
import git.shin.adfree.model.RuleDraftKind
import git.shin.adfree.model.RuleDraft
import git.shin.adfree.model.composeRuleText
import git.shin.adfree.model.ruleCandidates
import git.shin.adfree.model.userBlockRule
import git.shin.adfree.model.userWhitelistRule
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
 * AdGuard's "rule from log" screen: the rule is pre-filled from the request and
 * stays editable, so nothing is written to the user rules behind the user's back.
 */
@Composable
fun RuleFromLogSheetContent(
    draft: RuleDraft,
    appLabel: String?,
    existingRules: List<String>,
    onSubmit: (String) -> Unit,
    onCancel: () -> Unit,
) {
    val candidates = remember(draft) { ruleCandidates(draft.kind, draft.host) }
    val isBlock = draft.kind == RuleDraftKind.BLOCK
    val showPriority = isBlock
    val showAppScope = draft.appScopable

    var selectedIndex by remember { mutableIntStateOf(0) }
    var ruleText by remember { mutableStateOf(candidates.firstOrNull().orEmpty()) }
    var appScoped by remember { mutableStateOf(false) }
    var important by remember { mutableStateOf(false) }
    var handEdited by remember { mutableStateOf(false) }
    var notice by remember { mutableStateOf<String?>(null) }
    // The full builder, for a rule that needs more than the candidates above.
    var builderOpen by remember { mutableStateOf(false) }

    if (builderOpen) {
        RuleBuilderSheet(
            title = L10n.get(
                if (isBlock) Strings.rule_from_log_block_title else Strings.rule_from_log_allow_title,
            ),
            initialRule = ruleText,
            existingRules = existingRules,
            previewHost = draft.host,
            onSave = onSubmit,
            onCancel = { builderOpen = false },
        )
        return
    }

    fun applyToggles(base: String) =
        composeRuleText(draft.kind, base, draft.appPackage, appScoped, important)

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp)
            .padding(bottom = 24.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = L10n.get(if (isBlock) Strings.rule_from_log_block_title else Strings.rule_from_log_allow_title),
                fontSize = 17.sp,
                fontWeight = FontWeight.Bold,
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

        Spacer(modifier = Modifier.height(12.dp))

        Text(
            text = L10n.get(Strings.rule_from_log_rule_text),
            fontSize = 12.sp,
            color = AdGuardTextSecondary,
        )
        Spacer(modifier = Modifier.height(6.dp))
        OutlinedTextField(
            value = ruleText,
            onValueChange = {
                ruleText = it
                handEdited = true
                notice = null
            },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(10.dp),
            textStyle = androidx.compose.ui.text.TextStyle(
                fontFamily = FontFamily.Monospace,
                fontSize = 13.sp,
            ),
            trailingIcon = {
                IconButton(onClick = {
                    ruleText = ""
                    handEdited = false
                    notice = null
                }) {
                    Icon(
                        Icons.Default.Close,
                        contentDescription = L10n.get(Strings.common_clear),
                        tint = AdGuardTextMuted,
                    )
                }
            },
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

        // The candidates above cover the common case in one click; everything
        // AdGuard for Windows can express (types, third party, case, scope)
        // lives behind this.
        TextButton(
            onClick = { builderOpen = true },
            modifier = Modifier.testTag("rule_from_log_open_builder"),
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

        Spacer(modifier = Modifier.height(20.dp))

        Text(
            text = L10n.get(if (isBlock) Strings.rule_from_log_what_block else Strings.rule_from_log_what_allow),
            fontSize = 15.sp,
            fontWeight = FontWeight.Bold,
            color = AdGuardTextPrimary,
        )
        Spacer(modifier = Modifier.height(4.dp))
        candidates.forEachIndexed { index, candidate ->
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(
                    selected = index == selectedIndex,
                    onClick = {
                        selectedIndex = index
                        if (!handEdited) {
                            ruleText = applyToggles(candidate)
                        }
                        notice = null
                    },
                    colors = androidx.compose.material3.RadioButtonDefaults.colors(
                        selectedColor = AdGuardGreenPrimary,
                        unselectedColor = AdGuardTextSecondary,
                    ),
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = candidate,
                    fontSize = 13.sp,
                    fontFamily = FontFamily.Monospace,
                    color = AdGuardTextPrimary,
                )
            }
        }

        if (showPriority || showAppScope || (draft.appPackage != null && !draft.appScopable)) {
            Spacer(modifier = Modifier.height(20.dp))
            Text(
                text = L10n.get(Strings.rule_from_log_options),
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
                color = AdGuardTextPrimary,
            )
            Spacer(modifier = Modifier.height(4.dp))

            if (showPriority) {
                OptionCheckbox(
                    label = L10n.get(Strings.rule_from_log_priority),
                    checked = important,
                    onCheckedChange = {
                        important = it
                        ruleText = applyToggles(ruleText)
                        notice = null
                    },
                )
            }

            val scopedPackage = draft.appPackage
            if (showAppScope && scopedPackage != null) {
                OptionCheckbox(
                    label = L10n.format(Strings.rule_from_log_app_scope, appLabel ?: scopedPackage),
                    checked = appScoped,
                    onCheckedChange = {
                        appScoped = it
                        ruleText = applyToggles(ruleText)
                        notice = null
                    },
                )
            }

            // The core decides a DNS lookup before it knows which app asked, so
            // offering the modifier here would store a rule that never runs.
            if (!showAppScope && draft.appPackage != null) {
                Text(
                    text = L10n.get(Strings.rule_from_log_dns_note),
                    fontSize = 12.sp,
                    color = AdGuardTextMuted,
                    modifier = Modifier.padding(vertical = 8.dp),
                )
            }
        }

        notice?.let {
            Spacer(modifier = Modifier.height(10.dp))
            Text(text = it, fontSize = 12.sp, color = AdGuardRedBlocked)
        }

        Spacer(modifier = Modifier.height(24.dp))

        Button(
            onClick = {
                val rule = if (isBlock) userBlockRule(ruleText) else userWhitelistRule(ruleText)
                notice = when {
                    rule == null -> L10n.get(Strings.rules_invalid_rule)
                    rule in existingRules -> L10n.get(Strings.rules_exists)
                    else -> null
                }
                if (rule != null && notice == null) onSubmit(rule)
            },
            enabled = ruleText.isNotBlank(),
            colors = ButtonDefaults.buttonColors(containerColor = AdGuardGreenPrimary),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp),
        ) {
            Text(
                text = L10n.get(Strings.rule_from_log_add),
                color = AdGuardOnAccent,
                fontWeight = FontWeight.Bold,
                fontSize = 15.sp,
            )
        }

        TextButton(
            onClick = onCancel,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(L10n.get(Strings.common_cancel), color = AdGuardTextSecondary, fontSize = 13.sp)
        }
    }
}

@Composable
private fun OptionCheckbox(
    label: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .height(48.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Checkbox(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = CheckboxDefaults.colors(
                checkedColor = AdGuardGreenPrimary,
                uncheckedColor = AdGuardTextSecondary,
                checkmarkColor = AdGuardDarkSurface,
            ),
        )
        Spacer(modifier = Modifier.width(6.dp))
        Text(text = label, fontSize = 13.sp, color = AdGuardTextPrimary)
    }
}
