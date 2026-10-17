package git.shin.adfree.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Extension
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import git.shin.adfree.model.UserScriptInfo
import git.shin.adfree.ui.theme.AdGuardBlueDns
import git.shin.adfree.ui.theme.AdGuardDarkOutline
import git.shin.adfree.ui.theme.AdGuardDarkSurface
import git.shin.adfree.ui.theme.AdGuardDarkSurfaceVariant
import git.shin.adfree.ui.theme.AdGuardGreenLight
import git.shin.adfree.ui.theme.AdGuardGreenPrimary
import git.shin.adfree.ui.theme.AdGuardPurpleAI
import git.shin.adfree.ui.theme.AdGuardRedBlocked
import git.shin.adfree.ui.theme.AdGuardTextMuted
import git.shin.adfree.ui.theme.AdGuardTextPrimary
import git.shin.adfree.ui.theme.AdGuardTextSecondary

/**
 * The Extensions block of the "Bộ lọc" tab: userscripts that run on every page
 * we terminate TLS for, behind a single master switch.
 *
 * A script is only pushed to the core once its body is on disk, so the same
 * switch silently downloads a catalogue entry the first time it is turned on.
 */
@Composable
fun ExtensionsSection(
    scripts: List<UserScriptInfo>,
    masterEnabled: Boolean,
    onToggleMaster: (Boolean) -> Unit,
    onToggleScript: (UserScriptInfo, Boolean) -> Unit,
    onOpenScript: (UserScriptInfo) -> Unit,
    onAddScript: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("extensions_section"),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = AdGuardDarkSurface),
        border = BorderStroke(1.dp, AdGuardDarkOutline),
    ) {
        Column {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(14.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Box(
                    modifier = Modifier
                        .size(38.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(AdGuardPurpleAI.copy(alpha = 0.12f)),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(Icons.Default.Extension, contentDescription = null, tint = AdGuardPurpleAI, modifier = Modifier.size(20.dp))
                }
                Spacer(modifier = Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text("Tiện ích", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = AdGuardTextPrimary)
                    Text(
                        "Script chạy trên mọi trang web đã lọc",
                        fontSize = 10.sp,
                        color = AdGuardTextMuted,
                    )
                }
                Switch(
                    checked = masterEnabled,
                    onCheckedChange = { onToggleMaster(it) },
                    colors = SwitchDefaults.colors(checkedTrackColor = AdGuardGreenPrimary),
                )
            }

            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(1.dp)
                    .background(AdGuardDarkOutline),
            )

            if (scripts.isEmpty()) {
                Text(
                    text = "Chưa có tiện ích nào. Thêm một userscript (.user.js) để bắt đầu.",
                    fontSize = 11.sp,
                    color = AdGuardTextMuted,
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
                )
            } else {
                for (script in scripts) {
                    ScriptRow(
                        script = script,
                        onToggle = { onToggleScript(script, !script.isEnabled) },
                        onClick = { onOpenScript(script) },
                    )
                }
            }

            TextButton(
                onClick = onAddScript,
                modifier = Modifier
                    .padding(start = 6.dp, bottom = 4.dp)
                    .testTag("add_script_btn"),
            ) {
                Icon(Icons.Default.Add, contentDescription = null, tint = AdGuardGreenLight, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text("Thêm tiện ích", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = AdGuardGreenLight)
            }
        }
    }
}

@Composable
private fun ScriptRow(
    script: UserScriptInfo,
    onToggle: () -> Unit,
    onClick: () -> Unit,
) {
    val meta = if (script.sizeBytes > 0) {
        "${script.sizeBytes / 1024} KB • ${script.lastUpdatedText}"
    } else {
        "Chưa tải • Bật để tải về"
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() }
            .padding(start = 14.dp, end = 8.dp, top = 6.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = script.name,
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold,
                color = AdGuardTextPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(text = meta, fontSize = 10.sp, color = AdGuardTextMuted)
        }
        Switch(
            checked = script.isEnabled,
            onCheckedChange = { onToggle() },
            colors = SwitchDefaults.colors(checkedTrackColor = AdGuardGreenPrimary),
        )
    }
}

/** Dialog for adding a userscript by URL. */
@Composable
fun AddScriptDialog(
    onDismiss: () -> Unit,
    onAdd: (String, String) -> Unit,
) {
    var name by remember { mutableStateOf("") }
    var url by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Extension, contentDescription = null, tint = AdGuardPurpleAI, modifier = Modifier.size(22.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text("Thêm tiện ích", fontSize = 17.sp, fontWeight = FontWeight.Bold, color = AdGuardTextPrimary)
            }
        },
        text = {
            Column {
                Text(
                    text = "Dán đường dẫn tới tệp userscript (.user.js). Tiện ích chỉ chạy khi lọc HTTPS được bật.",
                    fontSize = 12.sp,
                    color = AdGuardTextSecondary,
                )
                Spacer(modifier = Modifier.height(12.dp))
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Tên (không bắt buộc)", fontSize = 12.sp) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = AdGuardGreenPrimary,
                        unfocusedBorderColor = AdGuardDarkOutline,
                        focusedTextColor = AdGuardTextPrimary,
                        unfocusedTextColor = AdGuardTextPrimary,
                    ),
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = url,
                    onValueChange = { url = it },
                    label = { Text("Đường dẫn (.user.js)", fontSize = 12.sp) },
                    placeholder = { Text("https://…", fontSize = 12.sp, color = AdGuardTextMuted) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = AdGuardGreenPrimary,
                        unfocusedBorderColor = AdGuardDarkOutline,
                        focusedTextColor = AdGuardTextPrimary,
                        unfocusedTextColor = AdGuardTextPrimary,
                    ),
                )
            }
        },
        confirmButton = {
            Button(
                onClick = { if (url.isNotBlank()) onAdd(name, url) },
                enabled = url.isNotBlank(),
                colors = ButtonDefaults.buttonColors(containerColor = AdGuardGreenPrimary),
                shape = RoundedCornerShape(8.dp),
            ) {
                Text("Thêm và tải", color = Color.Black, fontWeight = FontWeight.Bold)
            }
        },
        dismissButton = {
            OutlinedButton(onClick = onDismiss, shape = RoundedCornerShape(8.dp)) {
                Text("Hủy", color = AdGuardTextSecondary)
            }
        },
    )
}

/** Bottom sheet with everything we know about one userscript. */
@Composable
fun ScriptDetailSheet(
    script: UserScriptInfo,
    onToggle: () -> Unit,
    onRefresh: () -> Unit,
    onDelete: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp, vertical = 12.dp),
    ) {
        Text(script.name, fontSize = 16.sp, fontWeight = FontWeight.Black, color = AdGuardTextPrimary)
        if (script.description.isNotBlank()) {
            Spacer(modifier = Modifier.height(4.dp))
            Text(script.description, fontSize = 12.sp, color = AdGuardTextSecondary)
        }

        Spacer(modifier = Modifier.height(14.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text("Bật tiện ích này", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = AdGuardTextPrimary)
                Text(
                    text = if (script.isEnabled) "Đang chạy khi lọc HTTPS bật" else "Đang tắt",
                    fontSize = 11.sp,
                    color = AdGuardTextMuted,
                )
            }
            Switch(
                checked = script.isEnabled,
                onCheckedChange = { onToggle() },
                colors = SwitchDefaults.colors(checkedTrackColor = AdGuardGreenPrimary),
            )
        }

        Spacer(modifier = Modifier.height(12.dp))

        ScriptInfoRow("Kích thước", if (script.sizeBytes > 0) "${script.sizeBytes / 1024} KB" else "Chưa tải")
        ScriptInfoRow("Cập nhật", script.lastUpdatedText)

        Spacer(modifier = Modifier.height(6.dp))
        Text(
            text = script.url,
            fontSize = 9.sp,
            fontFamily = FontFamily.Monospace,
            color = AdGuardTextMuted,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )

        Spacer(modifier = Modifier.height(16.dp))

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onRefresh, shape = RoundedCornerShape(10.dp)) {
                Icon(Icons.Default.Sync, contentDescription = null, tint = AdGuardGreenLight, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text("Cập nhật", fontSize = 12.sp, color = AdGuardGreenLight)
            }
            if (script.isUserAdded) {
                OutlinedButton(onClick = onDelete, shape = RoundedCornerShape(10.dp)) {
                    Icon(Icons.Default.Delete, contentDescription = null, tint = AdGuardRedBlocked, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Xóa", fontSize = 12.sp, color = AdGuardRedBlocked)
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))
    }
}

@Composable
private fun ScriptInfoRow(label: String, value: String) {
    Row(modifier = Modifier
        .fillMaxWidth()
        .padding(vertical = 3.dp)) {
        Text(label, fontSize = 12.sp, color = AdGuardTextMuted, modifier = Modifier.width(110.dp))
        Text(value, fontSize = 12.sp, color = AdGuardTextPrimary, modifier = Modifier.weight(1f))
    }
}
