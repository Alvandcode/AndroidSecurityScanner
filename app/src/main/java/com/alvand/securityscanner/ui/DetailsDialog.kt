package com.alvand.securityscanner.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.alvand.securityscanner.R
import com.alvand.securityscanner.dataStore
import com.alvand.securityscanner.data.PrefsKeys
import com.alvand.securityscanner.scanner.AppFinding
import com.alvand.securityscanner.scanner.ApkDetails
import com.alvand.securityscanner.scanner.loadApkDetails
import com.alvand.securityscanner.scanner.lookupVirusTotal
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

@Composable
fun DetailsDialog(f: AppFinding, onClose: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val clip = LocalClipboardManager.current
    var det by remember { mutableStateOf<ApkDetails?>(null) }
    var vt by remember { mutableStateOf<String?>(null) }
    var checking by remember { mutableStateOf(false) }
    val cloud by ctx.dataStore.data.map { it[PrefsKeys.CLOUD] == true }.collectAsState(false)
    val vtKey by ctx.dataStore.data.map { it[PrefsKeys.VT_KEY] ?: "" }.collectAsState("")

    LaunchedEffect(f.packageName) { det = loadApkDetails(ctx, f.packageName) }

    AlertDialog(
        onDismissRequest = onClose,
        title = { Text(f.appName, fontWeight = FontWeight.Bold) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(f.packageName, fontSize = 11.sp)
                Text("${f.score}/100")
                val installerFriendly = com.alvand.securityscanner.scanner.RiskEngine.installerLabel(f.installer)
                Text("${stringResource(R.string.installer)}: $installerFriendly (${f.installer ?: "?"})", fontSize = 12.sp)
                val target = det?.targetSdk
                Text(
                    "${stringResource(R.string.target_sdk)}: ${target ?: "…"} " +
                            if (target != null && target < 29 && !f.isSystemApp) "⚠️" else "",
                    fontSize = 12.sp
                )
                if (target != null && target < 29 && !f.isSystemApp) {
                    Text(stringResource(R.string.target_sdk_old_warn), fontSize = 11.sp)
                }
                Text("${stringResource(R.string.signatures)}: ${det?.signers ?: "…"}", fontSize = 12.sp)
                SelectionContainer {
                    Text("${stringResource(R.string.sha256)}:\n${det?.sha256 ?: "…"}", fontSize = 11.sp)
                }
                if (f.riskyPermissions.isNotEmpty())
                    Text(f.riskyPermissions.joinToString { it.name }, fontSize = 12.sp)
                if (cloud && vtKey.isNotBlank()) {
                    if (vt != null) Text("VirusTotal: $vt", fontSize = 12.sp)
                    Button(
                        onClick = {
                            val sha = det?.sha256 ?: return@Button
                            scope.launch {
                                checking = true
                                vt = lookupVirusTotal(sha, vtKey) ?: "error/offline"
                                checking = false
                            }
                        },
                        enabled = !checking && det?.sha256 != null
                    ) { Text(if (checking) "…" else stringResource(R.string.check_online)) }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                clip.setText(AnnotatedString(det?.sha256 ?: f.packageName))
            }) { Text(stringResource(R.string.copy)) }
        },
        dismissButton = {
            TextButton(onClick = onClose) { Text(stringResource(R.string.close)) }
        }
    )
}
