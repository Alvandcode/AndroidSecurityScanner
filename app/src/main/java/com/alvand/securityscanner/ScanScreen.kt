package com.alvand.securityscanner

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Surface
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.preferencesDataStore
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import com.alvand.securityscanner.data.PrefsKeys
import com.alvand.securityscanner.scanner.AppFinding
import com.alvand.securityscanner.scanner.AppScanner
import com.alvand.securityscanner.scanner.Verdict
import com.alvand.securityscanner.ui.AppTheme
import com.alvand.securityscanner.ui.GlassBackground
import com.alvand.securityscanner.ui.GlassCard
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.*

@Composable
fun EngineRow(icon: ImageVector, title: String, count: String, active: Boolean) {
    Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, contentDescription = null, tint = com.alvand.securityscanner.ui.TextSecondary(), modifier = Modifier.size(20.dp))
        Spacer(Modifier.width(10.dp))
        Text(title, fontSize = 14.sp, modifier = Modifier.weight(1f), color = com.alvand.securityscanner.ui.TextPrimary())
        if (active) {
            Text(stringResource(R.string.checking), fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary())
            Spacer(Modifier.width(6.dp))
            CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = com.alvand.securityscanner.ui.AccentBlue)
        } else {
            Text(count, fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary())
        }
    }
}

@Composable
fun ScanScreen(vm: ScanViewModel, onBack: () -> Unit) {
    val ctx = LocalContext.current
    val active = vm.unifiedScanning.value || vm.scanning.value || vm.fileScanning.value
    val appDanger = vm.findings.value.count { it.verdict == Verdict.DANGEROUS }
    val fileDanger = vm.fileFindings.value.count { it.verdict == com.alvand.securityscanner.scanner.FileVerdict.DANGEROUS }
    val threats = appDanger + fileDanger
    val scanned = vm.findings.value.size + vm.fileFindings.value.size
    var now by remember { mutableStateOf(System.currentTimeMillis()) }
    LaunchedEffect(active) {
        if (active) {
            while (true) {
                delay(1000)
                now = System.currentTimeMillis()
            }
        }
    }
    val secs = ((now - vm.scanStartMs.value) / 1000).coerceAtLeast(0)
    val time = "%02d:%02d".format(secs / 60, secs % 60)
    val prog = when {
        vm.unifiedScanning.value -> vm.unifiedProgress.value
        vm.scanning.value -> vm.progress.value
        vm.fileScanning.value -> vm.fileProgress.value
        else -> 0f
    }
    val stage = when {
        vm.unifiedScanning.value && vm.unifiedStage.value.isNotBlank() ->
            if (vm.unifiedStage.value == "catalog") stringResource(R.string.catalog_stage)
            else if (vm.unifiedStage.value == "vt") stringResource(R.string.vt_stage)
            else vm.unifiedStage.value
        vm.fileScanning.value && vm.fileCurrent.value.isNotBlank() -> vm.fileCurrent.value
        else -> ""
    }
    LazyColumn(
        Modifier.fillMaxSize().padding(horizontal = 20.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        item {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                IconButton(onClick = onBack) {
                    Icon(Icons.Default.ArrowBack, contentDescription = null, tint = com.alvand.securityscanner.ui.TextPrimary(), modifier = Modifier.size(26.dp))
                }
                Text(stringResource(R.string.full_scan), fontSize = 18.sp, fontWeight = FontWeight.SemiBold, color = com.alvand.securityscanner.ui.TextPrimary())
                IconButton(onClick = { }) {
                    Icon(Icons.Default.MoreVert, contentDescription = null, tint = com.alvand.securityscanner.ui.TextSecondary(), modifier = Modifier.size(24.dp))
                }
            }
        }
        item { Radar(active) }
        item {
            Text(
                if (active) stringResource(R.string.scanning)
                else if (threats > 0) "${stringResource(R.string.scan_complete)} — $threats ${stringResource(R.string.threats)}"
                else stringResource(R.string.no_threats),
                fontSize = 20.sp, fontWeight = FontWeight.Bold, color = com.alvand.securityscanner.ui.TextPrimary()
            )
            if (stage.isNotBlank()) {
                Spacer(Modifier.height(4.dp))
                Text(stage.take(48), fontSize = 12.sp, color = com.alvand.securityscanner.ui.AccentBlue)
            }
            Text("$scanned ${stringResource(R.string.scanned_label)}", fontSize = 13.sp, color = com.alvand.securityscanner.ui.TextSecondary())
        }
        item {
            GlassCard(Modifier.fillMaxWidth()) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    LinearProgressIndicator(
                        progress = { prog },
                        modifier = Modifier.weight(1f).height(6.dp),
                        color = com.alvand.securityscanner.ui.AccentBlue,
                        trackColor = com.alvand.securityscanner.ui.AccentBlue.copy(alpha = 0.12f)
                    )
                    Spacer(Modifier.width(10.dp))
                    Text("${(prog * 100).toInt()}%", fontSize = 13.sp, color = com.alvand.securityscanner.ui.AccentBlue, fontWeight = FontWeight.SemiBold)
                }
                Spacer(Modifier.height(14.dp))
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                    ScanStat("$threats", stringResource(R.string.threats))
                    ScanStat("$scanned", stringResource(R.string.scanned_label))
                    ScanStat(time, stringResource(R.string.time_label))
                }
            }
        }
        item {
            GlassCard(Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.scan_engine), fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = com.alvand.securityscanner.ui.TextPrimary())
                Spacer(Modifier.height(10.dp))
                EngineRow(Icons.Default.BugReport, stringResource(R.string.malware), "$threats", active)
                HorizontalDivider(Modifier.padding(vertical = 4.dp), color = com.alvand.securityscanner.ui.AccentBlue.copy(alpha = 0.08f))
                EngineRow(
                    Icons.Default.VerifiedUser, stringResource(R.string.privacy_risks),
                    "${vm.findings.value.count { it.verdict == Verdict.REVIEW } + vm.fileFindings.value.count { it.verdict == com.alvand.securityscanner.scanner.FileVerdict.REVIEW }}",
                    active
                )
            }
        }
        item {
            if (active) {
                Surface(
                    onClick = { vm.stopAll() },
                    modifier = Modifier.fillMaxWidth().height(56.dp),
                    color = com.alvand.securityscanner.ui.AccentBlue,
                    shape = RoundedCornerShape(18.dp)
                ) {
                    Row(Modifier.fillMaxSize(), horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Stop, contentDescription = null, tint = Color.White, modifier = Modifier.size(22.dp))
                        Spacer(Modifier.width(10.dp))
                        Text(stringResource(R.string.stop_scan), color = Color.White, fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
                    }
                }
            } else {
                Surface(
                    onClick = { vm.scanAll(ctx) },
                    modifier = Modifier.fillMaxWidth().height(56.dp),
                    color = com.alvand.securityscanner.ui.AccentBlue,
                    shape = RoundedCornerShape(18.dp)
                ) {
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Text(stringResource(R.string.new_scan), color = Color.White, fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
                    }
                }
            }
        }
    }
}

@Composable
fun WebScanDialog(onClose: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var url by remember { mutableStateOf("") }
    var res by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var err by remember { mutableStateOf<String?>(null) }
    val cloud by ctx.dataStore.data.map { it[PrefsKeys.CLOUD] == true }.collectAsState(false)
    val vtKey by ctx.dataStore.data.map { it[PrefsKeys.VT_KEY] ?: "" }.collectAsState("")
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text(stringResource(R.string.web_title), fontWeight = FontWeight.Bold) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = url, onValueChange = { url = it },
                    label = { Text(stringResource(R.string.web_hint)) },
                    singleLine = true, modifier = Modifier.fillMaxWidth()
                )
                if (!cloud || vtKey.isBlank()) Text(stringResource(R.string.cloud_desc), fontSize = 11.sp)
                if (err != null) Text(err!!, fontSize = 12.sp, color = MaterialTheme.colorScheme.error)
                if (res != null) Text("VirusTotal: $res", fontSize = 12.sp)
            }
        },
        confirmButton = {
            Button(onClick = {
                if (!url.trim().startsWith("http")) {
                    try { err = ctx.getString(R.string.enter_url_valid) } catch (_: Exception) { err = "!" }
                    return@Button
                }
                if (!cloud || vtKey.isBlank()) {
                    try { err = ctx.getString(R.string.cloud_lookup) } catch (_: Exception) { err = "!" }
                    return@Button
                }
                scope.launch {
                    busy = true; err = null
                    res = try {
                        com.alvand.securityscanner.scanner.lookupVirusTotalUrl(url.trim(), vtKey) ?: "error/offline"
                    } catch (_: Exception) { "error/offline" }
                    busy = false
                }
            }, enabled = !busy) { Text(if (busy) "…" else stringResource(R.string.check_online)) }
        },
        dismissButton = {
            TextButton(onClick = onClose) { Text(stringResource(R.string.close)) }
        }
    )
}

