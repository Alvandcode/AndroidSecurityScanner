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
fun fileVerdictText(v: com.alvand.securityscanner.scanner.FileVerdict) = when (v) {
    com.alvand.securityscanner.scanner.FileVerdict.SAFE -> stringResource(R.string.healthy)
    com.alvand.securityscanner.scanner.FileVerdict.REVIEW -> stringResource(R.string.suspicious)
    else -> stringResource(R.string.infected)
}

@Composable
fun FilesScreen(vm: ScanViewModel) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var query by remember { mutableStateOf("") }
    var onlyThreats by remember { mutableStateOf(true) }
    var toast by remember { mutableStateOf<String?>(null) }
    val cloud by ctx.dataStore.data.map { it[PrefsKeys.CLOUD] == true }.collectAsState(false)
    val vtKey by ctx.dataStore.data.map { it[PrefsKeys.VT_KEY] ?: "" }.collectAsState("")
    val vtResults = remember { mutableStateMapOf<String, String>() }
    // Per-file busy flag: checking one file must not disable the others.
    val vtChecking = remember { mutableStateMapOf<String, Boolean>() }
    val treeLauncher = androidx.activity.compose.rememberLauncherForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.OpenDocumentTree()
    ) { uri ->
        if (uri != null) {
            try {
                com.alvand.securityscanner.scanner.takePersistableTree(ctx, uri)
                val s = uri.toString()
                vm.setTreeUri(s)
                scope.launch { ctx.dataStore.edit { it[PrefsKeys.FILE_TREE] = s } }
            } catch (_: Exception) { }
        }
    }
    val files = vm.fileFindings.value
    val safe = files.count { it.verdict == com.alvand.securityscanner.scanner.FileVerdict.SAFE }
    val review = files.count { it.verdict == com.alvand.securityscanner.scanner.FileVerdict.REVIEW }
    val danger = files.count { it.verdict == com.alvand.securityscanner.scanner.FileVerdict.DANGEROUS }

    LazyColumn(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            GlassCard(Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.files_scanned), fontSize = 14.sp, fontWeight = FontWeight.Bold)
                Text(stringResource(R.string.file_scope_note), fontSize = 12.sp)
                Spacer(Modifier.height(8.dp))
                if (vm.fileTreeUri.value == null) {
                    Text(stringResource(R.string.no_folder), fontSize = 12.sp)
                    Spacer(Modifier.height(6.dp))
                    Button(onClick = { try { treeLauncher.launch(null) } catch (_: Exception) { } }, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.pick_folder))
                    }
                } else {
                    Text("${stringResource(R.string.folder_Chosen)} ✓", fontSize = 12.sp)
                    // Primary: Scan All. Secondary: files only.
                    Button(onClick = { vm.scanAll(ctx) },
                        enabled = !vm.fileScanning.value && !vm.unifiedScanning.value && !vm.scanning.value,
                        modifier = Modifier.fillMaxWidth()) {
                        Text(if (vm.unifiedScanning.value) stringResource(R.string.scanning) else "◉ " + stringResource(R.string.scan_all))
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = {
                            vm.fileTreeUri.value?.let { vm.scanFiles(ctx, it) }
                        }, enabled = !vm.fileScanning.value && !vm.unifiedScanning.value, modifier = Modifier.weight(1f)) {
                            Text(if (vm.fileScanning.value) stringResource(R.string.scanning) else stringResource(R.string.scan_files))
                        }
                        OutlinedButton(onClick = { try { treeLauncher.launch(null) } catch (_: Exception) { } }) {
                            Text(stringResource(R.string.change_folder))
                        }
                    }
                    if (vm.fileScanning.value || vm.unifiedScanning.value) {
                        Spacer(Modifier.height(6.dp))
                        LinearProgressIndicator(
                            if (vm.unifiedScanning.value) vm.unifiedProgress.value else vm.fileProgress.value,
                            Modifier.fillMaxWidth()
                        )
                        val stage = if (vm.unifiedScanning.value && vm.unifiedStage.value.isNotBlank()) vm.unifiedStage.value else vm.fileCurrent.value
                        Text(stage, fontSize = 11.sp)
                    }
                    if (vm.vtSummary.value != null) Text(vm.vtSummary.value!!, fontSize = 12.sp)
                }
            }
        }
        if (files.isNotEmpty()) {
            item {
                GlassCard(Modifier.fillMaxWidth()) {
                    // Report: سالم / مشکوک / آلوده
                    Text(
                        "${stringResource(R.string.healthy)}: $safe   •   " +
                                "${stringResource(R.string.suspicious)}: $review   •   " +
                                "${stringResource(R.string.infected)}: $danger",
                        fontWeight = FontWeight.Bold, fontSize = 14.sp
                    )
                    if (vm.fileTruncated.value) Text(stringResource(R.string.truncated_2), fontSize = 11.sp)
                    Spacer(Modifier.height(6.dp))
                    OutlinedTextField(
                        value = query, onValueChange = { query = it },
                        label = { Text(stringResource(R.string.search_files)) },
                        singleLine = true, modifier = Modifier.fillMaxWidth()
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = onlyThreats, onCheckedChange = { onlyThreats = it })
                        Text(stringResource(R.string.only_threats), fontSize = 12.sp)
                    }
                }
            }
        }
        val base = files
            .filter {
                if (onlyThreats) it.verdict != com.alvand.securityscanner.scanner.FileVerdict.SAFE else true
            }
            .filter { if (query.isBlank()) true else it.displayName.contains(query, true) }
        if (base.isEmpty() && files.isNotEmpty() && !vm.fileScanning.value) {
            item { GlassCard(Modifier.fillMaxWidth()) { Text(stringResource(R.string.no_threats)) } }
        }
        items(base.take(200), key = { it.uriString }) { f ->
            val fglow = when (f.verdict) {
                com.alvand.securityscanner.scanner.FileVerdict.DANGEROUS -> com.alvand.securityscanner.ui.GlowDanger
                com.alvand.securityscanner.scanner.FileVerdict.REVIEW -> com.alvand.securityscanner.ui.GlowWarn
                else -> com.alvand.securityscanner.ui.GlowSafe
            }
            com.alvand.securityscanner.ui.GlowCard(
                glow = fglow,
                pulse = f.verdict == com.alvand.securityscanner.scanner.FileVerdict.REVIEW,
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    com.alvand.securityscanner.ui.FileGlyph(f.isApk, Modifier.size(40.dp))
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(f.displayName, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                    Text(
                        "${com.alvand.securityscanner.scanner.FileScanner.displaySize(f.size)} • ${f.score}/100 • " + fileVerdictText(f.verdict),
                        fontSize = 12.sp
                    )
                    if (f.reasons.isNotEmpty())
                        Text("${stringResource(R.string.reasons)}: " + f.reasons.take(6).joinToString(", "), fontSize = 11.sp)
                    if (f.sha256 != null) Text("SHA: ${f.sha256.take(16)}…", fontSize = 11.sp)
                    if (f.apkPackage != null) Text("pkg: ${f.apkPackage}", fontSize = 11.sp)
                    // Opt-in VirusTotal per file (SHA only, cached, rate-limited).
                    val vtRes = vtResults[f.uriString]
                    if (cloud && vtKey.isNotBlank() && f.sha256 != null &&
                        f.verdict != com.alvand.securityscanner.scanner.FileVerdict.SAFE
                    ) {
                        if (vtRes != null) Text("VirusTotal: $vtRes", fontSize = 11.sp)
                        TextButton(onClick = {
                            val sha = f.sha256 ?: return@TextButton
                            scope.launch {
                                vtChecking[f.uriString] = true
                                vtResults[f.uriString] = try {
                                    com.alvand.securityscanner.scanner.lookupVirusTotalCached(sha, vtKey)
                                        ?: "error/offline"
                                } catch (_: Exception) { "error/offline" }
                                vtChecking.remove(f.uriString)
                            }
                        }, enabled = vtChecking[f.uriString] != true) {
                            Text(if (vtChecking[f.uriString] == true) "…" else stringResource(R.string.check_online))
                        }
                    }
                    Spacer(Modifier.height(6.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        // User decides: open / delete. We never auto-delete.
                        TextButton(onClick = {
                            try {
                                val uri = Uri.parse(f.uriString)
                                val open = Intent(Intent.ACTION_VIEW).apply {
                                    setDataAndType(uri, f.mime ?: "*/*")
                                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                }
                                ctx.startActivity(Intent.createChooser(open, f.displayName))
                            } catch (_: Exception) { toast = f.displayName }
                        }) { Text(stringResource(R.string.open)) }
                        TextButton(onClick = {
                            val ok = com.alvand.securityscanner.scanner.FileScanner.deleteByUri(ctx, f.uriString)
                            toast = if (ok) ctx.getString(R.string.deleted) else ctx.getString(R.string.delete_failed)
                            if (ok) {
                                vm.fileFindings.value = vm.fileFindings.value.filter { it.uriString != f.uriString }
                            }
                        }) { Text(stringResource(R.string.delete)) }
                        }
                    }
                }
            }
        }
    }
    toast?.let {
        LaunchedEffect(it) {
            try { android.widget.Toast.makeText(ctx, it, android.widget.Toast.LENGTH_SHORT).show() } catch (_: Exception) { }
            toast = null
        }
    }
}

