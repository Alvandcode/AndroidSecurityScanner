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
fun HistoryList(vm: ScanViewModel) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var confirmClear by remember { mutableStateOf(false) }
    val lastScore by ctx.dataStore.data.map { it[PrefsKeys.LAST_SCORE] }.collectAsState(null)
    val lastScan by ctx.dataStore.data.map { it[PrefsKeys.LAST_SCAN] }.collectAsState(null)
    val records by remember(ctx) { com.alvand.securityscanner.data.HistoryDb.get(ctx).dao().recent() }
        .collectAsState(emptyList())
    val fmt = remember { SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US) }
    LazyColumn(Modifier.fillMaxSize().padding(horizontal = 20.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            Text(stringResource(R.string.history), fontSize = 26.sp, fontWeight = FontWeight.Bold, color = com.alvand.securityscanner.ui.TextPrimary())
        }
        item {
            GlassCard(Modifier.fillMaxWidth()) {
                Text("${stringResource(R.string.last_scan)}: ${lastScan ?: stringResource(R.string.never)}", color = com.alvand.securityscanner.ui.TextPrimary())
                Text("${stringResource(R.string.device_score)}: ${lastScore ?: "--"}", fontSize = 13.sp, color = com.alvand.securityscanner.ui.TextSecondary())
                Spacer(Modifier.height(8.dp))
                TextButton(onClick = { confirmClear = true }, enabled = records.isNotEmpty()) {
                    Icon(Icons.Default.DeleteOutline, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(stringResource(R.string.clear_history), fontSize = 13.sp)
                }
            }
        }
        if (records.isEmpty()) {
            item { GlassCard(Modifier.fillMaxWidth()) { Text(stringResource(R.string.no_history), color = com.alvand.securityscanner.ui.TextSecondary()) } }
        }
        items(records) { r ->
            GlassCard(Modifier.fillMaxWidth()) {
                Text("${fmt.format(Date(r.timestamp))} — ${r.deviceScore}/100", fontWeight = FontWeight.SemiBold, color = com.alvand.securityscanner.ui.TextPrimary())
                Text("${stringResource(R.string.apps_scanned)}: ${r.appsScanned} • ${stringResource(R.string.threats)}: ${r.threats}", fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary())
                if (r.filesScanned > 0) {
                    Text(
                        "${stringResource(R.string.files_scanned)}: ${r.filesScanned} • " +
                                "${stringResource(R.string.suspicious)}/${stringResource(R.string.infected)}: ${r.fileThreats}",
                        fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary()
                    )
                }
                if (r.summary.isNotBlank()) Text(r.summary.take(300), fontSize = 11.sp, color = com.alvand.securityscanner.ui.TextSecondary())
                if (r.fileSummary.isNotBlank()) Text(r.fileSummary.take(300), fontSize = 11.sp, color = com.alvand.securityscanner.ui.TextSecondary())
            }
        }
    }
    if (confirmClear) {
        AlertDialog(
            onDismissRequest = { confirmClear = false },
            title = { Text(stringResource(R.string.clear_history), fontWeight = FontWeight.Bold) },
            text = { Text(stringResource(R.string.clear_history_confirm)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmClear = false
                    scope.launch {
                        try { com.alvand.securityscanner.data.HistoryDb.get(ctx).dao().clearAll() } catch (_: Exception) { }
                    }
                }) { Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { confirmClear = false }) { Text(stringResource(R.string.close)) }
            }
        )
    }
}

