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

class ScanViewModel : ViewModel() {
    var findings = mutableStateOf<List<AppFinding>>(emptyList()); private set
    var scanning = mutableStateOf(false); private set
    var progress = mutableStateOf(0f); private set
    var deviceScore = mutableStateOf<Int?>(null); private set
    var health = mutableStateOf<com.alvand.securityscanner.scanner.DeviceHealth?>(null); private set
    var includeSystem = mutableStateOf(false); private set
    // Phase-3 file scan
    var fileFindings = mutableStateOf<List<com.alvand.securityscanner.scanner.FileFinding>>(emptyList()); private set
    var fileScanning = mutableStateOf(false); private set
    var fileProgress = mutableStateOf(0f); private set
    var fileCurrent = mutableStateOf(""); private set
    var fileTruncated = mutableStateOf(false); private set
    var fileTreeUri = mutableStateOf<String?>(null); private set
    // Phase-4 unified «اسکن همه»
    var unifiedScanning = mutableStateOf(false); private set
    var unifiedProgress = mutableStateOf(0f); private set
    var unifiedStage = mutableStateOf(""); private set
    var unifiedScore = mutableStateOf<Int?>(null); private set
    var vtSummary = mutableStateOf<String?>(null); private set
    var scanStartMs = mutableStateOf(0L); private set
    var catalog = mutableStateOf<com.alvand.securityscanner.scanner.CatalogData?>(null); private set
    private var appJob: Job? = null
    private var fileJob: Job? = null
    private var uniJob: Job? = null

    fun setTreeUri(uri: String?) { fileTreeUri.value = uri }

    /** Stop any running scan (Scan screen Stop button). Loops check ensureActive. */
    fun stopAll() {
        appJob?.cancel(); fileJob?.cancel(); uniJob?.cancel()
        scanning.value = false; fileScanning.value = false; unifiedScanning.value = false
    }

    fun scan(ctx: Context, withSystem: Boolean = includeSystem.value) {
        if (scanning.value) return
        includeSystem.value = withSystem
        appJob?.cancel()
        appJob = viewModelScope.launch {
            scanning.value = true; progress.value = 0f
            // Fresh scan: clear any stale unified score from a previous Scan All.
            unifiedScore.value = null
            scanStartMs.value = System.currentTimeMillis()
            val appCtx = ctx.applicationContext
            catalog.value = fetchCatalog(appCtx)
            val list = AppScanner(appCtx).scanAll(includeSystem = withSystem, catalog = catalog.value) { p ->
                progress.value = if (p.total == 0) 0f else p.done.toFloat() / p.total
            }
            findings.value = list
            // Fixed: threat-weighted device score (was plain average, hid single trojan).
            val score = com.alvand.securityscanner.scanner.RiskEngine.deviceScore(list)
            val threats = list.count { it.verdict == Verdict.DANGEROUS }
            deviceScore.value = score
            try { health.value = com.alvand.securityscanner.scanner.checkDeviceHealth(appCtx) } catch (_: Exception) { }
            ctx.dataStore.edit { e ->
                e[PrefsKeys.LAST_SCORE] = score.toString()
                e[PrefsKeys.LAST_SCAN] = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date())
            }
            // Phase-2: persistent history + notification (only on threats, to avoid spam)
            try {
                val db = com.alvand.securityscanner.data.HistoryDb.get(ctx)
                val top = list.filter { it.verdict != Verdict.SAFE }.take(15)
                    .joinToString(";") { "${it.packageName}:${it.score}" }.take(2000)
                db.dao().insert(
                    com.alvand.securityscanner.data.ScanRecord(
                        timestamp = System.currentTimeMillis(),
                        deviceScore = score, appsScanned = list.size,
                        threats = threats, summary = top
                    )
                )
                db.dao().trim()
            } catch (_: Exception) { }
            try {
                if (threats > 0) com.alvand.securityscanner.scanner.notifyScanFinished(ctx, score, threats)
            } catch (_: Exception) { }
            scanning.value = false
        }
    }

    fun scanFiles(ctx: Context, treeUriString: String) {
        if (fileScanning.value) return
        fileJob?.cancel()
        fileJob = viewModelScope.launch {
            fileScanning.value = true; fileProgress.value = 0f; fileCurrent.value = ""
            unifiedScore.value = null
            scanStartMs.value = System.currentTimeMillis()
            try {
                val appCtx = ctx.applicationContext
                catalog.value = fetchCatalog(appCtx)
                val treeUri = Uri.parse(treeUriString)
                val res = com.alvand.securityscanner.scanner.FileScanner.scanTree(
                    appCtx, treeUri, catalog = catalog.value
                ) { p ->
                    fileProgress.value = if (p.total == 0) 0f else p.done.toFloat() / p.total
                    fileCurrent.value = p.currentName
                }
                fileFindings.value = res.files
                fileTruncated.value = res.truncated
                val danger = res.dangerous
                val review = res.review
                try {
                    val db = com.alvand.securityscanner.data.HistoryDb.get(ctx)
                    val top = res.files.filter { it.verdict != com.alvand.securityscanner.scanner.FileVerdict.SAFE }
                        .take(15).joinToString(";") { "${it.displayName}:${it.score}" }.take(2000)
                    db.dao().insert(
                        com.alvand.securityscanner.data.ScanRecord(
                            timestamp = System.currentTimeMillis(),
                            deviceScore = deviceScore.value ?: 100,
                            appsScanned = findings.value.size,
                            threats = findings.value.count { it.verdict == Verdict.DANGEROUS },
                            summary = "",
                            filesScanned = res.files.size,
                            fileThreats = danger + review,
                            fileSummary = top
                        )
                    )
                    db.dao().trim()
                } catch (_: Exception) { }
                try {
                    if (danger > 0) com.alvand.securityscanner.scanner.notifyScanFinished(
                        ctx, deviceScore.value ?: 100, danger
                    )
                } catch (_: Exception) { }
            } catch (_: Exception) { } finally {
                fileScanning.value = false
            }
        }
    }

    /**
     * «اسکن همه»: apps (0..50%) + files (50..100%) in one run, one unified score.
     * If no SAF folder was granted, apps are still scanned and the UI prompts
     * to pick a folder for full coverage. Never crashes without a folder.
     */
    fun scanAll(ctx: Context, withSystem: Boolean = includeSystem.value) {
        if (unifiedScanning.value || scanning.value || fileScanning.value) return
        uniJob?.cancel()
        uniJob = viewModelScope.launch {
            unifiedScanning.value = true; unifiedProgress.value = 0f; vtSummary.value = null
            scanStartMs.value = System.currentTimeMillis()
            try {
                val appCtx = ctx.applicationContext
                // Stage 0: catalog reputation (read-only public JSON, cached 6h)
                unifiedStage.value = "catalog"
                catalog.value = fetchCatalog(appCtx)
                // Stage 1: apps
                unifiedStage.value = "apps"
                scanning.value = true
                val apps = com.alvand.securityscanner.scanner.AppScanner(appCtx)
                    .scanAll(includeSystem = withSystem, catalog = catalog.value) { p ->
                        unifiedProgress.value = 0.5f * (if (p.total == 0) 0f else p.done.toFloat() / p.total)
                    }
                findings.value = apps
                includeSystem.value = withSystem
                val appScore = com.alvand.securityscanner.scanner.RiskEngine.deviceScore(apps)
                deviceScore.value = appScore
                try { health.value = com.alvand.securityscanner.scanner.checkDeviceHealth(appCtx) } catch (_: Exception) { }
                scanning.value = false
                // Stage 2: files (only if folder granted)
                val tree = fileTreeUri.value
                var fScore = 100
                var hasFiles = false
                if (!tree.isNullOrBlank()) {
                    try {
                        unifiedStage.value = "files"
                        fileScanning.value = true
                        val res = com.alvand.securityscanner.scanner.FileScanner.scanTree(
                            appCtx, Uri.parse(tree), catalog = catalog.value
                        ) { p ->
                            unifiedProgress.value = 0.5f + 0.5f * (if (p.total == 0) 0f else p.done.toFloat() / p.total)
                            fileProgress.value = if (p.total == 0) 0f else p.done.toFloat() / p.total
                            fileCurrent.value = p.currentName
                            unifiedStage.value = p.currentName
                        }
                        fileFindings.value = res.files
                        fileTruncated.value = res.truncated
                        fScore = com.alvand.securityscanner.scanner.RiskEngine.fileScore(res.files)
                        hasFiles = res.files.isNotEmpty()
                        fileScanning.value = false
                        // Stage 3 (opt-in): VT check on top dangerous files only (quota-safe).
                        try {
                            unifiedStage.value = "vt"
                            vtSummary.value = vtCheckTopFiles(appCtx)
                        } catch (_: Exception) { vtSummary.value = null }
                    } catch (_: Exception) { fileScanning.value = false }
                }
                unifiedProgress.value = 1f
                val uni = com.alvand.securityscanner.scanner.RiskEngine.unifiedScore(appScore, fScore, hasFiles)
                unifiedScore.value = uni
                ctx.dataStore.edit { e ->
                    e[PrefsKeys.LAST_SCORE] = uni.toString()
                    e[PrefsKeys.LAST_SCAN] = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date())
                }
                try {
                    val db = com.alvand.securityscanner.data.HistoryDb.get(ctx)
                    val appTop = apps.filter { it.verdict != Verdict.DANGEROUS || true }
                        .filter { it.verdict != Verdict.SAFE }.take(10)
                        .joinToString(";") { "${it.packageName}:${it.score}" }.take(1200)
                    val fileTop = fileFindings.value
                        .filter { it.verdict != com.alvand.securityscanner.scanner.FileVerdict.SAFE }.take(10)
                        .joinToString(";") { "${it.displayName}:${it.score}" }.take(1200)
                    db.dao().insert(
                        com.alvand.securityscanner.data.ScanRecord(
                            timestamp = System.currentTimeMillis(),
                            deviceScore = uni,
                            appsScanned = apps.size,
                            threats = apps.count { it.verdict == Verdict.DANGEROUS },
                            summary = appTop,
                            filesScanned = fileFindings.value.size,
                            fileThreats = fileFindings.value.count { it.verdict != com.alvand.securityscanner.scanner.FileVerdict.SAFE },
                            fileSummary = fileTop
                        )
                    )
                    db.dao().trim()
                } catch (_: Exception) { }
                try {
                    val totalDanger = apps.count { it.verdict == Verdict.DANGEROUS } +
                            fileFindings.value.count { it.verdict == com.alvand.securityscanner.scanner.FileVerdict.DANGEROUS }
                    if (totalDanger > 0) com.alvand.securityscanner.scanner.notifyScanFinished(ctx, uni, totalDanger)
                } catch (_: Exception) { }
            } finally {
                scanning.value = false; fileScanning.value = false
                unifiedScanning.value = false; unifiedProgress.value = 0f; unifiedStage.value = ""
            }
        }
    }

    /**
     * Idol Catalog reputation: read-only public JSON, no device data sent.
     * Honors the CATALOG toggle; cached 6h inside CatalogReputation.
     */
    private suspend fun fetchCatalog(appCtx: Context): com.alvand.securityscanner.scanner.CatalogData? {
        return try {
            val on = appCtx.dataStore.data
                .map { it[PrefsKeys.CATALOG] != false } // default ON
                .firstOrNull() ?: true
            if (on) com.alvand.securityscanner.scanner.CatalogReputation.fetch() else null
        } catch (_: Exception) { null }
    }

    /**
     * Opt-in VT reputation for the most dangerous FILE hashes (max 3, cached,
     * 16s gap respected inside lookupVirusTotalCached). Returns a one-line
     * summary or null when disabled/offline. Never uploads file content.
     */
    private suspend fun vtCheckTopFiles(appCtx: Context): String? {
        val cloud: Boolean
        val key: String
        try {
            val prefs = appCtx.dataStore.data.firstOrNull() ?: return null
            cloud = prefs[PrefsKeys.CLOUD] == true
            key = prefs[PrefsKeys.VT_KEY] ?: ""
        } catch (_: Exception) { return null }
        if (!cloud || key.isBlank()) return null
        val cands = fileFindings.value
            .filter { it.verdict != com.alvand.securityscanner.scanner.FileVerdict.SAFE && it.sha256 != null }
            .sortedBy { it.score }.take(3)
        if (cands.isEmpty()) return null
        var flagged = 0
        var checked = 0
        for (c in cands) {
            val sha = c.sha256 ?: continue
            val res = try {
                com.alvand.securityscanner.scanner.lookupVirusTotalCached(sha, key)
            } catch (_: Exception) { null } ?: continue
            checked++
            val v = com.alvand.securityscanner.scanner.parseVtVerdict(res)
            if (v != null && v.first > 0) flagged++
            if (res.startsWith("quota exceeded") || res.startsWith("invalid API key")) return res
        }
        if (checked == 0) return null
        return "VirusTotal: $flagged/$checked suspicious"
    }
}

