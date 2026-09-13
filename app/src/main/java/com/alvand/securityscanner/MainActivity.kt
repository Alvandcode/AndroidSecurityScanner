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

val Context.dataStore by preferencesDataStore("settings")

private const val TG_CHANNEL = "https://t.me/a_c_official"
private const val TON_ADDR = "UQCB9rzvwmq0FJDaBkHVdBgbfZPb06FWdKco3woAHH6AXuUt"

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
            scanStartMs.value = System.currentTimeMillis()
            val appCtx = ctx.applicationContext
            val list = AppScanner(appCtx).scanAll(includeSystem = withSystem) { p ->
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
            scanStartMs.value = System.currentTimeMillis()
            try {
                val appCtx = ctx.applicationContext
                val treeUri = Uri.parse(treeUriString)
                val res = com.alvand.securityscanner.scanner.FileScanner.scanTree(appCtx, treeUri) { p ->
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
                // Stage 1: apps
                unifiedStage.value = "apps"
                scanning.value = true
                val apps = com.alvand.securityscanner.scanner.AppScanner(appCtx)
                    .scanAll(includeSystem = withSystem) { p ->
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
                            appCtx, Uri.parse(tree)
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
                        try { vtSummary.value = vtCheckTopFiles(appCtx) } catch (_: Exception) { vtSummary.value = null }
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

class MainActivity : ComponentActivity() {
    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(applyLocale(newBase))
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            val ctx = LocalContext.current
            val theme by ctx.dataStore.data.map { it[PrefsKeys.THEME] ?: "system" }.collectAsState("system")
            val lang by ctx.dataStore.data.map { it[PrefsKeys.LANG] ?: "system" }.collectAsState("system")
            AppTheme(theme) {
                GlassBackground(androidx.compose.foundation.isSystemInDarkTheme() || theme == "dark") {
                    MainTabs(theme, lang)
                }
            }
        }
    }

    companion object {
        fun applyLocale(c: Context): Context {
            // FIX: never runBlocking(DataStore) on the main thread (ANR).
            // Language is mirrored to SharedPreferences "events/ui_lang" on every
            // change in Settings, so attachBaseContext stays synchronous.
            val lang = try {
                c.getSharedPreferences("events", MODE_PRIVATE).getString("ui_lang", "system")
            } catch (_: Exception) { "system" }
            if (lang == null || lang == "system") return c
            val locale = Locale(if (lang == "fa") "fa" else "en")
            Locale.setDefault(locale)
            val cfg = c.resources.configuration
            cfg.setLocale(locale)
            cfg.setLayoutDirection(locale)
            return c.createConfigurationContext(cfg)
        }
    }
}

@Composable
fun MainTabs(theme: String, lang: String) {
    var tab by remember { mutableIntStateOf(0) }
    val vm: ScanViewModel = viewModel()
    val ctx0 = LocalContext.current
    LaunchedEffect(Unit) {
        try {
            val saved = ctx0.dataStore.data.map { it[PrefsKeys.FILE_TREE] }.firstOrNull()
            if (!saved.isNullOrBlank()) vm.setTreeUri(saved)
        } catch (_: Exception) { }
    }
    Scaffold(
        containerColor = androidx.compose.ui.graphics.Color.Transparent,
        bottomBar = {
            Surface(
                color = Color.White,
                shadowElevation = 16.dp,
                shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp)
            ) {
                Row(
                    Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 10.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    BottomTab(
                        selected = tab == 0, icon = Icons.Default.Home,
                        label = stringResource(R.string.dashboard), onClick = { tab = 0 }
                    )
                    Box(contentAlignment = Alignment.Center) {
                        FloatingActionButton(
                            onClick = { tab = 1; vm.scanAll(ctx0) },
                            containerColor = com.alvand.securityscanner.ui.AccentBlue,
                            contentColor = Color.White,
                            shape = CircleShape,
                            modifier = Modifier.size(62.dp).offset(y = (-8).dp),
                            elevation = FloatingActionButtonDefaults.elevation(8.dp)
                        ) {
                            Icon(Icons.Default.GpsFixed, contentDescription = null, modifier = Modifier.size(28.dp))
                        }
                    }
                    BottomTab(
                        selected = tab == 2, icon = Icons.Default.History,
                        label = stringResource(R.string.history), onClick = { tab = 2 }
                    )
                }
            }
        }
    ) { pad ->
        Box(Modifier.padding(pad)) {
            when (tab) {
                0 -> HomeScreen(vm, onScan = { tab = 1 }, onSettings = { tab = 3 }, onHistory = { tab = 2 })
                1 -> ScanScreen(vm, onBack = { tab = 0 })
                2 -> HistoryList(vm)
                3 -> SettingsScreen(theme, lang)
                else -> HomeScreen(vm, onScan = { tab = 1 }, onSettings = { tab = 3 }, onHistory = { tab = 2 })
            }
        }
    }
}

@Composable
fun BottomTab(
    selected: Boolean,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    onClick: () -> Unit
) {
    val tint = if (selected) com.alvand.securityscanner.ui.AccentBlue else Color(0xFF9CA3AF)
    Column(
        Modifier.clickable(onClick = onClick).padding(horizontal = 16.dp, vertical = 4.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(26.dp))
        Spacer(Modifier.height(2.dp))
        Text(label, fontSize = 11.sp, color = tint, fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal)
    }
}

@Composable
fun HomeScreen(vm: ScanViewModel, onScan: () -> Unit, onSettings: () -> Unit, onHistory: () -> Unit) {
    val ctx = LocalContext.current
    var selected by remember { mutableStateOf<AppFinding?>(null) }
    var webOpen by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val notifLauncher = androidx.activity.compose.rememberLauncherForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.RequestPermission()
    ) { }
    val sched by ctx.dataStore.data.map { it[PrefsKeys.SCHED] == true }.collectAsState(false)
    val lastScan by ctx.dataStore.data.map { it[PrefsKeys.LAST_SCAN] }.collectAsState(null)
    val notifOn = if (Build.VERSION.SDK_INT >= 33) {
        ctx.checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) ==
                android.content.pm.PackageManager.PERMISSION_GRANTED
    } else true
    fun askNotif() {
        if (Build.VERSION.SDK_INT >= 33 && !notifOn) {
            try { notifLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS) } catch (_: Exception) { }
        }
    }
    LazyColumn(Modifier.fillMaxSize().padding(horizontal = 20.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        item {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                IconButton(onClick = onSettings) {
                    Icon(Icons.Default.Menu, contentDescription = null, tint = com.alvand.securityscanner.ui.TextPrimary, modifier = Modifier.size(26.dp))
                }
                IconButton(onClick = onHistory) {
                    Icon(Icons.Default.VerifiedUser, contentDescription = null, tint = com.alvand.securityscanner.ui.AccentBlue, modifier = Modifier.size(26.dp))
                }
            }
        }
        item {
            Text(stringResource(R.string.app_name), fontSize = 26.sp, fontWeight = FontWeight.Bold, color = com.alvand.securityscanner.ui.TextPrimary)
            Text(stringResource(R.string.app_tagline), fontSize = 14.sp, color = com.alvand.securityscanner.ui.TextSecondary)
        }
        item {
            val shown = vm.unifiedScore.value ?: vm.deviceScore.value
            Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                ScoreRing(shown)
                Spacer(Modifier.height(12.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        Icons.Default.AccessTime, contentDescription = null,
                        modifier = Modifier.size(14.dp), tint = com.alvand.securityscanner.ui.TextSecondary
                    )
                    Spacer(Modifier.width(4.dp))
                    Text(
                        "${stringResource(R.string.last_scan)}: ${lastScan ?: stringResource(R.string.never)}",
                        fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary
                    )
                }
            }
        }
        item {
            GlassCard(Modifier.fillMaxWidth()) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Surface(
                        color = com.alvand.securityscanner.ui.AccentBlue.copy(alpha = 0.1f),
                        shape = CircleShape,
                        modifier = Modifier.size(44.dp)
                    ) {
                        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                            Icon(
                                Icons.Default.VerifiedUser, contentDescription = null,
                                tint = com.alvand.securityscanner.ui.AccentBlue, modifier = Modifier.size(24.dp)
                            )
                        }
                    }
                    Spacer(Modifier.width(14.dp))
                    Column(Modifier.weight(1f)) {
                        Text(stringResource(R.string.quick_scan), fontWeight = FontWeight.SemiBold, fontSize = 15.sp, color = com.alvand.securityscanner.ui.TextPrimary)
                        Text(
                            stringResource(R.string.quick_desc), fontSize = 12.sp,
                            color = com.alvand.securityscanner.ui.TextSecondary
                        )
                    }
                    Surface(
                        onClick = { askNotif(); vm.scan(ctx, false) },
                        color = com.alvand.securityscanner.ui.AccentBlue,
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.size(44.dp)
                    ) {
                        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                            Icon(Icons.Default.ArrowForward, contentDescription = null, tint = Color.White, modifier = Modifier.size(20.dp))
                        }
                    }
                }
                if (vm.scanning.value && !vm.unifiedScanning.value) {
                    Spacer(Modifier.height(10.dp))
                    LinearProgressIndicator(
                        progress = { vm.progress.value },
                        modifier = Modifier.fillMaxWidth().height(4.dp),
                        color = com.alvand.securityscanner.ui.AccentBlue,
                        trackColor = com.alvand.securityscanner.ui.AccentBlue.copy(alpha = 0.12f)
                    )
                }
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                MiniScanCard(
                    Modifier.weight(1f), Icons.Default.GpsFixed,
                    stringResource(R.string.full_scan), stringResource(R.string.full_desc)
                ) { askNotif(); vm.scanAll(ctx, false); onScan() }
                MiniScanCard(
                    Modifier.weight(1f), Icons.Default.Apps,
                    stringResource(R.string.app_scan), stringResource(R.string.app_desc)
                ) { askNotif(); vm.scan(ctx, true) }
                MiniScanCard(
                    Modifier.weight(1f), Icons.Default.Language,
                    stringResource(R.string.web_scan), stringResource(R.string.web_desc)
                ) { webOpen = true }
            }
        }
        item {
            Text(
                stringResource(R.string.protection), fontSize = 16.sp, fontWeight = FontWeight.SemiBold,
                modifier = Modifier.padding(start = 4.dp), color = com.alvand.securityscanner.ui.TextPrimary
            )
        }
        item {
            GlassCard(Modifier.fillMaxWidth()) {
                ProtRow(
                    Icons.Default.VerifiedUser,
                    stringResource(R.string.realtime),
                    if (sched) stringResource(R.string.scan_on) else stringResource(R.string.scan_off)
                ) {
                    Switch(
                        checked = sched,
                        onCheckedChange = { on ->
                            scope.launch {
                                ctx.dataStore.edit { it[PrefsKeys.SCHED] = on }
                                if (on) com.alvand.securityscanner.scanner.ScanWorker.schedule(ctx)
                                else com.alvand.securityscanner.scanner.ScanWorker.cancel(ctx)
                            }
                        },
                        colors = SwitchDefaults.colors(checkedThumbColor = Color.White, checkedTrackColor = com.alvand.securityscanner.ui.AccentBlue)
                    )
                }
                HorizontalDivider(Modifier.padding(vertical = 6.dp), color = com.alvand.securityscanner.ui.AccentBlue.copy(alpha = 0.08f))
                ProtRow(Icons.Default.Wifi, stringResource(R.string.wifi_sec), stringResource(R.string.wifi_desc)) {
                    IconButton(onClick = {
                        try { ctx.startActivity(Intent(Settings.ACTION_WIFI_SETTINGS)) } catch (_: Exception) { }
                    }) {
                        Icon(Icons.Default.ChevronRight, contentDescription = null, tint = com.alvand.securityscanner.ui.TextSecondary)
                    }
                }
                HorizontalDivider(Modifier.padding(vertical = 6.dp), color = com.alvand.securityscanner.ui.AccentBlue.copy(alpha = 0.08f))
                ProtRow(Icons.Default.Storage, stringResource(R.string.database), stringResource(R.string.db_desc)) {
                    IconButton(onClick = onSettings) {
                        Icon(Icons.Default.Refresh, contentDescription = null, tint = com.alvand.securityscanner.ui.TextSecondary)
                    }
                }
                HorizontalDivider(Modifier.padding(vertical = 6.dp), color = com.alvand.securityscanner.ui.AccentBlue.copy(alpha = 0.08f))
                ProtRow(
                    Icons.Default.Notifications,
                    stringResource(R.string.notif_title),
                    if (notifOn) stringResource(R.string.notif_on) else stringResource(R.string.notif_off)
                ) {
                    IconButton(onClick = { if (!notifOn) askNotif() else {
                        try {
                            if (Build.VERSION.SDK_INT >= 26) {
                                ctx.startActivity(
                                    Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                                        .putExtra(Settings.EXTRA_APP_PACKAGE, ctx.packageName)
                                )
                            } else {
                                ctx.startActivity(
                                    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${ctx.packageName}"))
                                )
                            }
                        } catch (_: Exception) { }
                    } }) {
                        Icon(Icons.Default.ChevronRight, contentDescription = null, tint = com.alvand.securityscanner.ui.TextSecondary)
                    }
                }
            }
        }
        val danger = vm.findings.value.filter { it.verdict == Verdict.DANGEROUS }
        val review = vm.findings.value.filter { it.verdict == Verdict.REVIEW }
        val safe = vm.findings.value.filter { it.verdict == Verdict.SAFE }
        if (danger.isNotEmpty()) {
            item {
                com.alvand.securityscanner.ui.CategoryHeader(
                    "${stringResource(R.string.dangerous)}: ${danger.size}",
                    com.alvand.securityscanner.ui.GlowDanger
                )
            }
            items(danger.take(50), key = { it.packageName }) { f ->
                AppRow(f, com.alvand.securityscanner.ui.GlowDanger, false) { selected = f }
            }
        }
        if (review.isNotEmpty()) {
            item {
                com.alvand.securityscanner.ui.CategoryHeader(
                    "${stringResource(R.string.review_needed)}: ${review.size}",
                    com.alvand.securityscanner.ui.GlowWarn
                )
            }
            items(review.take(50), key = { it.packageName }) { f ->
                AppRow(f, com.alvand.securityscanner.ui.GlowWarn, true) { selected = f }
            }
        }
        if (safe.isNotEmpty() && !danger.isNotEmpty() && !review.isNotEmpty()) {
            item {
                com.alvand.securityscanner.ui.CategoryHeader(
                    "${stringResource(R.string.safe)}: ${safe.size}",
                    com.alvand.securityscanner.ui.GlowSafe
                )
            }
            items(safe.take(30), key = { it.packageName }) { f ->
                AppRow(f, com.alvand.securityscanner.ui.GlowSafe, false) { selected = f }
            }
        }
    }
    selected?.let { com.alvand.securityscanner.ui.DetailsDialog(it) { selected = null } }
    if (webOpen) WebScanDialog { webOpen = false }
}

@Composable
fun AppRow(
    f: AppFinding,
    glow: androidx.compose.ui.graphics.Color,
    pulse: Boolean,
    onDetails: () -> Unit
) {
    val c = LocalContext.current
    com.alvand.securityscanner.ui.GlowCard(glow = glow, pulse = pulse, modifier = Modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            com.alvand.securityscanner.ui.AppIcon(f.packageName, Modifier.size(44.dp))
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(f.appName, fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = com.alvand.securityscanner.ui.TextPrimary)
                Text(f.packageName, fontSize = 11.sp, color = com.alvand.securityscanner.ui.TextSecondary)
                Text("${f.score}/100 • " + verdictText(f.verdict) + (if (f.unknownSource) " • " + stringResource(R.string.unknown_source) else ""),
                    fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary)
                if (f.riskyPermissions.isNotEmpty())
                    Text("${stringResource(R.string.risky_permissions)}: " + f.riskyPermissions.joinToString { it.name }, fontSize = 11.sp, color = com.alvand.securityscanner.ui.TextSecondary)
            }
            Column {
                Surface(
                    onClick = onDetails,
                    color = com.alvand.securityscanner.ui.AccentBlue.copy(alpha = 0.1f),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Text(stringResource(R.string.details), modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp), fontSize = 12.sp, color = com.alvand.securityscanner.ui.AccentBlue, fontWeight = FontWeight.SemiBold)
                }
                Spacer(Modifier.height(4.dp))
                TextButton(onClick = {
                    try { c.startActivity(Intent(Intent.ACTION_DELETE, Uri.parse("package:${f.packageName}"))) } catch (_: Exception) { }
                }) { Text(stringResource(R.string.uninstall), fontSize = 11.sp) }
            }
        }
    }
}

@Composable
fun ScoreRing(score: Int?) {
    val s = (score ?: 0).coerceIn(0, 100)
    val frac = s / 100f
    val ring: Brush
    val label: String
    val sub: String
    when {
        score == null || s >= 80 -> {
            ring = Brush.sweepGradient(listOf(com.alvand.securityscanner.ui.RingBlue, com.alvand.securityscanner.ui.RingPink, com.alvand.securityscanner.ui.RingBlue))
            label = stringResource(R.string.safe)
            sub = stringResource(R.string.no_threats)
        }
        s >= 50 -> {
            ring = Brush.sweepGradient(listOf(Color(0xFFFFB300), Color(0xFFFF7043), Color(0xFFFFB300)))
            label = stringResource(R.string.review_needed)
            sub = stringResource(R.string.suspicious)
        }
        else -> {
            ring = Brush.sweepGradient(listOf(Color(0xFFFF5252), Color(0xFFD81B60), Color(0xFFFF5252)))
            label = stringResource(R.string.dangerous)
            sub = stringResource(R.string.infected)
        }
    }
    Box(Modifier.size(230.dp), contentAlignment = Alignment.Center) {
        Canvas(Modifier.fillMaxSize()) {
            val stroke = 14.dp.toPx()
            val padding = 4.dp.toPx()
            drawArc(
                Color(0xFFE0E4F0), 0f, 360f, false,
                style = Stroke(stroke, cap = StrokeCap.Round),
                topLeft = Offset(padding, padding),
                size = Size(size.width - padding * 2f, size.height - padding * 2f)
            )
            if (frac > 0f) drawArc(
                ring, -90f, 360f * frac, false,
                style = Stroke(stroke, cap = StrokeCap.Round),
                topLeft = Offset(padding, padding),
                size = Size(size.width - padding * 2f, size.height - padding * 2f)
            )
            val inset = 32.dp.toPx()
            drawArc(
                Color(0xFFBCC3DA), 0f, 360f, false,
                style = Stroke(1.5.dp.toPx(), pathEffect = PathEffect.dashPathEffect(floatArrayOf(4f, 6f), 0f)),
                alpha = 0.4f,
                topLeft = Offset(inset, inset),
                size = Size(size.width - inset * 2f, size.height - inset * 2f)
            )
        }
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Surface(
                color = com.alvand.securityscanner.ui.AccentBlue.copy(alpha = 0.1f),
                shape = CircleShape,
                modifier = Modifier.size(48.dp)
            ) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Icon(Icons.Default.VerifiedUser, contentDescription = null, tint = com.alvand.securityscanner.ui.AccentBlue, modifier = Modifier.size(28.dp))
                }
            }
            Spacer(Modifier.height(4.dp))
            Text(label, fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary, fontWeight = FontWeight.Medium)
            Text(
                if (score == null) "--%" else "$s%",
                fontSize = 42.sp, fontWeight = FontWeight.Bold,
                color = com.alvand.securityscanner.ui.TextPrimary
            )
            Text(sub, fontSize = 12.sp, color = com.alvand.securityscanner.ui.AccentBlue, fontWeight = FontWeight.Medium)
        }
    }
}

@Composable
fun MiniScanCard(mod: Modifier, icon: ImageVector, title: String, desc: String, onClick: () -> Unit) {
    Surface(
        modifier = mod.clickable(onClick = onClick),
        color = Color.White,
        shape = RoundedCornerShape(20.dp),
        shadowElevation = 4.dp
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.fillMaxWidth().padding(vertical = 16.dp, horizontal = 8.dp)
        ) {
            Surface(
                color = com.alvand.securityscanner.ui.AccentBlue.copy(alpha = 0.1f),
                shape = CircleShape,
                modifier = Modifier.size(42.dp)
            ) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Icon(icon, contentDescription = null, tint = com.alvand.securityscanner.ui.AccentBlue, modifier = Modifier.size(22.dp))
                }
            }
            Spacer(Modifier.height(8.dp))
            Text(title, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = com.alvand.securityscanner.ui.TextPrimary)
            Text(desc, fontSize = 10.sp, color = com.alvand.securityscanner.ui.TextSecondary)
        }
    }
}

@Composable
fun ProtRow(icon: ImageVector, title: String, sub: String, action: @Composable () -> Unit) {
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, contentDescription = null, tint = com.alvand.securityscanner.ui.AccentBlue, modifier = Modifier.size(24.dp))
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            Text(title, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = com.alvand.securityscanner.ui.TextPrimary)
            Text(sub, fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary)
        }
        action()
    }
}

@Composable
fun Radar(active: Boolean) {
    val sweep = if (active) {
        rememberInfiniteTransition(label = "radar").animateFloat(
            initialValue = 0f, targetValue = 360f,
            animationSpec = infiniteRepeatable(
                animation = tween(durationMillis = 2600, easing = LinearEasing),
                repeatMode = RepeatMode.Restart
            ),
            label = "sweep"
        ).value
    } else 0f
    Box(Modifier.size(260.dp), contentAlignment = Alignment.Center) {
        Canvas(Modifier.fillMaxSize()) {
            val cx = size.width / 2f
            val cy = size.height / 2f
            val r = minOf(cx, cy)
            for (f in listOf(0.34f, 0.56f, 0.78f, 1f)) {
                drawCircle(Color(0xFFD0D5E8), r * f, style = Stroke(1.5.dp.toPx()), alpha = 0.6f)
            }
            if (active) {
                rotate(sweep) {
                    drawArc(
                        brush = Brush.sweepGradient(
                            0f to Color.Transparent,
                            0.22f to com.alvand.securityscanner.ui.AccentBlue.copy(alpha = 0.5f),
                            0.26f to Color.Transparent,
                            center = Offset(cx, cy)
                        ),
                        startAngle = 0f, sweepAngle = 360f, useCenter = true,
                        topLeft = Offset(cx - r, cy - r),
                        size = Size(r * 2f, r * 2f)
                    )
                }
            }
        }
        OrbitChip(Modifier.align(Alignment.TopCenter).offset(y = (-14).dp), Icons.Default.BugReport)
        OrbitChip(Modifier.align(Alignment.CenterEnd).offset(x = 14.dp), Icons.Default.Wifi)
        OrbitChip(Modifier.align(Alignment.CenterStart).offset(x = (-14).dp), Icons.Default.Lock)
        OrbitChip(Modifier.align(Alignment.BottomCenter).offset(y = 14.dp), Icons.Default.Description)
        Surface(
            color = Color.White, shape = CircleShape,
            shadowElevation = 8.dp, modifier = Modifier.size(110.dp)
        ) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Icon(Icons.Default.VerifiedUser, contentDescription = null, tint = com.alvand.securityscanner.ui.AccentBlue, modifier = Modifier.size(52.dp))
                Icon(
                    Icons.Default.Search, contentDescription = null, tint = com.alvand.securityscanner.ui.AccentBlue,
                    modifier = Modifier.size(22.dp).align(Alignment.BottomEnd).offset(x = (-22).dp, y = (-22).dp)
                )
            }
        }
    }
}

@Composable
fun OrbitChip(mod: Modifier, icon: ImageVector) {
    Surface(color = Color.White, shape = CircleShape, shadowElevation = 4.dp, modifier = mod.size(40.dp)) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Icon(icon, contentDescription = null, tint = com.alvand.securityscanner.ui.AccentBlue, modifier = Modifier.size(20.dp))
        }
    }
}

@Composable
fun ScanStat(value: String, label: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, fontSize = 20.sp, fontWeight = FontWeight.Bold, color = com.alvand.securityscanner.ui.TextPrimary)
        Text(label, fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary)
    }
}

@Composable
fun EngineRow(icon: ImageVector, title: String, count: String, active: Boolean) {
    Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, contentDescription = null, tint = com.alvand.securityscanner.ui.TextSecondary, modifier = Modifier.size(20.dp))
        Spacer(Modifier.width(10.dp))
        Text(title, fontSize = 14.sp, modifier = Modifier.weight(1f), color = com.alvand.securityscanner.ui.TextPrimary)
        if (active) {
            Text(stringResource(R.string.checking), fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary)
            Spacer(Modifier.width(6.dp))
            CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = com.alvand.securityscanner.ui.AccentBlue)
        } else {
            Text(count, fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary)
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
        vm.unifiedScanning.value && vm.unifiedStage.value.isNotBlank() -> vm.unifiedStage.value
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
                    Icon(Icons.Default.ArrowBack, contentDescription = null, tint = com.alvand.securityscanner.ui.TextPrimary, modifier = Modifier.size(26.dp))
                }
                Text(stringResource(R.string.full_scan), fontSize = 18.sp, fontWeight = FontWeight.SemiBold, color = com.alvand.securityscanner.ui.TextPrimary)
                IconButton(onClick = { }) {
                    Icon(Icons.Default.MoreVert, contentDescription = null, tint = com.alvand.securityscanner.ui.TextSecondary, modifier = Modifier.size(24.dp))
                }
            }
        }
        item { Radar(active) }
        item {
            Text(
                if (active) stringResource(R.string.scanning)
                else if (threats > 0) "${stringResource(R.string.scan_complete)} — $threats ${stringResource(R.string.threats)}"
                else stringResource(R.string.no_threats),
                fontSize = 20.sp, fontWeight = FontWeight.Bold, color = com.alvand.securityscanner.ui.TextPrimary
            )
            if (stage.isNotBlank()) {
                Spacer(Modifier.height(4.dp))
                Text(stage.take(48), fontSize = 12.sp, color = com.alvand.securityscanner.ui.AccentBlue)
            }
            Text("$scanned ${stringResource(R.string.scanned_label)}", fontSize = 13.sp, color = com.alvand.securityscanner.ui.TextSecondary)
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
                Text(stringResource(R.string.scan_engine), fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = com.alvand.securityscanner.ui.TextPrimary)
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

@Composable
fun verdictText(v: Verdict) = when (v) {
    Verdict.SAFE -> stringResource(R.string.safe)
    Verdict.REVIEW -> stringResource(R.string.review_needed)
    Verdict.DANGEROUS -> stringResource(R.string.dangerous)
}

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
    var vtChecking by remember { mutableStateOf<String?>(null) }
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
                    if (vm.fileTruncated.value) Text(stringResource(R.string.truncated), fontSize = 11.sp)
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
                                vtChecking = f.uriString
                                vtResults[f.uriString] = try {
                                    com.alvand.securityscanner.scanner.lookupVirusTotalCached(sha, vtKey)
                                        ?: "error/offline"
                                } catch (_: Exception) { "error/offline" }
                                vtChecking = null
                            }
                        }, enabled = vtChecking == null) {
                            Text(if (vtChecking == f.uriString) "…" else stringResource(R.string.check_online))
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

@Composable
fun HistoryList(vm: ScanViewModel) {
    val ctx = LocalContext.current
    val lastScore by ctx.dataStore.data.map { it[PrefsKeys.LAST_SCORE] }.collectAsState(null)
    val lastScan by ctx.dataStore.data.map { it[PrefsKeys.LAST_SCAN] }.collectAsState(null)
    val records by remember(ctx) { com.alvand.securityscanner.data.HistoryDb.get(ctx).dao().recent() }
        .collectAsState(emptyList())
    val fmt = remember { SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US) }
    LazyColumn(Modifier.fillMaxSize().padding(horizontal = 20.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            Text(stringResource(R.string.history), fontSize = 26.sp, fontWeight = FontWeight.Bold, color = com.alvand.securityscanner.ui.TextPrimary)
        }
        item {
            GlassCard(Modifier.fillMaxWidth()) {
                Text("${stringResource(R.string.last_scan)}: ${lastScan ?: stringResource(R.string.never)}", color = com.alvand.securityscanner.ui.TextPrimary)
                Text("${stringResource(R.string.device_score)}: ${lastScore ?: "--"}", fontSize = 13.sp, color = com.alvand.securityscanner.ui.TextSecondary)
            }
        }
        if (records.isEmpty()) {
            item { GlassCard(Modifier.fillMaxWidth()) { Text(stringResource(R.string.no_history), color = com.alvand.securityscanner.ui.TextSecondary) } }
        }
        items(records) { r ->
            GlassCard(Modifier.fillMaxWidth()) {
                Text("${fmt.format(Date(r.timestamp))} — ${r.deviceScore}/100", fontWeight = FontWeight.SemiBold, color = com.alvand.securityscanner.ui.TextPrimary)
                Text("${stringResource(R.string.apps_scanned)}: ${r.appsScanned} • ${stringResource(R.string.threats)}: ${r.threats}", fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary)
                if (r.filesScanned > 0) {
                    Text(
                        "${stringResource(R.string.files_scanned)}: ${r.filesScanned} • " +
                                "${stringResource(R.string.suspicious)}/${stringResource(R.string.infected)}: ${r.fileThreats}",
                        fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary
                    )
                }
                if (r.summary.isNotBlank()) Text(r.summary.take(300), fontSize = 11.sp, color = com.alvand.securityscanner.ui.TextSecondary)
                if (r.fileSummary.isNotBlank()) Text(r.fileSummary.take(300), fontSize = 11.sp, color = com.alvand.securityscanner.ui.TextSecondary)
            }
        }
    }
}

@Composable
fun SettingsScreen(theme: String, lang: String) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val clip = LocalClipboardManager.current
    val pkg = ctx.packageName
    val verName = try {
        if (Build.VERSION.SDK_INT >= 33) {
            ctx.packageManager.getPackageInfo(pkg, android.content.pm.PackageManager.PackageInfoFlags.of(0)).versionName
        } else {
            @Suppress("DEPRECATION") ctx.packageManager.getPackageInfo(pkg, 0).versionName
        }
    } catch (_: Exception) { "1.2.0" }
    val verCode = try {
        if (Build.VERSION.SDK_INT >= 28) {
            if (Build.VERSION.SDK_INT >= 33) {
                ctx.packageManager.getPackageInfo(pkg, android.content.pm.PackageManager.PackageInfoFlags.of(0)).longVersionCode.toString()
            } else {
                @Suppress("DEPRECATION") ctx.packageManager.getPackageInfo(pkg, 0).longVersionCode.toString()
            }
        } else ""
    } catch (_: Exception) { "" }
    val cloud by ctx.dataStore.data.map { it[PrefsKeys.CLOUD] == true }.collectAsState(false)
    val vtKey by ctx.dataStore.data.map { it[PrefsKeys.VT_KEY] ?: "" }.collectAsState("")
    val sched by ctx.dataStore.data.map { it[PrefsKeys.SCHED] == true }.collectAsState(false)
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text(stringResource(R.string.settings), fontSize = 26.sp, fontWeight = FontWeight.Bold, color = com.alvand.securityscanner.ui.TextPrimary)
        GlassCard(Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.theme), fontWeight = FontWeight.SemiBold, color = com.alvand.securityscanner.ui.TextPrimary)
            Spacer(Modifier.height(6.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf("system" to stringResource(R.string.theme_system), "light" to stringResource(R.string.theme_light), "dark" to stringResource(R.string.theme_dark)).forEach { (v, t) ->
                    FilterChip(
                        selected = theme == v,
                        onClick = { scope.launch { ctx.dataStore.edit { it[PrefsKeys.THEME] = v }; (ctx as? MainActivity)?.recreate() } },
                        label = { Text(t) },
                        colors = FilterChipDefaults.filterChipColors(selectedContainerColor = com.alvand.securityscanner.ui.AccentBlue.copy(alpha = 0.12f), selectedLabelColor = com.alvand.securityscanner.ui.AccentBlue)
                    )
                }
            }
        }
        GlassCard(Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.language), fontWeight = FontWeight.SemiBold, color = com.alvand.securityscanner.ui.TextPrimary)
            Spacer(Modifier.height(6.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf("system" to stringResource(R.string.lang_system), "en" to stringResource(R.string.lang_en), "fa" to stringResource(R.string.lang_fa)).forEach { (v, t) ->
                    FilterChip(
                        selected = lang == v,
                        onClick = {
                            scope.launch {
                                ctx.dataStore.edit { it[PrefsKeys.LANG] = v }
                                ctx.getSharedPreferences("events", Context.MODE_PRIVATE).edit().putString("ui_lang", v).apply()
                                if (Build.VERSION.SDK_INT >= 33) {
                                    val lm = ctx.getSystemService(android.app.LocaleManager::class.java)
                                    lm?.applicationLocales = if (v == "system") android.os.LocaleList.forLanguageTags("") else android.os.LocaleList.forLanguageTags(v)
                                }
                                (ctx as? MainActivity)?.recreate()
                            }
                        },
                        label = { Text(t) },
                        colors = FilterChipDefaults.filterChipColors(selectedContainerColor = com.alvand.securityscanner.ui.AccentBlue.copy(alpha = 0.12f), selectedLabelColor = com.alvand.securityscanner.ui.AccentBlue)
                    )
                }
            }
        }
        GlassCard(Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.scheduled_scan), fontWeight = FontWeight.SemiBold, color = com.alvand.securityscanner.ui.TextPrimary)
            Text(stringResource(R.string.scheduled_desc), fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary)
            Spacer(Modifier.height(4.dp))
            Switch(
                checked = sched,
                onCheckedChange = { on ->
                    scope.launch {
                        ctx.dataStore.edit { it[PrefsKeys.SCHED] = on }
                        if (on) com.alvand.securityscanner.scanner.ScanWorker.schedule(ctx)
                        else com.alvand.securityscanner.scanner.ScanWorker.cancel(ctx)
                    }
                },
                colors = SwitchDefaults.colors(checkedThumbColor = Color.White, checkedTrackColor = com.alvand.securityscanner.ui.AccentBlue)
            )
        }
        GlassCard(Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.cloud_lookup), fontWeight = FontWeight.SemiBold, color = com.alvand.securityscanner.ui.TextPrimary)
            Text(stringResource(R.string.cloud_desc), fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary)
            Spacer(Modifier.height(4.dp))
            Switch(
                checked = cloud,
                onCheckedChange = { on ->
                    scope.launch {
                        ctx.dataStore.edit {
                            it[PrefsKeys.CLOUD] = on
                            if (!on) it.remove(PrefsKeys.VT_KEY)
                        }
                    }
                },
                colors = SwitchDefaults.colors(checkedThumbColor = Color.White, checkedTrackColor = com.alvand.securityscanner.ui.AccentBlue)
            )
            if (cloud) {
                Spacer(Modifier.height(4.dp))
                var keyInput by remember(vtKey) { mutableStateOf(vtKey) }
                OutlinedTextField(
                    value = keyInput,
                    onValueChange = { keyInput = it },
                    label = { Text(stringResource(R.string.vt_api_key)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(4.dp))
                Surface(
                    onClick = {
                        val v = keyInput.trim()
                        scope.launch { ctx.dataStore.edit { it[PrefsKeys.VT_KEY] = v } }
                    },
                    modifier = Modifier.fillMaxWidth().height(48.dp),
                    color = com.alvand.securityscanner.ui.AccentBlue,
                    shape = RoundedCornerShape(14.dp)
                ) {
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Text(stringResource(R.string.save), color = Color.White, fontWeight = FontWeight.SemiBold)
                    }
                }
            }
        }
        GlassCard(Modifier.fillMaxWidth()) {
            Text("${stringResource(R.string.version)}: $verName ($verCode)", color = com.alvand.securityscanner.ui.TextPrimary)
            Text("com.alvand.securityscanner", fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary)
        }
        GlassCard(Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.about), fontWeight = FontWeight.SemiBold, color = com.alvand.securityscanner.ui.TextPrimary)
            Spacer(Modifier.height(8.dp))
            val appIcon = remember(ctx) {
                try {
                    val d = ctx.packageManager.getApplicationIcon(ctx.packageName)
                    val w = d.intrinsicWidth.coerceAtLeast(1).coerceAtMost(512)
                    val h = d.intrinsicHeight.coerceAtLeast(1).coerceAtMost(512)
                    val bmp = android.graphics.Bitmap.createBitmap(w, h, android.graphics.Bitmap.Config.ARGB_8888)
                    val c = android.graphics.Canvas(bmp)
                    d.setBounds(0, 0, w, h); d.draw(c)
                    bmp
                } catch (_: Exception) { null }
            }
            if (appIcon != null) {
                Image(
                    appIcon.asImageBitmap(),
                    contentDescription = null,
                    modifier = Modifier.size(72.dp)
                )
            } else {
                Image(
                    painterResource(R.drawable.ic_logo_placeholder),
                    contentDescription = null,
                    modifier = Modifier.size(72.dp)
                )
            }
            Spacer(Modifier.height(8.dp))
            Text(stringResource(R.string.developed_by), fontSize = 13.sp, color = com.alvand.securityscanner.ui.TextPrimary)
            Text(stringResource(R.string.copyright), fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary)
            Spacer(Modifier.height(8.dp))
            Surface(
                onClick = {
                    ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/Alvandcode")))
                },
                modifier = Modifier.fillMaxWidth().height(48.dp),
                color = com.alvand.securityscanner.ui.AccentBlue,
                shape = RoundedCornerShape(14.dp)
            ) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(stringResource(R.string.contact_dev), color = Color.White, fontWeight = FontWeight.SemiBold)
                }
            }
            Spacer(Modifier.height(8.dp))
            OutlinedButton(onClick = {
                try { ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(TG_CHANNEL))) } catch (_: Exception) { }
            }, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.telegram_channel))
            }
        }
        GlassCard(Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.donate_title), fontWeight = FontWeight.SemiBold, color = com.alvand.securityscanner.ui.TextPrimary)
            Text(stringResource(R.string.donate_desc), fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary)
            Spacer(Modifier.height(6.dp))
            SelectionContainer {
                Text(TON_ADDR, fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextPrimary)
            }
            Spacer(Modifier.height(6.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Surface(
                    onClick = { clip.setText(AnnotatedString(TON_ADDR)) },
                    modifier = Modifier.weight(1f).height(44.dp),
                    color = com.alvand.securityscanner.ui.AccentBlue,
                    shape = RoundedCornerShape(14.dp)
                ) {
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Text(stringResource(R.string.donate_copy), color = Color.White, fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
                    }
                }
                OutlinedButton(onClick = {
                    try {
                        ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("ton://transfer/$TON_ADDR")))
                    } catch (_: Exception) {
                        try { ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://tonviewer.io/$TON_ADDR"))) } catch (_: Exception) { }
                    }
                }, modifier = Modifier.weight(1f).height(44.dp)) {
                    Text(stringResource(R.string.donate_open))
                }
            }
        }
        Text(
            stringResource(R.string.copyright),
            fontSize = 11.sp,
            modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
            color = com.alvand.securityscanner.ui.TextSecondary
        )
    }
}
